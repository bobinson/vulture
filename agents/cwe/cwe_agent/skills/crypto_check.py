"""CWE cryptography vulnerability detection skill."""

import base64
import binascii
import re
from pathlib import Path

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._var_reference import line_value_is_variable_ref

# CWE-327: Broken or risky cryptographic algorithm.
#
# Standalone bare-cipher names (DES, RC4, Blowfish, 3DES, TripleDES,
# ECB) used to be flagged with `\bX\b` alone, which matched variables
# named `DES_state`, `aes_DES_compat`, comments mentioning "DES", etc.
# Now the bare-name pattern only fires when the CALLER also confirms
# crypto context on the line — see the
# ``BROKEN_CRYPTO_BARE_NAME``/``BROKEN_CRYPTO_CONTEXT`` pair used by
# ``_check_broken_crypto``.
BROKEN_CRYPTO_PATTERNS = [
    # Specific high-confidence call shapes (already precise).
    re.compile(r"\bDES\.new\("),
    re.compile(r"\bARC4\.new\("),
    re.compile(r"\bBlowfish\.new\("),
    re.compile(r"\bTripleDES\.new\(", re.IGNORECASE),
    re.compile(r'mode\s*=\s*["\']?ECB'),
    re.compile(r"\bMODE_ECB\b"),
    # Cipher constructors / library lookups by name with the cipher
    # name as a string argument. Self-contextualising (no extra check).
    re.compile(
        r'(?:Cipher\.getInstance|crypto\.create(?:Cipher|Decipher)|EVP_get_cipherbyname)'
        r'\s*\(\s*["\']?(?:DES|RC4|BLOWFISH|3DES|TRIPLEDES|ECB)\b',
        re.IGNORECASE,
    ),
]

# Bare-name pattern + context check, used together by the detector to
# require that a `\bDES\b` mention appear on a line that ALSO contains
# a crypto symbol (Cipher, crypto, encrypt, decrypt, key, IV, mode).
# Doing the context check separately means we don't need a variable-
# length regex lookbehind — the context can be before OR after the
# cipher name on the line.
BROKEN_CRYPTO_BARE_NAME = re.compile(
    r"\b(DES|RC4|Blowfish|3DES|TripleDES|ECB)\b(?!C\b|RIPT|RIPE|EFS)",
    re.IGNORECASE,
)
BROKEN_CRYPTO_CONTEXT = re.compile(
    r"\b(?:cipher|crypto|encrypt|decrypt|key|IV|mode)\b",
    re.IGNORECASE,
)

SAFE_CRYPTO_CONTEXT = re.compile(
    r"(?:deprecated|legacy|migration|upgrade|warning|doc|README|CHANGELOG)",
    re.IGNORECASE,
)

# CWE-326: Inadequate encryption strength
WEAK_KEY_PATTERNS = [
    re.compile(r"RSA.*(?:1024|512|768)\b"),
    re.compile(r"generate.*(?:1024|512|768)\b.*(?:key|rsa)", re.IGNORECASE),
    re.compile(r"key.?(?:size|length|bits)\s*(?:=|:)\s*(?:512|768|1024)\b"),
    re.compile(r"rsa\.GenerateKey\([^,]+,\s*(?:512|768|1024)\)"),
]

# CWE-326, second path: the key strength is not written down anywhere — it
# lives in the PEM body. juice-shop inlines a 1024-bit RSA private key in
# `lib/insecurity.ts` and signs every JWT with it; every pattern above needs a
# literal 512/768/1024 next to "RSA", so the whole repo reported zero CWE-326.
#
# So decode the base64 body of an inline PEM literal and read the modulus.
# EC/DSA/OpenSSH/PGP blocks are skipped: their integers are not RSA moduli and
# a 256-bit EC key is perfectly strong. For an unlabelled PKCS#8
# `BEGIN PRIVATE KEY` we require the RSA algorithm OID to be present before
# interpreting an integer as a modulus.
PEM_KEY_BEGIN = re.compile(r"-----BEGIN (RSA |)(?:PRIVATE|PUBLIC) KEY-----")
PEM_KEY_END = re.compile(r"-----END (?:[A-Z]+ )?(?:PRIVATE|PUBLIC) KEY-----")

# rsaEncryption OID 1.2.840.113549.1.1.1, DER-encoded content bytes.
_RSA_OID = bytes.fromhex("2a864886f70d010101")
_MIN_RSA_BITS = 2048
_MAX_PEM_LINES = 80
# String-escaped newlines inside a source literal ("...KEY-----\r\n...").
_PEM_ESCAPE = re.compile(r"\\[rnt]")
_NON_BASE64 = re.compile(r"[^A-Za-z0-9+/=]")

# CWE-330: Insufficient randomness
WEAK_RANDOM_PATTERNS = [
    re.compile(r"\brandom\.random\s*\("),
    re.compile(r"\brandom\.randint\s*\("),
    re.compile(r"\brandom\.choice\s*\("),
    re.compile(r"\bMath\.random\s*\("),
    re.compile(r"\brand\(\s*\)"),
    re.compile(r"\bsrand\s*\("),
    re.compile(r"java\.util\.Random\b"),
]

SAFE_RANDOM_CONTEXT = re.compile(
    r"(?:secrets\.|crypto[./]rand|os\.urandom|SecureRandom|"
    r"CSPRNG|getrandom|SystemRandom|test|shuffle|sample.*display)",
    re.IGNORECASE,
)

# Two-tier context: weak random is only high when file has security/crypto context
_CRYPTO_CONTEXT = [re.compile(r"(encrypt|decrypt|token|secret|password|auth|sign|verify|key)", re.IGNORECASE)]

# CWE-328: Reversible one-way hash (MD5/SHA1 for integrity)
WEAK_HASH_PATTERNS = [
    re.compile(r"hashlib\.md5\("),
    re.compile(r"hashlib\.sha1\("),
    re.compile(r"\bMD5\.(?:new|Create|digest)\b"),
    re.compile(r"\bSHA1\.(?:new|Create|digest)\b"),
    re.compile(r"crypto\.MD5\b"),
    re.compile(r"crypto\.SHA1\b"),
    re.compile(r"md5\.New\(\)"),
    re.compile(r"sha1\.New\(\)"),
    re.compile(r'MessageDigest\.getInstance\(\s*["\'](?:MD5|SHA-?1)["\']'),
    # Node: crypto.createHash('md5') / createHmac("sha1", key).
    #
    # Every pattern above is Python/Go/Java-shaped, so Node was uncovered —
    # juice-shop hashes passwords with crypto.createHash('md5') and the whole
    # report contained no CWE-327/328/916 at all.
    re.compile(r'create(?:Hash|Hmac)\(\s*["\'](?:md5|sha-?1)["\']', re.IGNORECASE),
]

# Contexts where a weak digest is defensible (non-security integrity checks).
#
# `hmac` was previously listed here, which would have suppressed a
# createHmac('md5', ...) finding as soon as one became detectable — an HMAC
# construction does not rescue a broken digest when the digest itself is the
# weakness. Anchor the remaining terms so a bare substring like the "test" in
# "latest" or the "compat" in "compatibility" cannot silence a real finding.
SAFE_HASH_CONTEXT = re.compile(
    r"(?:checksum|fingerprint|cache.?key|etag|\btest\b|\blegacy\b|\bcompat\b)",
    re.IGNORECASE,
)

# Hardcoded cryptographic keys (CWE-321).
#
# The name group used to be `encrypt|cipher|aes|secret` only, so the two keys
# juice-shop ships in source — `const privateKey = '-----BEGIN RSA ...'` and
# the HMAC key literal below — were both invisible. Signing/session/cookie/JWT
# keys are exactly as sensitive as an encryption key, and a key handed
# POSITIONALLY to a Node crypto constructor has no name at all, hence the third
# pattern.
#
# `session` and `cookie` are deliberately NOT in this list even though they name
# key material occasionally: `sessionKey` / `cookieKey` overwhelmingly name a
# *slot*, not a secret. Measured — both juice-shop hits of that shape were
# `welcomeBannerStatusCookieKey = 'welcomebanner_status'`, and adding the two
# names produced 57 rows on a second corpus (openclaw), every one of them a
# routing identifier like `sessionKey: "hook:gmail:{{id}}"`. A hardcoded
# session-signing key named exactly `sessionKey` is the accepted miss; the far
# more common `session_secret` / `cookieSecret` spellings are not matched by
# this rule either way.
_KEY_NAME = r"(?:encrypt(?:ion)?|cipher|aes|secret|private|signing|sign|hmac|jwt|master)"

# Elided documentation values (`PRIVATE_KEY="nsec1..."`, `key = "xxxxxxxx"`)
# are not key material. SAFE_KEY_CONTEXT can't express this: it tests the whole
# line, while this has to test the captured literal.
HARDCODED_KEY_NAMED = re.compile(
    rf'{_KEY_NAME}.?key\s*(?:=|:)\s*["\']([^"\']{{8,}})["\']', re.IGNORECASE,
)
PLACEHOLDER_KEY_VALUE = re.compile(r"(?:\.\.\.$|^\*+$|^x{4,}$|^<.*>$)", re.IGNORECASE)

HARDCODED_KEY_PATTERNS = [
    HARDCODED_KEY_NAMED,
    re.compile(r'(?:iv|nonce)\s*(?:=|:)\s*b?["\'][^"\']{8,}["\']', re.IGNORECASE),
    # Literal key as the second argument of a Node crypto constructor:
    # crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')
    re.compile(
        r'create(?:Hmac|Cipheriv|Decipheriv|Cipher|Decipher|Sign|Verify)\s*\(\s*'
        r'["\'][^"\']+["\']\s*,\s*["\'][^"\']{8,}["\']',
        re.IGNORECASE,
    ),
]

SAFE_KEY_CONTEXT = re.compile(
    r"(?:os\.(?:environ|getenv)|process\.env|Config\.|config\[|"
    r"example|placeholder|test|dummy|mock|<)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")


def check_cryptography(source_path: str) -> dict:
    """Check for CWE cryptography vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of cryptography vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for cryptography patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_broken_crypto(file_path, line, line_num, lines, findings)
        _check_weak_keys(file_path, line, line_num, lines, findings)
        _check_weak_random(file_path, line, line_num, lines, content, findings)
        _check_weak_hash(file_path, line, line_num, lines, findings)
        _check_hardcoded_key(file_path, line, line_num, lines, findings)


def _check_broken_crypto(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-327 broken cryptographic algorithm.

    Two paths:
      1. Specific high-confidence shapes (DES.new(), MODE_ECB,
         Cipher.getInstance("DES")) — fire on first match.
      2. Bare-name occurrence (`\\bDES\\b` etc.) — only fire if the
         line ALSO contains a crypto symbol like `cipher`, `crypto`,
         `encrypt`, `decrypt`, `key`, `IV`, `mode`. Context can appear
         before OR after the cipher name on the line (so
         `from Crypto.Cipher import DES` matches).
    """
    if SAFE_CRYPTO_CONTEXT.search(line):
        return
    matched = False
    for pattern in BROKEN_CRYPTO_PATTERNS:
        if pattern.search(line):
            matched = True
            break
    if not matched and BROKEN_CRYPTO_BARE_NAME.search(line) and BROKEN_CRYPTO_CONTEXT.search(line):
        matched = True
    if not matched:
        return
    finding = {
        "severity": "critical",
        "check_id": "cwe.crypto.broken_algorithm",
        "category": "CWE-327",
        "title": "Broken cryptographic algorithm",
        "description": f"Use of weak cipher or mode at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use AES-256-GCM, ChaCha20-Poly1305, or other modern algorithms",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "327"))


def _der_read_length(data: bytes, i: int) -> tuple[int, int] | None:
    """Parse the DER length octets at `i`; return (length, next index)."""
    length = data[i]
    i += 1
    if not length & 0x80:
        return length, i
    count = length & 0x7F
    if count == 0 or count > 4 or i + count > len(data):
        return None
    return int.from_bytes(data[i:i + count], "big"), i + count


def _der_max_integer_bits(data: bytes, depth: int = 0) -> int:
    """Largest INTEGER bit length anywhere in a DER blob.

    For a PKCS#1 RSAPrivateKey / RSAPublicKey the modulus is the largest
    integer, so the maximum is the key size. Recursing through SEQUENCE /
    OCTET STRING / BIT STRING wrappers also handles PKCS#8 and SPKI without
    needing a full ASN.1 implementation.
    """
    best = 0
    i, n = 0, len(data)
    while i + 1 < n:
        tag = data[i]
        parsed = _der_read_length(data, i + 1)
        if parsed is None:
            break
        length, i = parsed
        if length > n - i:
            break
        chunk = data[i:i + length]
        i += length
        if tag == 0x02:  # INTEGER
            best = max(best, int.from_bytes(chunk, "big").bit_length())
        elif depth < 4 and tag in (0x30, 0x31, 0x04, 0x03):
            body = chunk[1:] if tag == 0x03 else chunk  # BIT STRING: unused-bits octet
            best = max(best, _der_max_integer_bits(body, depth + 1))
    return best


def _pem_body(line: str, lines: list[str], line_num: int) -> str | None:
    """Collect the base64 body of a PEM block starting on ``line``.

    Handles both juice-shop's one-line literal (whole PEM in a single string
    with escaped ``\\r\\n``) and a conventional multi-line block. Returns None
    when no terminator is found within a sane distance.
    """
    header = PEM_KEY_BEGIN.search(line)
    if header is None:
        return None
    rest = line[header.end():]
    parts: list[str] = []
    for offset in range(_MAX_PEM_LINES):
        end = PEM_KEY_END.search(rest)
        if end is not None:
            parts.append(rest[:end.start()])
            return "".join(parts)
        parts.append(rest)
        nxt = line_num + offset  # 0-indexed: the line after line_num
        if nxt >= len(lines):
            return None
        rest = lines[nxt]
    return None


def _pem_key_bits(line: str, lines: list[str], line_num: int) -> int | None:
    """RSA modulus bit length of an inline PEM literal, or None."""
    body = _pem_body(line, lines, line_num)
    if body is None:
        return None
    b64 = _NON_BASE64.sub("", _PEM_ESCAPE.sub("", body))
    if len(b64) < 64:
        return None
    b64 = b64.rstrip("=")
    der = _b64_decode(b64 + "=" * (-len(b64) % 4))
    if der is None:
        return None
    labelled_rsa = bool(PEM_KEY_BEGIN.search(line).group(1))  # type: ignore[union-attr]
    if not labelled_rsa and _RSA_OID not in der:
        return None
    bits = _der_max_integer_bits(der)
    return bits if 256 <= bits <= 16384 else None


def _b64_decode(text: str) -> bytes | None:
    """Strict base64 decode that never raises."""
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _check_weak_keys(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-326 inadequate encryption strength.

    Two paths: an explicit weak key size written in the source, and an inline
    PEM literal whose decoded modulus is below 2048 bits.
    """
    detail = _weak_key_detail(line, lines, line_num)
    if detail is None:
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.crypto.weak_key",
        "category": "CWE-326",
        "title": "Inadequate encryption key strength",
        "description": detail.format(line_num=line_num),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use RSA >= 2048 bits, or switch to ECC (P-256+)",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "326"))


def _weak_key_detail(line: str, lines: list[str], line_num: int) -> str | None:
    """Description template for a weak key on this line, or None.

    A decoded PEM modulus is authoritative: when the line carries a PEM literal
    we answer from its real bit length and never fall through to the textual
    patterns, whose `RSA.*(?:512|768|1024)` shape would otherwise match a digit
    run inside the base64 body of a perfectly strong key.
    """
    bits = _pem_key_bits(line, lines, line_num)
    if bits is not None:
        if bits >= _MIN_RSA_BITS:
            return None
        return (
            f"Inline PEM key literal has a {bits}-bit RSA modulus "
            f"(minimum {_MIN_RSA_BITS}) at line {{line_num}}"
        )
    for pattern in WEAK_KEY_PATTERNS:
        if pattern.search(line):
            return "Key size below recommended minimum at line {line_num}"
    return None


def _check_weak_random(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict],
) -> None:
    """Check for CWE-330 insufficient randomness."""
    if SAFE_RANDOM_CONTEXT.search(line):
        return
    for pattern in WEAK_RANDOM_PATTERNS:
        if pattern.search(line):
            # Two-tier: demote to medium if file lacks security/crypto context
            severity = "high"
            if not check_context(content, _CRYPTO_CONTEXT):
                severity = "medium"
            finding = {
                "severity": severity,
                "check_id": "cwe.crypto.weak_random",
                "category": "CWE-330",
                "title": "Use of non-cryptographic randomness",
                "description": f"Weak random number generator at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use secrets module, crypto/rand, or SecureRandom",
                "verification_hints": ["Verify algorithm is used for security (not checksums)"],
                "requires_context": True,
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "330"))
            return


def _check_weak_hash(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-328 reversible one-way hash."""
    if SAFE_HASH_CONTEXT.search(line):
        return
    for pattern in WEAK_HASH_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.crypto.weak_hash",
                "category": "CWE-328",
                "title": "Weak hash algorithm for integrity",
                "description": f"MD5 or SHA1 used for hashing at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use SHA-256 or SHA-3 for integrity checks",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "328"))
            return


def _check_hardcoded_key(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for hardcoded cryptographic keys (CWE-321).

    CWE-321 ("Use of Hard-coded Cryptographic Key") is the precise CWE
    for keys embedded in source. Earlier code labelled this CWE-327
    ("Use of Broken/Risky Algorithm"), which mis-routes catalog
    enrichment and confuses downstream triage.

    Suppress when the captured RHS is a variable reference (`$VAR`,
    `${VAR}`, `{{ var }}`) — the literal value is a pointer, not a key.
    """
    if SAFE_KEY_CONTEXT.search(line):
        return
    if line_value_is_variable_ref(line):
        return
    for pattern in HARDCODED_KEY_PATTERNS:
        match = pattern.search(line)
        if match:
            if pattern is HARDCODED_KEY_NAMED and PLACEHOLDER_KEY_VALUE.search(match.group(1)):
                continue
            finding = {
                "severity": "critical",
                "check_id": "cwe.crypto.hardcoded_key",
                "category": "CWE-321",
                "title": "Hardcoded cryptographic key",
                "description": f"Cryptographic key embedded in source code at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Load encryption keys from environment variables or key management service",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "321"))
            return


check_cryptography_tool = function_tool(check_cryptography)
