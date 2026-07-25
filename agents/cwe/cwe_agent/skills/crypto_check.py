"""CWE cryptography vulnerability detection skill."""

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
_CRYPTO_CONTEXT = [re.compile(r"(encrypt|decrypt|token|secret|password|auth|sign|verify|key)", re.I)]

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
]

SAFE_HASH_CONTEXT = re.compile(
    r"(?:checksum|fingerprint|cache.?key|etag|HMAC|hmac|test|legacy|compat)",
    re.IGNORECASE,
)

# Hardcoded encryption keys
HARDCODED_KEY_PATTERNS = [
    re.compile(r'(?:encrypt|cipher|aes|secret).?key\s*(?:=|:)\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'(?:iv|nonce)\s*(?:=|:)\s*b?["\'][^"\']{8,}["\']', re.IGNORECASE),
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
    if not matched and BROKEN_CRYPTO_BARE_NAME.search(line):
        if BROKEN_CRYPTO_CONTEXT.search(line):
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


def _check_weak_keys(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-326 inadequate encryption strength."""
    for pattern in WEAK_KEY_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.crypto.weak_key",
                "category": "CWE-326",
                "title": "Inadequate encryption key strength",
                "description": f"Key size below recommended minimum at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use RSA >= 2048 bits, or switch to ECC (P-256+)",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "326"))
            return


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
        if pattern.search(line):
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
