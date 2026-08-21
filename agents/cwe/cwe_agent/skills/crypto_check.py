"""CWE cryptography vulnerability detection skill."""

import base64
import binascii
import re
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from agents import function_tool
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    effective_name,
    effective_suffix,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import check_context, extract_snippet

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._args import arg_slot, call_span_end, split_call_args
from cwe_agent.skills._var_reference import line_value_is_variable_ref
from cwe_agent.skills.weak_entropy_check import (
    SECURITY_VALUE_TOKEN as _SECURITY_VALUE_TOKEN,
)
from cwe_agent.skills.weak_entropy_check import (
    _has_safe_cooccurrence as _entropy_safe_cooccurrence,
)
from cwe_agent.skills.weak_entropy_check import (
    _is_sensitive as _entropy_is_sensitive,
)
from cwe_agent.skills.weak_entropy_check import (
    _looks_like_flow as _entropy_flow_target,
)

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
]

# Go `rsa.GenerateKey(reader, bits)`: the weak size lives in a POSITIONAL slot,
# so it is read from the tokenised argument list. The `[^,]+` reader stand-in
# this replaces stops at the first comma, so `GenerateKey(newReader(a, 1024),
# 4096)` read the reader's own argument as the key size.
_GO_GENERATE_KEY = re.compile(r"\brsa\.GenerateKey\s*\(")
_WEAK_RSA_BITS = frozenset({"512", "768", "1024"})

# CWE-326, second path: the key strength is not written down anywhere — it
# lives in the PEM body. An app that inlines a 1024-bit RSA private key and signs
# every JWT with it went unreported: every pattern above needs a literal
# 512/768/1024 next to "RSA", so such a repo reported zero CWE-326.
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
    re.compile(r"\brandom\.(?:randrange|choices)\s*\("),
    re.compile(r"\bMath\.random\s*\("),
    re.compile(r"\brand\(\s*\)"),
    re.compile(r"\bsrand\s*\("),
    re.compile(r"\bmt_rand\s*\("),
    re.compile(r"java\.util\.Random\b"),
    re.compile(r"\bRandom\(\s*\)\.next(?:Int|Long)\s*\("),
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
    # an app hashing passwords with crypto.createHash('md5') produced no
    # CWE-327/328/916 at all.
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
# The name group used to be `encrypt|cipher|aes|secret` only, so the two key
# shapes most often shipped in source — `const privateKey = '-----BEGIN RSA ...'` and
# the HMAC key literal below — were both invisible. Signing/session/cookie/JWT
# keys are exactly as sensitive as an encryption key, and a key handed
# POSITIONALLY to a Node crypto constructor has no name at all, hence the third
# pattern.
#
# `session` and `cookie` are deliberately NOT in this list even though they name
# key material occasionally: `sessionKey` / `cookieKey` overwhelmingly name a
# *slot*, not a secret. Measured — both hits of that shape in one sweep were
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

# ---------------------------------------------------------------------------
# CWE-322: key exchange without entity authentication.
#
# Two families. (a) An anonymous key-agreement suite in a cipher list — no
# certificate is exchanged at all, so the peer is unauthenticated. (b) SSH
# host-key verification disabled.
#
# MAPPING CAVEAT, recorded deliberately: CWE-322 is "performs a key exchange
# with an actor without verifying the identity of that actor". Disabling SSH
# host-key checking satisfies that text on its face; the TLS analogues that
# disable *certificate* validation stay on CWE-295/297 (they authenticate with
# a certificate and then ignore the result).
#
# Family (b) is restricted to executable and config dialects. Measured on the
# baseline: of 3 surviving rows, 2 were a markdown security advisory that names
# `StrictHostKeyChecking=no` and `UserKnownHostsFile=/dev/null` in order to
# CONDEMN them, and COMMENT_INDICATORS cannot help — markdown body text carries
# no comment marker. The third real occurrence outside config was a guard that
# string-matches the option in order to reject it, hence the matcher veto.
# ---------------------------------------------------------------------------
_EXEC_CONFIG_SUFFIXES = frozenset({
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".yml", ".yaml", ".toml", ".json", ".tf", ".tfvars", ".hcl",
    ".conf", ".cfg", ".ini", ".properties", ".env", ".envrc",
    ".py", ".go", ".java", ".kt", ".rb", ".ts", ".tsx", ".js", ".jsx",
    ".mjs", ".cjs", ".cs", ".php", ".rs", ".gradle", ".dockerfile",
})
_EXEC_CONFIG_NAMES = frozenset({
    "Dockerfile", "Containerfile", "Makefile", "Jenkinsfile",
})

# Case-SENSITIVE: suite names are uppercase (`ADH`, `DH_anon`) and a lowercase
# match would read the ordinary identifier `adherence` as a cipher suite. The
# `(?:\b|_)` edges are what let `TLS_ECDH_anon_WITH_AES_128_CBC_SHA` match
# while `ADHOC_TIMEOUT` does not.
_ANON_KEX_SUITE = re.compile(r"(?:\b|_)(?:aNULL|ADH|DH_anon|ECDH_anon)(?:\b|_)")
# `HIGH:!aNULL:!ADH` EXCLUDES the anonymous suites — the recommended config.
_ANON_KEX_EXCLUDED = re.compile(r"[!\-](?:aNULL|ADH|kDH|DH_anon|ECDH_anon)")
_CIPHER_LIST_CONTEXT = re.compile(r"cipher|ssl|tls", re.IGNORECASE)

_SSH_NO_HOST_KEY = re.compile(
    r"StrictHostKeyChecking\s*[=: ]\s*[\"']?no\b"
    r"|UserKnownHostsFile\s*[=: ]\s*[\"']?/dev/null"
    r"|InsecureIgnoreHostKey\s*\("
    r"|AutoAddPolicy\s*\(",
    re.IGNORECASE,
)
_SSH_VERIFIED = re.compile(
    r"StrictHostKeyChecking\s*[=: ]\s*[\"']?(?:yes|accept-new)"
    r"|FixedHostKey|knownhosts\.New|RejectPolicy|WarningPolicy",
    re.IGNORECASE,
)
# A rule that reports the code REJECTING the weakness is a self-inflicted FP.
_MATCHER_CONTEXT = re.compile(
    r"strings\.Contains|\.includes\s*\(|\.match\s*\(|expect\s*\(|assert"
    r"|regexp\.|MustCompile|re\.compile|toBe\s*\(|\bshould\b",
)

_ANON_SUITE_REASON = "anonymous key-agreement cipher suite (no peer certificate)"
_SSH_HOST_KEY_REASON = "SSH host-key verification disabled"

# ---------------------------------------------------------------------------
# CWE-780: RSA encryption without OAEP (PKCS#1 v1.5 padding).
# ---------------------------------------------------------------------------
_RSA_DOTNET_PKCS1 = re.compile(r"\bRSAEncryptionPadding\.Pkcs1\b")
_RSA_NODE_PKCS1 = re.compile(r"\bRSA_PKCS1_PADDING\b")
_CRYPTOGRAPHY_V15 = re.compile(r"\bpadding\.PKCS1v15\s*\(")
_ENCRYPT_CALL = re.compile(r"\b(?:en|de)crypt\w*\s*\(", re.IGNORECASE)
_PYCRYPTO_V15_CALL = re.compile(r"\bPKCS1_v1_5\.new\s*\(")
_PYCRYPTO_CIPHER_IMPORT = re.compile(r"from\s+Crypto\.Cipher\s+import[^\n]*PKCS1_v1_5")
_PYCRYPTO_SIG_IMPORT = re.compile(r"from\s+Crypto\.Signature\s+import[^\n]*PKCS1_v1_5")
_JCE_RSA_TRANSFORM = re.compile(r"Cipher\.getInstance\s*\(\s*[\"'](RSA[^\"']*)[\"']")
_DOTNET_ENCRYPT = re.compile(r"(\w*)\.Encrypt\s*\(")
_DOTNET_RSA_FILE = re.compile(
    r"RSACryptoServiceProvider|RSA\.Create\s*\(|System\.Security\.Cryptography",
)
# A JCE transformation whose algorithm is RSA: `ECB` there is not a chaining
# mode (RSA has none), so the bare-name CWE-327 path must not fire on it.
_RSA_TRANSFORMATION = re.compile(r"[\"']RSA/", re.IGNORECASE)


def _arm_dotnet_padding(line: str, content: str) -> str | None:
    """.NET explicit PKCS#1 v1.5 encryption padding."""
    return "RSAEncryptionPadding.Pkcs1" if _RSA_DOTNET_PKCS1.search(line) else None


def _arm_node_constant(line: str, content: str) -> str | None:
    """Node `crypto.constants.RSA_PKCS1_PADDING` (never the OAEP constant)."""
    return "RSA_PKCS1_PADDING" if _RSA_NODE_PKCS1.search(line) else None


def _arm_cryptography_v15(line: str, content: str) -> str | None:
    """`padding.PKCS1v15()` on an encrypt/decrypt call (signing is not 780)."""
    if not _CRYPTOGRAPHY_V15.search(line) or not _ENCRYPT_CALL.search(line):
        return None
    return "padding.PKCS1v15() on an RSA encryption call"


def _arm_pycrypto_cipher(line: str, content: str) -> str | None:
    """`PKCS1_v1_5.new(` resolved to Crypto.Cipher, not Crypto.Signature.

    The name is shared by the cipher and the signature module; only the cipher
    one is CWE-780. The per-line loop skips IMPORT_LINE, so the import is
    resolved against the whole file.
    """
    if not _PYCRYPTO_V15_CALL.search(line):
        return None
    if _PYCRYPTO_SIG_IMPORT.search(content) or not _PYCRYPTO_CIPHER_IMPORT.search(content):
        return None
    return "Crypto.Cipher.PKCS1_v1_5 (RSA PKCS#1 v1.5 encryption)"


def _arm_jce_transformation(line: str, content: str) -> str | None:
    """A JCE `RSA/...` transformation that is not OAEP-padded."""
    match = _JCE_RSA_TRANSFORM.search(line)
    if match is None or "OAEP" in match.group(1).upper():
        return None
    return f"JCE transformation {match.group(1)!r} (PKCS#1 v1.5 padding)"


def _rsa_anchored(receiver: str, content: str) -> bool:
    """True when a bare `.Encrypt(x, false)` is demonstrably an RSA call.

    A bare two-argument encrypt with a boolean flag matches any helper
    (`vault.Encrypt(payload, false)`), so it needs either an RSA receiver or
    an RSA type in the file.
    """
    return "rsa" in receiver.lower() or _DOTNET_RSA_FILE.search(content) is not None


def _arm_dotnet_foaep_false(line: str, content: str) -> str | None:
    """.NET `Encrypt(data, fOAEP: false)` — the positional legacy overload."""
    match = _DOTNET_ENCRYPT.search(line)
    if match is None or not _is_foaep_false(line, match.end() - 1):
        return None
    if not _rsa_anchored(match.group(1), content):
        return None
    return "RSA Encrypt(..., fOAEP: false) — PKCS#1 v1.5 padding"


def _is_foaep_false(line: str, paren: int) -> bool:
    """True for exactly `(<data>, false)` — a positional slot test, not `[^,]+`."""
    args = split_call_args(line, paren)
    return args is not None and len(args) == 2 and args[1] == "false"


_RSA_NO_OAEP_ARMS = (
    _arm_dotnet_padding,
    _arm_node_constant,
    _arm_cryptography_v15,
    _arm_pycrypto_cipher,
    _arm_jce_transformation,
    _arm_dotnet_foaep_false,
)

# ---------------------------------------------------------------------------
# CWE-338: cryptographically weak PRNG for a security value.
#
# A CONDITIONAL re-tag of the CWE-330 row: the same weak-RNG call is CWE-338
# only when a line-local token names a security value. Measured: 25 non-test
# weak-RNG lines on the baseline, of which the line-local gate keeps 1 (itself
# a comment, already dropped upstream). The 24 it rejects are exactly the
# retry-jitter, slug-picker and correlation-id shapes a file-level crypto
# context would have mislabelled.
#
# The security-value vocabulary itself lives in ``weak_entropy_check`` (imported
# above as ``_SECURITY_VALUE_TOKEN``): that skill's CWE-336/337 seed gate needs
# the same answer to "does this text name a credential?", and two drifting
# copies of that judgement is how one rule ends up flagging what the other
# exempts. The exclusions it encodes are documented at its definition.
#
# Non-security consumers of a weak draw, kept from the measured FP classes.
_NON_SECURITY_CONSUMER = re.compile(
    r"jitter|backoff|\bdelay\b|\bindex\b|\.length\b|display|shuffle|placeholder"
    r"|animation|\bslug\b|avatar|\bcolou?r\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CWE-329 (predictable IV with CBC) / CWE-323 (nonce reuse with an AEAD or
# stream mode). One table of constructor specs, one slot test.
#
# The mode gate reads the constructor's OWN algorithm/mode argument, so a
# variable algorithm is not evidence of either mode, and the two mode sets are
# mutually exclusive: one line can never carry both ids.
# ---------------------------------------------------------------------------
_CBC_MODE = re.compile(r"-cbc\b|MODE_CBC\b|modes\.CBC\s*\(|/CBC/|NewCBC", re.IGNORECASE)
_AEAD_MODE = re.compile(
    r"-(?:gcm|ctr|ofb|cfb)\b|chacha20[-_]?poly1305|MODE_(?:GCM|CCM|CTR|OFB|CFB)\b"
    r"|modes\.(?:GCM|CTR|OFB|CFB)\s*\(|/GCM/|NewGCM\s*\(|GCMParameterSpec",
    re.IGNORECASE,
)
_JCE_CBC_TRANSFORM = re.compile(r"[\"'][A-Za-z0-9]+/CBC/")
_AEAD_RECEIVER = re.compile(r"gcm|aead|chacha", re.IGNORECASE)

# A zero-filled allocation. As a BARE token this matched 41 benign baseline
# lines (`make([]byte, 4096)`, `Buffer.alloc(0)`, a WAV header), so it is only
# ever applied to a constructor's IV/nonce slot.
_ZERO_ALLOC_SRC = (
    r"Buffer\.alloc(?:Unsafe)?\s*\(\s*\d+\s*\)"
    r"|bytes\s*\(\s*\d+\s*\)"
    r"|bytearray\s*\(\s*\d+\s*\)"
    r"|new\s+byte\s*\[\s*[\w.]+\s*\]"
    r"|new\s+Uint8Array\s*\(\s*[\w.]+\s*\)"
    r"|make\s*\(\s*\[\]byte\s*,\s*[\w.]+\s*\)"
)
_ZERO_ALLOC = re.compile(rf"^(?:{_ZERO_ALLOC_SRC})$")
_LITERAL_VALUE = re.compile(
    r"^(?:b|rb|br|u|@)?(?:\"[^\"]*\"|'[^']*'|`[^`]*`)$"
    r"|^\[\]byte\s*\(\s*\"[^\"]*\"\s*\)$",
)
# A charset/encoding conversion wrapped around a literal — `"0000".getBytes(cs)`
# is still a hardcoded IV. The `[^)]*` stand-in this replaces cannot span a
# nested call, so `.getBytes(Charset.forName("UTF-8"))` was a silent miss; the
# tokeniser instead requires the conversion call to END the slot, so
# `"0000".getBytes(cs) + suffix` is not read as a bare literal.
_CONVERSION_CALL = re.compile(r"\.(?:getBytes|encode|toCharArray)\s*\(")
_IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")
_CSPRNG_FILL = re.compile(
    r"randomFillSync|randomBytes|rand\.Read|urandom|get_random_bytes|SecureRandom"
    r"|nextBytes|randombytes|token_bytes|getRandomValues|randomFill",
)

_REASON_LITERAL = "a hardcoded literal"
_REASON_ZERO = "a zero-filled buffer"
_REASON_KEY_REUSE = "the same value as the key"
_REASON_ZERO_BOUND = "bound to a zero-filled buffer that is never CSPRNG-filled"


class _IvSpec(NamedTuple):
    """One constructor shape: where the IV/nonce and key slots are."""

    anchor: re.Pattern[str]
    iv: int
    key: int | None
    mode_slot: int | None
    mode: str | None
    gate: re.Pattern[str] | None
    gate_scope: str


_IV_SPECS = (
    _IvSpec(re.compile(r"\bcreate(?:Cipher|Decipher)iv\s*\("), 2, 1, 0, None, None, ""),
    _IvSpec(re.compile(r"\bAES\.new\s*\("), 2, 0, 1, None, None, ""),
    _IvSpec(re.compile(r"\bNewCBC(?:En|De)crypter\s*\("), 1, None, None, "cbc", None, ""),
    _IvSpec(
        re.compile(r"\bnew\s+IvParameterSpec\s*\("), 0, None, None, "cbc",
        _JCE_CBC_TRANSFORM, "file",
    ),
    _IvSpec(re.compile(r"\bnew\s+GCMParameterSpec\s*\("), 1, None, None, "aead", None, ""),
    _IvSpec(re.compile(r"\bmodes\.CBC\s*\("), 0, None, None, "cbc", None, ""),
    _IvSpec(re.compile(r"\bmodes\.(?:GCM|CTR|OFB|CFB)\s*\("), 0, None, None, "aead", None, ""),
    _IvSpec(
        re.compile(r"\.(?:Seal|Open)\s*\("), 1, None, None, "aead",
        _AEAD_RECEIVER, "line",
    ),
)

_IV_ROWS = {
    "cbc": {
        "severity": "medium",
        "check_id": "cwe.crypto.static_iv_cbc",
        "category": "CWE-329",
        "title": "Predictable initialization vector with CBC mode",
        "recommendation": (
            "Draw a fresh IV from a CSPRNG for every message and transmit it "
            "alongside the ciphertext"
        ),
    },
    "aead": {
        "severity": "high",
        "check_id": "cwe.crypto.nonce_reuse",
        "category": "CWE-323",
        "title": "Nonce reuse with an AEAD or stream cipher mode",
        "recommendation": (
            "Never reuse a nonce with the same key: use a per-message counter "
            "or a CSPRNG draw (GCM/CTR nonce reuse leaks the keystream)"
        ),
    },
}
_IV_CWE = {"cbc": "329", "aead": "323"}


# ---------------------------------------------------------------------------
# CWE-760: one-way hash with a predictable salt.
#
# Same machinery as the IV/nonce rule — a constructor spec table plus a
# positional slot test over the depth-aware argument tokeniser — because the
# failure mode is identical: `pbkdf2Sync(Buffer.from(pwHex, 'hex'), salt, ...)`
# defeats any `[^,]+` argument stand-in by sliding the salt group onto the
# `'hex'` literal that belongs to the PASSWORD argument.
#
# Only the KDF families are listed. A bare digest over a literal is not this
# weakness (no salt is CWE-759, owned by ``auth_check``); what CWE-760 names is
# a salted construction whose salt is the same on every password.
# ---------------------------------------------------------------------------


class _SaltSpec(NamedTuple):
    """One key-derivation shape: where the salt argument sits."""

    anchor: re.Pattern[str]
    salt: int


_SALT_SPECS = (
    # hashlib.pbkdf2_hmac(hash_name, password, salt, iterations)
    _SaltSpec(re.compile(r"\bpbkdf2_hmac\s*\("), 2),
    # PHP hash_pbkdf2(algo, password, salt, iterations)
    _SaltSpec(re.compile(r"\bhash_pbkdf2\s*\("), 2),
    # Node crypto.pbkdf2 / pbkdf2Sync(password, salt, iterations, keylen, digest)
    _SaltSpec(re.compile(r"\bpbkdf2(?:Sync)?\s*\(", re.IGNORECASE), 1),
    # Node crypto.scrypt / scryptSync and hashlib.scrypt(password, salt=..., n=...)
    _SaltSpec(re.compile(r"\bscrypt(?:Sync)?\s*\(", re.IGNORECASE), 1),
    # Go golang.org/x/crypto: pbkdf2.Key / scrypt.Key / argon2.IDKey(pw, salt, ...)
    _SaltSpec(re.compile(r"\b(?:pbkdf2|scrypt)\.Key\s*\("), 1),
    _SaltSpec(re.compile(r"\bargon2\.(?:ID|I)?Key\s*\("), 1),
    # JCE new PBEKeySpec(password, salt, iterationCount, keyLength)
    _SaltSpec(re.compile(r"\bnew\s+PBEKeySpec\s*\("), 1),
    # .NET new Rfc2898DeriveBytes(password, salt, iterations)
    _SaltSpec(re.compile(r"\bnew\s+Rfc2898DeriveBytes\s*\("), 1),
    # bcrypt.hashpw(password, salt) — a literal here replaces gensalt()
    _SaltSpec(re.compile(r"\bhashpw\s*\("), 1),
)

_SALT_ROW = {
    "severity": "high",
    "check_id": "cwe.crypto.predictable_salt",
    "category": "CWE-760",
    "title": "One-way hash with a predictable salt",
    "recommendation": (
        "Generate a fresh salt per password from a CSPRNG and store it "
        "alongside the hash; a shared salt lets one precomputed table cover "
        "every account"
    ),
    "verification_hints": ["Confirm the salt slot is not a per-user value"],
}


def _spec_salt(
    spec: _SaltSpec, ctx: "_FileCtx", line: str, line_num: int,
) -> str | None:
    """Apply one KDF spec to ``line`` and test its salt slot."""
    match = spec.anchor.search(line)
    if match is None:
        return None
    args = _call_slots(line, ctx.lines, line_num, match.end() - 1)
    slot = arg_slot(args, spec.salt) if args else None
    return _iv_defect(slot, None, ctx.lines, line_num) if slot else None


def _salt_defect(ctx: "_FileCtx", line: str, line_num: int) -> str | None:
    """Why this line's KDF salt is predictable, or None."""
    for spec in _SALT_SPECS:
        reason = _spec_salt(spec, ctx, line, line_num)
        if reason is not None:
            return reason
    return None


def _check_predictable_salt(
    ctx: "_FileCtx", line: str, line_num: int, findings: list[dict],
) -> bool:
    """Check for CWE-760 use of a one-way hash with a predictable salt.

    Returns True when a row was emitted, so the caller can suppress the generic
    CWE-321 arm on the same line (P5: skill findings are not deduplicated
    against each other, so a second label there would be a duplicate row).
    """
    reason = _salt_defect(ctx, line, line_num)
    if reason is None:
        return False
    finding = dict(_SALT_ROW)
    finding["description"] = f"The salt argument at line {line_num} is {reason}"
    finding["file_path"] = str(ctx.path)
    finding["line_start"] = line_num
    finding["line_end"] = line_num
    finding["code_snippet"] = extract_snippet(ctx.lines, line_num)
    findings.append(enrich_finding(finding, "760"))
    return True


def check_cryptography(source_path: str) -> dict:
    """Check for CWE cryptography vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of cryptography vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if not _is_scannable(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _is_scannable(file_path: Path) -> bool:
    """Per-file guard chain.

    Documentation prose MENTIONS crypto APIs; it does not call them. A
    hardening guide that tells you never to disable host-key checking is not an
    instance of disabling it, and COMMENT_INDICATORS cannot see markdown body
    text (P7). Measured on three real trees: 4 rows removed (CWE-327, CWE-330
    x3), all of them documentation.
    """
    return not (
        is_generated_file(file_path)
        or is_test_file(file_path)
        or is_prose_file(file_path)
    )


class _FileCtx(NamedTuple):
    """Per-file analysis context, so line checks keep short signatures."""

    path: Path
    lines: tuple[str, ...]
    content: str


def _file_ctx(file_path: Path, lines: tuple[str, ...]) -> _FileCtx:
    """Bundle the path, lines and whole-file text for the line checks."""
    return _FileCtx(file_path, tuple(lines), read_file_safe(file_path) or "")


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for cryptography patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    ctx = _file_ctx(file_path, lines)
    for line_num, line in enumerate(lines, start=1):
        if _skip_line(line):
            continue
        _analyze_line(ctx, line, line_num, findings)


def _skip_line(line: str) -> bool:
    """Comment / import / scanner-definition lines are never findings."""
    return bool(
        COMMENT_INDICATORS.match(line)
        or IMPORT_LINE.match(line)
        or SCANNER_DEF_LINE.search(line)
    )


def _analyze_line(ctx: _FileCtx, line: str, line_num: int, findings: list[dict]) -> None:
    """Run every per-line cryptography check.

    Ordering is load-bearing at the end: skill findings are not deduplicated
    against each other (P5), so the IV/nonce specialisation runs BEFORE the
    CWE-321 hardcoded-key check and claims the line when it fires.
    """
    _check_broken_crypto(ctx.path, line, line_num, ctx.lines, findings)
    _check_weak_keys(ctx.path, line, line_num, ctx.lines, findings)
    _check_weak_random(ctx.path, line, line_num, ctx.lines, ctx.content, findings)
    _check_weak_hash(ctx.path, line, line_num, ctx.lines, findings)
    _check_rsa_without_oaep(ctx, line, line_num, findings)
    _check_anon_key_exchange(ctx, line, line_num, findings)
    claimed = _check_iv_and_nonce(ctx, line, line_num, findings)
    claimed |= _check_predictable_salt(ctx, line, line_num, findings)
    _check_hardcoded_key(ctx.path, line, line_num, ctx.lines, findings, claimed)


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
    if not _matches_any(BROKEN_CRYPTO_PATTERNS, line) and not _bare_cipher_name(line):
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


def _matches_any(patterns: list[re.Pattern[str]], line: str) -> bool:
    """True when any pattern in ``patterns`` matches ``line``."""
    return any(pattern.search(line) for pattern in patterns)


def _bare_cipher_name(line: str) -> bool:
    """Bare cipher-name path for CWE-327, with the JCE RSA carve-out.

    `ECB` inside a transformation whose algorithm is RSA is not a mode choice:
    RSA has no chaining mode, the JCE simply requires the field. The real
    weakness there is the padding, which the CWE-780 rule owns — so
    ``RSA/ECB/PKCS1Padding`` yields exactly one row and the correctly padded
    ``RSA/ECB/OAEPWith…`` yields none.
    """
    match = BROKEN_CRYPTO_BARE_NAME.search(line)
    if match is None or not BROKEN_CRYPTO_CONTEXT.search(line):
        return False
    return not _is_rsa_transformation_ecb(match.group(1), line)


def _is_rsa_transformation_ecb(name: str, line: str) -> bool:
    """True when the matched token is the `ECB` of a JCE `RSA/...` transformation."""
    return name.upper() == "ECB" and _RSA_TRANSFORMATION.search(line) is not None


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

    Handles both a one-line literal (whole PEM in a single string
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
        return _pem_key_detail(bits)
    if _written_weak_key_size(line) or _weak_generatekey_slot(line):
        return "Key size below recommended minimum at line {line_num}"
    return None


def _pem_key_detail(bits: int) -> str | None:
    """Description for a decoded PEM modulus, or None when it is strong enough."""
    if bits >= _MIN_RSA_BITS:
        return None
    return (
        f"Inline PEM key literal has a {bits}-bit RSA modulus "
        f"(minimum {_MIN_RSA_BITS}) at line {{line_num}}"
    )


def _written_weak_key_size(line: str) -> bool:
    """A weak key size written down textually on the line."""
    return _matches_any(WEAK_KEY_PATTERNS, line)


def _weak_generatekey_slot(line: str) -> bool:
    """Go `rsa.GenerateKey(...)` whose bit-size SLOT is a weak literal."""
    match = _GO_GENERATE_KEY.search(line)
    if match is None:
        return False
    args = split_call_args(line, match.end() - 1)
    return args is not None and arg_slot(args, 1) in _WEAK_RSA_BITS


_WEAK_RANDOM_ROWS = {
    "330": {
        "severity": "high",
        "check_id": "cwe.crypto.weak_random",
        "category": "CWE-330",
        "title": "Use of non-cryptographic randomness",
        "recommendation": "Use secrets module, crypto/rand, or SecureRandom",
        "verification_hints": ["Verify algorithm is used for security (not checksums)"],
        "requires_context": True,
    },
    "338": {
        "severity": "high",
        "check_id": "cwe.crypto.weak_prng_security_value",
        "category": "CWE-338",
        "title": "Cryptographically weak PRNG for a security value",
        "recommendation": (
            "Draw security values from a CSPRNG: secrets.token_urlsafe(), "
            "crypto.randomBytes(), crypto/rand, or SecureRandom"
        ),
        "verification_hints": ["Confirm the value is a credential, not a display value"],
    },
}


def _check_weak_random(
    file_path: Path, line: str, line_num: int, lines: list[str],
    content: str, findings: list[dict],
) -> None:
    """Check for CWE-330 insufficient randomness, or CWE-338 when the value
    consumed on the line is named as a security value."""
    if SAFE_RANDOM_CONTEXT.search(line):
        return
    if not _matches_any(WEAK_RANDOM_PATTERNS, line):
        return
    cwe = _weak_random_cwe(line, lines, content)
    finding = dict(_WEAK_RANDOM_ROWS[cwe])
    finding["description"] = _weak_random_description(cwe, line_num)
    finding["severity"] = _weak_random_severity(cwe, content)
    finding["file_path"] = str(file_path)
    finding["line_start"] = line_num
    finding["line_end"] = line_num
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, cwe))


def _weak_random_severity(cwe: str, content: str) -> str:
    """CWE-330 is demoted to medium when the file has no security context; a
    CWE-338 row has already proven its security context on the line."""
    if cwe == "330" and not check_context(content, _CRYPTO_CONTEXT):
        return "medium"
    return "high"


def _weak_random_description(cwe: str, line_num: int) -> str:
    """Description for the chosen id (never an f-string category)."""
    if cwe == "338":
        return (
            f"Security-sensitive value derived from a non-cryptographic PRNG "
            f"at line {line_num}"
        )
    return f"Weak random number generator at line {line_num}"


def _weak_random_cwe(line: str, lines: list[str], content: str) -> str:
    """CWE-338 when a line-local security token names the consumed value.

    The re-tag is conditional and exclusive: a line never carries both 330 and
    338, and it stays on 330 when ``weak_entropy_check`` already emits
    CWE-331 + CWE-332 for it — three synonymous labels on one line is not
    coverage (P5).
    """
    if not _SECURITY_VALUE_TOKEN.search(line):
        return "330"
    if _NON_SECURITY_CONSUMER.search(line):
        return "330"
    if _entropy_skill_owns_line(line, lines):
        return "330"
    return "338"


def _entropy_skill_owns_line(line: str, lines: list[str]) -> bool:
    """True when weak_entropy_check already emits CWE-331 + CWE-332 here.

    Reuses that skill's own predicate rather than restating it, so the two
    detectors cannot drift into double-reporting.
    """
    target = _entropy_flow_target(line)
    if target is None or not _entropy_is_sensitive(target):
        return False
    return not _entropy_safe_cooccurrence(tuple(lines))


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


def _window_matches(
    lines: list[str], line_num: int, radius: int, pattern: re.Pattern[str],
) -> bool:
    """True when ``pattern`` matches any line within ``radius`` of ``line_num``."""
    low = max(0, line_num - 1 - radius)
    high = min(len(lines), line_num + radius)
    return any(pattern.search(lines[index]) for index in range(low, high))


def _is_exec_or_config(path: Path) -> bool:
    """True for executable/config dialects — never documentation prose."""
    name = effective_name(path.name)
    return effective_suffix(name) in _EXEC_CONFIG_SUFFIXES or name in _EXEC_CONFIG_NAMES


def _is_anon_suite_line(line: str) -> bool:
    """An anonymous key-agreement suite ENABLED in a cipher list."""
    if not _ANON_KEX_SUITE.search(line):
        return False
    if _ANON_KEX_EXCLUDED.search(line):
        return False
    return _CIPHER_LIST_CONTEXT.search(line) is not None


def _is_unverified_host_key(line: str, lines: list[str], line_num: int) -> bool:
    """SSH host-key verification disabled, with no verifying callback nearby."""
    if not _SSH_NO_HOST_KEY.search(line):
        return False
    return not _window_matches(lines, line_num, 3, _SSH_VERIFIED)


def _anon_kex_reason(line: str, lines: list[str], line_num: int) -> str | None:
    """Why this line performs an unauthenticated key exchange, or None."""
    if _is_anon_suite_line(line):
        return _ANON_SUITE_REASON
    if _is_unverified_host_key(line, lines, line_num):
        return _SSH_HOST_KEY_REASON
    return None


def _check_anon_key_exchange(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict],
) -> None:
    """Check for CWE-322 key exchange without entity authentication."""
    if not _is_exec_or_config(ctx.path):
        return
    if _window_matches(ctx.lines, line_num, 1, _MATCHER_CONTEXT):
        return
    reason = _anon_kex_reason(line, ctx.lines, line_num)
    if reason is None:
        return
    finding = {
        "severity": "medium",
        "check_id": "cwe.crypto.unauthenticated_key_exchange",
        "category": "CWE-322",
        "title": "Key exchange without entity authentication",
        "description": f"{reason} at line {line_num}",
        "file_path": str(ctx.path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Authenticate the peer during key exchange: keep certificate-bearing "
            "cipher suites only (`!aNULL:!ADH`), and pin or verify SSH host keys"
        ),
        "code_snippet": extract_snippet(ctx.lines, line_num),
    }
    findings.append(enrich_finding(finding, "322"))


def _check_rsa_without_oaep(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict],
) -> None:
    """Check for CWE-780 RSA encryption without OAEP padding."""
    detail = _rsa_no_oaep_detail(line, ctx.content)
    if detail is None:
        return
    finding = {
        "severity": "medium",
        "check_id": "cwe.crypto.rsa_without_oaep",
        "category": "CWE-780",
        "title": "RSA encryption without OAEP padding",
        "description": f"{detail} at line {line_num}",
        "file_path": str(ctx.path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": (
            "Use RSA-OAEP (SHA-256) for encryption; PKCS#1 v1.5 encryption "
            "padding is vulnerable to Bleichenbacher-style oracle attacks"
        ),
        "code_snippet": extract_snippet(ctx.lines, line_num),
    }
    findings.append(enrich_finding(finding, "780"))


def _rsa_no_oaep_detail(line: str, content: str) -> str | None:
    """First matching CWE-780 arm's description, or None."""
    for arm in _RSA_NO_OAEP_ARMS:
        detail = arm(line, content)
        if detail is not None:
            return detail
    return None


def _gate_ok(spec: _IvSpec, line: str, content: str) -> bool:
    """Extra token a spec needs when its own arguments carry no mode."""
    haystack = line if spec.gate_scope == "line" else content
    return spec.gate is not None and spec.gate.search(haystack) is not None


def _classify_mode(text: str | None) -> str | None:
    """`cbc`, `aead`, or None for an algorithm/mode argument."""
    if text is None:
        return None
    if _CBC_MODE.search(text):
        return "cbc"
    return "aead" if _AEAD_MODE.search(text) else None


def _spec_mode(spec: _IvSpec, args: list[str], line: str, content: str) -> str | None:
    """Mode implied by the constructor's OWN mode argument (or its name)."""
    if spec.mode_slot is not None:
        return _classify_mode(arg_slot(args, spec.mode_slot))
    if spec.gate is not None and not _gate_ok(spec, line, content):
        return None
    return spec.mode


@lru_cache(maxsize=512)
def _zero_alloc_binding(name: str) -> re.Pattern[str]:
    """Regex binding ``name`` to a zero-filled allocation."""
    return re.compile(rf"\b{re.escape(name)}\s*(?::=|=)\s*(?:{_ZERO_ALLOC_SRC})")


def _csprng_fills(name: str, lines: list[str]) -> bool:
    """True when a CSPRNG anywhere in the file fills ``name``."""
    return any(_CSPRNG_FILL.search(text) and name in text for text in lines)


def _binds_zero_alloc(name: str, lines: list[str], line_num: int) -> bool:
    """True when ``name`` is bound to a zero-filled buffer just above."""
    binding = _zero_alloc_binding(name)
    low = max(0, line_num - 13)
    return any(binding.search(lines[index]) for index in range(low, line_num - 1))


def _traced_zero_alloc(slot: str, lines: list[str], line_num: int) -> str | None:
    """An identifier bound just above to a zero buffer and never randomised."""
    if _IDENT.match(slot) is None:
        return None
    if not _binds_zero_alloc(slot, lines, line_num):
        return None
    return None if _csprng_fills(slot, lines) else _REASON_ZERO_BOUND


def _is_key_reuse(slot: str, key: str | None) -> bool:
    """True when the IV/nonce slot is literally the key slot."""
    return key is not None and slot == key and _IDENT.match(slot) is not None


def _strip_conversion(slot: str) -> str:
    """A trailing charset/encoding conversion removed from ``slot``."""
    match = _CONVERSION_CALL.search(slot)
    if match is None:
        return slot
    end = call_span_end(slot, match.end() - 1)
    return slot[:match.start()] if end == len(slot) - 1 else slot


def _iv_defect(slot: str, key: str | None, lines: list[str], line_num: int) -> str | None:
    """Why the IV/nonce slot is predictable, or None."""
    if _LITERAL_VALUE.match(_strip_conversion(slot)):
        return _REASON_LITERAL
    if _ZERO_ALLOC.match(slot):
        return _REASON_ZERO
    if _is_key_reuse(slot, key):
        return _REASON_KEY_REUSE
    return _traced_zero_alloc(slot, lines, line_num)


def _call_slots(
    line: str, lines: list[str], line_num: int, paren: int,
) -> list[str] | None:
    """Argument slots of a call, retried over a 3-line window when wrapped.

    The window starts at ``line``, so the anchor offset stays valid.
    """
    args = split_call_args(line, paren)
    if args is not None:
        return args
    return split_call_args(" ".join(lines[line_num - 1:line_num + 2]), paren)


def _iv_verdict(
    spec: _IvSpec, args: list[str], ctx: _FileCtx, line: str, line_num: int,
) -> tuple[str, str] | None:
    """(mode, reason) when this spec's IV/nonce slot is predictable."""
    mode = _spec_mode(spec, args, line, ctx.content)
    slot = arg_slot(args, spec.iv)
    if mode is None or slot is None:
        return None
    reason = _iv_defect(slot, arg_slot(args, spec.key), ctx.lines, line_num)
    return None if reason is None else (mode, reason)


def _iv_spec_match(
    spec: _IvSpec, ctx: _FileCtx, line: str, line_num: int,
) -> tuple[str, str] | None:
    """Apply one constructor spec to ``line``."""
    match = spec.anchor.search(line)
    if match is None:
        return None
    args = _call_slots(line, ctx.lines, line_num, match.end() - 1)
    if args is None:
        return None
    return _iv_verdict(spec, args, ctx, line, line_num)


def _check_iv_and_nonce(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict],
) -> bool:
    """Check for CWE-329 (CBC IV) / CWE-323 (AEAD nonce reuse).

    Returns True when a row was emitted, so the caller can suppress the
    CWE-321 iv/nonce arm on the same line: this is the precise child of that
    check and skill findings are not deduplicated against each other (P5).
    """
    for spec in _IV_SPECS:
        verdict = _iv_spec_match(spec, ctx, line, line_num)
        if verdict is None:
            continue
        mode, reason = verdict
        finding = dict(_IV_ROWS[mode])
        finding["description"] = (
            f"The IV/nonce argument at line {line_num} is {reason}"
        )
        finding["file_path"] = str(ctx.path)
        finding["line_start"] = line_num
        finding["line_end"] = line_num
        finding["code_snippet"] = extract_snippet(ctx.lines, line_num)
        findings.append(enrich_finding(finding, _IV_CWE[mode]))
        return True
    return False


def _key_row_suppressed(line: str, claimed: bool) -> bool:
    """CWE-321 suppressions: a claimed line, a safe context, or an indirection."""
    return bool(
        claimed
        or SAFE_KEY_CONTEXT.search(line)
        or line_value_is_variable_ref(line)
    )


def _check_hardcoded_key(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict], claimed: bool = False,
) -> None:
    """Check for hardcoded cryptographic keys (CWE-321).

    CWE-321 ("Use of Hard-coded Cryptographic Key") is the precise CWE
    for keys embedded in source. Earlier code labelled this CWE-327
    ("Use of Broken/Risky Algorithm"), which mis-routes catalog
    enrichment and confuses downstream triage.

    Suppress when the captured RHS is a variable reference (`$VAR`,
    `${VAR}`, `{{ var }}`) — the literal value is a pointer, not a key.

    ``claimed`` is set when the CWE-329/323 specialisation already reported
    this line's IV/nonce; the precise child owns the row (P5).
    """
    if _key_row_suppressed(line, claimed):
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
