"""CWE cryptography vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-327: Broken or risky cryptographic algorithm
BROKEN_CRYPTO_PATTERNS = [
    re.compile(r"\bDES\b(?!C)"),
    re.compile(r"\bRC4\b"),
    re.compile(r"\bBlowfish\b", re.IGNORECASE),
    re.compile(r"\b3DES\b"),
    re.compile(r"\bTripleDES\b", re.IGNORECASE),
    re.compile(r"ECB\b"),
    re.compile(r"DES\.new\("),
    re.compile(r"ARC4\.new\("),
    re.compile(r"Blowfish\.new\("),
    re.compile(r'mode\s*=\s*["\']?ECB'),
    re.compile(r"MODE_ECB"),
]

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

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
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
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for cryptography patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_broken_crypto(file_path, line, line_num, findings, is_test=is_test)
        _check_weak_keys(file_path, line, line_num, findings, is_test=is_test)
        _check_weak_random(file_path, line, line_num, findings, is_test=is_test)
        _check_weak_hash(file_path, line, line_num, findings, is_test=is_test)
        _check_hardcoded_key(file_path, line, line_num, findings, is_test=is_test)


def _check_broken_crypto(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-327 broken cryptographic algorithm."""
    if SAFE_CRYPTO_CONTEXT.search(line):
        return
    for pattern in BROKEN_CRYPTO_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-327",
                "title": "Broken cryptographic algorithm",
                "description": f"Use of weak cipher or mode at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use AES-256-GCM, ChaCha20-Poly1305, or other modern algorithms",
            })
            return


def _check_weak_keys(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-326 inadequate encryption strength."""
    for pattern in WEAK_KEY_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-326",
                "title": "Inadequate encryption key strength",
                "description": f"Key size below recommended minimum at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use RSA >= 2048 bits, or switch to ECC (P-256+)",
            })
            return


def _check_weak_random(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-330 insufficient randomness."""
    if SAFE_RANDOM_CONTEXT.search(line):
        return
    for pattern in WEAK_RANDOM_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-330",
                "title": "Use of non-cryptographic randomness",
                "description": f"Weak random number generator at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use secrets module, crypto/rand, or SecureRandom",
            })
            return


def _check_weak_hash(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-328 reversible one-way hash."""
    if SAFE_HASH_CONTEXT.search(line):
        return
    for pattern in WEAK_HASH_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "medium",
                "category": "CWE-328",
                "title": "Weak hash algorithm for integrity",
                "description": f"MD5 or SHA1 used for hashing at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use SHA-256 or SHA-3 for integrity checks",
            })
            return


def _check_hardcoded_key(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for hardcoded encryption keys."""
    if SAFE_KEY_CONTEXT.search(line):
        return
    for pattern in HARDCODED_KEY_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-327",
                "title": "Hardcoded encryption key",
                "description": f"Encryption key embedded in source code at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Load encryption keys from environment variables or key management service",
            })
            return


check_cryptography_tool = function_tool(check_cryptography)
