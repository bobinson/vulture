"""Cryptographic failure detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

WEAK_CRYPTO_PATTERNS = [
    re.compile(r"\bDES\b"),  # case-sensitive: avoids French article "des"
    re.compile(r"\bRC4\b|\bBlowfish\b", re.IGNORECASE),
    re.compile(r"(?<![0-9a-fA-F])ECB(?![0-9a-fA-F])", re.IGNORECASE),  # exclude hex
    re.compile(r"\bmd5\b|\bsha1\b(?!_)", re.IGNORECASE),
    re.compile(r'random\(\)|Math\.random\(\)|rand\(\)'),
]

# Lines that are regex definitions or string patterns (not actual crypto usage)
SKIP_LINE_PATTERNS = re.compile(r"re\.compile|PATTERN|regex|pattern.*=.*compile", re.IGNORECASE)
COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
# Import/require lines (e.g. Go `"crypto/md5"`, Python `import hashlib`)
IMPORT_LINE = re.compile(r'^\s*(?:import\b|from\b.*import\b|require\b|\t*"[^"]*"$)')
# Values containing variable references or templates, not literal secrets
DYNAMIC_SECRET_VALUE = re.compile(r'''=\s*["'][^"']*(?:\$[\w{]|\{\{)''')
# Command substitution — values sourced dynamically, not hardcoded
COMMAND_SUBSTITUTION = re.compile(r"\$\(")
# Math.random()/rand() used for timing, not crypto
SAFE_RANDOM_CONTEXT = re.compile(r"jitter|delay|backoff|timeout|retry|sleep|wait", re.IGNORECASE)

HARDCODED_SECRET_PATTERNS = [
    re.compile(r'(?:secret|api)_?key\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    re.compile(r'password\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
    re.compile(r'token\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
]


def check_cryptography(source_path: str) -> dict:
    """Check for cryptographic failures and hardcoded secrets.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of cryptographic issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for cryptographic issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    test_region = _rust_test_region(content) if file_path.suffix == ".rs" else None

    for line_num, line in enumerate(content.splitlines(), start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SKIP_LINE_PATTERNS.search(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        line_test = is_test or (test_region is not None and line_num >= test_region)
        _check_weak_crypto(file_path, line, line_num, findings, is_test=line_test)
        _check_hardcoded_secrets(file_path, line, line_num, findings, is_test=line_test)


def _check_weak_crypto(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for weak cryptographic algorithms."""
    for pattern in WEAK_CRYPTO_PATTERNS:
        if pattern.search(line):
            if "random" in line.lower() and (is_test or SAFE_RANDOM_CONTEXT.search(line)):
                continue
            findings.append({
                "severity": "medium" if is_test else "high",
                "category": "A02-crypto-failure",
                "title": "Weak cryptographic algorithm",
                "description": f"Weak crypto at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use AES-256-GCM or ChaCha20-Poly1305",
            })
            return


def _check_hardcoded_secrets(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for hardcoded secrets."""
    for pattern in HARDCODED_SECRET_PATTERNS:
        if pattern.search(line):
            if DYNAMIC_SECRET_VALUE.search(line) or COMMAND_SUBSTITUTION.search(line):
                return
            findings.append({
                "severity": "low" if is_test else "critical",
                "category": "A02-crypto-failure",
                "title": "Hardcoded secret detected",
                "description": f"Hardcoded secret at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables or a secrets manager",
            })
            return


def _rust_test_region(content: str) -> int | None:
    """Find the line where Rust #[cfg(test)] region starts."""
    for i, line in enumerate(content.splitlines(), start=1):
        if "#[cfg(test)]" in line:
            return i
    return None


check_cryptography_tool = function_tool(check_cryptography)
