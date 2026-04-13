"""Cryptographic failure detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.snippet import extract_snippet

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
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

SAFE_IMPORT_LINE = re.compile(r'^\s*(?:import\b|from\b.*import\b|require\b|\t*"[^"]*"$)')
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
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for cryptographic issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SAFE_IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_weak_crypto(file_path, line, line_num, findings, lines)
        _check_hardcoded_secrets(file_path, line, line_num, findings, lines)


def _check_weak_crypto(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check for weak cryptographic algorithms."""
    for pattern in WEAK_CRYPTO_PATTERNS:
        if pattern.search(line):
            if "random" in line.lower() and SAFE_RANDOM_CONTEXT.search(line):
                continue
            finding = {
                "severity": "high",
                "check_id": "owasp.crypto.weak_algorithm",
                "category": "A02-crypto-failure",
                "title": "Weak cryptographic algorithm",
                "description": f"Weak crypto at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use AES-256-GCM or ChaCha20-Poly1305",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(finding)
            return


def _check_hardcoded_secrets(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check for hardcoded secrets."""
    for pattern in HARDCODED_SECRET_PATTERNS:
        if pattern.search(line):
            if DYNAMIC_SECRET_VALUE.search(line) or COMMAND_SUBSTITUTION.search(line):
                return
            finding = {
                "severity": "critical",
                "check_id": "owasp.crypto.hardcoded_secret",
                "category": "A02-crypto-failure",
                "title": "Hardcoded secret detected",
                "description": f"Hardcoded secret at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables or a secrets manager",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(finding)
            return


check_cryptography_tool = function_tool(check_cryptography)
