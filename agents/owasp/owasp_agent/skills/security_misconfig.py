"""Security misconfiguration detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

DEBUG_PATTERNS = [
    re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"debug\s*:\s*true", re.IGNORECASE),
    re.compile(r"NODE_ENV\s*(?:={1,3}|:)\s*['\"]?development"),
]

CORS_PATTERNS = [
    re.compile(r'allow_origins\s*=\s*\[\s*"\*"\s*\]'),
    re.compile(r"Access-Control-Allow-Origin.*\*"),
    re.compile(r'cors\(.*origin.*\*', re.IGNORECASE),
]

EXPOSED_PATTERNS = [
    re.compile(r'DATABASE_URL\s*=\s*["\'].*://.*:.*@'),
    re.compile(r'SECRET_KEY\s*=\s*["\']'),
]

# Skip lines that are regex/pattern definitions (avoid self-detection)
SKIP_LINE_PATTERNS = re.compile(r"re\.compile|PATTERN|regex|pattern.*=.*compile", re.IGNORECASE)
# Template syntax (Vault, Jinja, shell interpolation) — not literal values
TEMPLATE_VALUE = re.compile(r"\{\{.*\}\}|\$\{[^}]+\}|[\"']\$[A-Za-z_]")


def check_security_misconfig(source_path: str) -> dict:
    """Check for security misconfiguration.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of misconfiguration issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for security misconfiguration."""
    content = read_file_safe(file_path)
    if content is None:
        return

    for line_num, line in enumerate(content.splitlines(), start=1):
        if SKIP_LINE_PATTERNS.search(line):
            continue
        _check_debug_mode(file_path, line, line_num, findings, is_test=is_test)
        _check_exposed_config(file_path, line, line_num, findings, is_test=is_test)
        _check_cors(file_path, line, line_num, findings, is_test=is_test)


def _check_debug_mode(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for debug mode enabled."""
    if is_test:
        return
    for pattern in DEBUG_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium",
                "category": "A05-security-misconfig",
                "title": "Debug mode enabled",
                "description": f"Debug mode at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Disable debug mode in production",
            })
            return


def _check_exposed_config(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for exposed configuration."""
    if is_test:
        return
    for pattern in EXPOSED_PATTERNS:
        if pattern.search(line) and not TEMPLATE_VALUE.search(line):
            findings.append({
                "severity": "high",
                "category": "A05-security-misconfig",
                "title": "Sensitive configuration exposed",
                "description": f"Exposed config at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables for sensitive configuration",
            })
            return


def _check_cors(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for insecure CORS configuration."""
    if is_test:
        return
    for pattern in CORS_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "high",
                "category": "A05-security-misconfig",
                "title": "Insecure CORS configuration",
                "description": f"Insecure CORS wildcard origin at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Restrict CORS to specific trusted origins",
            })
            return


check_security_misconfig_tool = function_tool(check_security_misconfig)
