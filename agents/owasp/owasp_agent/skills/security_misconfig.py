"""Security misconfiguration detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.snippet import extract_snippet

from shared.tools.file_scanner import (
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_skill_source_file,
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

# Combined patterns use | alternation so a single regex search replaces
# iterating N individual patterns per line (reduces regex calls from
# N*lines to 1*lines per category).
COMBINED_DEBUG_RE = re.compile(
    r"DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV\s*(?:={1,3}|:)\s*['\"]?development",
    re.IGNORECASE,
)
COMBINED_CORS_RE = re.compile(
    r'allow_origins\s*=\s*\[\s*"\*"\s*\]'
    r'|(?i:Access-Control-Allow-Origin.*\*)'
    r'|(?i:cors\(.*origin.*\*)',
)
COMBINED_EXPOSED_RE = re.compile(
    r'DATABASE_URL\s*=\s*["\'].*://.*:.*@|SECRET_KEY\s*=\s*["\']',
)

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
        if is_test_file(file_path):
            continue
        # Skip Vulture's own detector source — CORS regex literals
        # like `allow_origins=["*"]` appear in skill source as the
        # PATTERN that's being detected, not as a real misconfiguration.
        if is_skill_source_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for security misconfiguration."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if SAFE_IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_debug_mode(file_path, line, line_num, findings, lines)
        _check_exposed_config(file_path, line, line_num, findings, lines)
        _check_cors(file_path, line, line_num, findings, lines)


_GUARDED_DEBUG_RE = re.compile(
    r"""
    debug\s*:\s*                                # debug:
    (?:                                         # then either…
        process\.env\.NODE_ENV\s*[!=]==?\s*["'](?:development|dev)["']
      | NODE_ENV\s*[!=]==?\s*["'](?:development|dev)["']
      | __DEV__
      | process\.env\.NODE_ENV\s*[!=]==?\s*["']production["']  # !==production
      | !\s*isProduction
      | isDev(?:elopment)?\b
      | env\s*===?\s*["']development["']
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _check_debug_mode(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check for debug mode enabled.

    Skips lines where the debug toggle is already gated by an
    environment check (`debug: process.env.NODE_ENV === "development"`,
    `debug: !isProduction`, etc.). Those are the CORRECT pattern —
    they make debug active only in dev builds.
    """
    if not COMBINED_DEBUG_RE.search(line):
        return
    if _GUARDED_DEBUG_RE.search(line):
        return
    finding = {
        "severity": "medium",
        "check_id": "owasp.misconfig.debug_enabled",
        "category": "A05-security-misconfig",
        "title": "Debug mode enabled",
        "description": f"Debug mode at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Disable debug mode in production",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(finding)


def _check_exposed_config(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check for exposed configuration."""
    if COMBINED_EXPOSED_RE.search(line) and not TEMPLATE_VALUE.search(line):
        finding = {
            "severity": "high",
            "check_id": "owasp.misconfig.exposed_config",
            "category": "A05-security-misconfig",
            "title": "Sensitive configuration exposed",
            "description": f"Exposed config at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use environment variables for sensitive configuration",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(finding)


def _check_cors(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check for insecure CORS configuration."""
    if COMBINED_CORS_RE.search(line):
        finding = {
            "severity": "high",
            "check_id": "owasp.misconfig.cors_wildcard",
            "category": "A05-security-misconfig",
            "title": "Insecure CORS configuration",
            "description": f"Insecure CORS wildcard origin at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Restrict CORS to specific trusted origins",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(finding)


check_security_misconfig_tool = function_tool(check_security_misconfig)
