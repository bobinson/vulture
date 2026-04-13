"""Insecure design detection skill (A04)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

AUTH_ENDPOINT_PATTERNS = [
    re.compile(
        r"def\s+(login|signin|signup|register|reset_password|forgot_password)\b",
        re.IGNORECASE,
    ),
]

RATE_LIMIT_PATTERNS = [
    re.compile(r"@rate_limit|@throttle|@ratelimit|RateLimiter|rate_limit", re.IGNORECASE),
]

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")


def check_insecure_design(source_path: str) -> dict:
    """Check for insecure design patterns (auth without rate limiting).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of insecure design issues.
    """
    files = scan_code_files(source_path)

    if _project_has_rate_limiting(files):
        return {"findings": []}

    findings: list[dict] = []
    for file_path in files:
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _project_has_rate_limiting(files: list[Path]) -> bool:
    """Check if any file in the project contains rate limiting."""
    for file_path in files:
        content = read_file_safe(file_path)
        if content is None:
            continue
        if any(p.search(content) for p in RATE_LIMIT_PATTERNS):
            return True
    return False


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for auth endpoints without rate limiting."""
    content = read_file_safe(file_path)
    if content is None:
        return

    for line_num, line in enumerate(content.splitlines(), start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if any(p.search(line) for p in AUTH_ENDPOINT_PATTERNS):
            findings.append({
                "severity": "medium",
                "check_id": "owasp.insecure_design.missing_rate_limit",
                "category": "A04-insecure-design",
                "title": "Auth endpoint without rate limiting",
                "description": f"Auth endpoint at line {line_num} has no rate limiting",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Add rate limiting to authentication endpoints",
            })


check_insecure_design_tool = function_tool(check_insecure_design)
