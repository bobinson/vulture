"""Access control vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

IDOR_PATTERNS = [
    re.compile(r'request\.(args|params|query)\[?["\']id["\']'),
    re.compile(r'request\.form\[?["\']user_id["\']'),
    re.compile(r'r\.URL\.Query\(\)\.Get\(\s*"[a-z_]*id"'),
]

AUTHZ_CHECK_PATTERNS = [
    re.compile(r"@requires_permission|@authorize|@has_role", re.IGNORECASE),
    re.compile(r"check_permission|is_authorized|has_access", re.IGNORECASE),
    re.compile(r"extractUser|RequireAuth|authMW|currentUser", re.IGNORECASE),
]


def check_access_control(source_path: str) -> dict:
    """Check for broken access control vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of access control issues.
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
    """Analyze a file for access control issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_authz = any(p.search(content) for p in AUTHZ_CHECK_PATTERNS)

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern in IDOR_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "severity": "medium" if has_authz else "high",
                    "check_id": "owasp.access_control.idor",
                    "category": "A01-access-control",
                    "title": "Potential IDOR vulnerability",
                    "description": f"User-supplied ID used directly at line {line_num}",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Verify resource ownership before access",
                })
                break


check_access_control_tool = function_tool(check_access_control)
