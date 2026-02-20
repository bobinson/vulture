"""Access logging audit skill for SOC2."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

LOGGING_PATTERNS = [
    re.compile(r"logging\.(info|warning|error|debug)\("),
    re.compile(r"logger\.(info|warning|error|debug)\("),
    re.compile(r"log\.(Info|Warn|Error|Debug|Printf)\("),
    re.compile(r"console\.(log|warn|error)\("),
    re.compile(r"audit.?log|AuditLog|audit_trail", re.IGNORECASE),
]

AUTH_ACTION_PATTERNS = [
    re.compile(r"def\s+(login|logout|authenticate|authorize)", re.IGNORECASE),
    re.compile(r"func\s+\w*(Login|Logout|Auth)\w*\("),
    re.compile(r"def\s+(create|update|delete)_"),
]


def check_access_logging(source_path: str) -> dict:
    """Check for proper access and audit logging.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of logging issues.
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
    """Analyze a file for access logging."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_auth_actions = any(p.search(content) for p in AUTH_ACTION_PATTERNS)
    has_logging = any(p.search(content) for p in LOGGING_PATTERNS)

    if has_auth_actions and not has_logging:
        findings.append({
            "severity": "high",
            "category": "CC6-access-logging",
            "title": "Missing audit logging for sensitive operations",
            "description": f"File {file_path.name} has auth actions without audit logging",
            "file_path": str(file_path),
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Add structured audit logging for all auth and data operations",
        })


check_access_logging_tool = function_tool(check_access_logging)
