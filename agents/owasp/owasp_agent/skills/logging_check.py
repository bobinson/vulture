"""Logging failure / sensitive data in logs detection skill (A09)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

SENSITIVE_LOG_PATTERNS = [
    re.compile(
        r"(?:log(?:ger)?\.(?:info|debug|warning|error|critical)|print)\s*\(\s*f[\"']"
        r".*(?:password|secret|token|api.?key|credential)",
        re.IGNORECASE,
    ),
]

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")


def check_logging(source_path: str) -> dict:
    """Check for sensitive data exposure in log statements.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of logging issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for sensitive data in log statements."""
    content = read_file_safe(file_path)
    if content is None:
        return

    for line_num, line in enumerate(content.splitlines(), start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if any(p.search(line) for p in SENSITIVE_LOG_PATTERNS):
            findings.append({
                "severity": "medium" if is_test else "high",
                "category": "A09-logging-failure",
                "title": "Sensitive data in log output",
                "description": f"Sensitive data logged at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Never log sensitive data; mask or redact secrets",
            })


check_logging_tool = function_tool(check_logging)
