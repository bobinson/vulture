"""Logging failure / sensitive data in logs detection skill (A09)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.snippet import extract_snippet

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
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
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for sensitive data in log statements."""
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
        if any(p.search(line) for p in SENSITIVE_LOG_PATTERNS):
            finding = {
                "severity": "high",
                "check_id": "owasp.logging.sensitive_data",
                "category": "A09-logging-failure",
                "title": "Sensitive data in log output",
                "description": f"Sensitive data logged at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Never log sensitive data; mask or redact secrets",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(finding)


check_logging_tool = function_tool(check_logging)
