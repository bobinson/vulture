"""Change management audit skill for SOC2."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

UNSAFE_DEPLOY_PATTERNS = [
    re.compile(r"git pull.*main|git pull.*master"),
    re.compile(r"rsync|scp.*deploy|ftp.*upload", re.IGNORECASE),
    re.compile(r"ssh.*deploy|manual.?deploy", re.IGNORECASE),
]


def check_change_management(source_path: str) -> dict:
    """Check for proper change management and deployment practices.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of change management issues.
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
    """Analyze a file for change management issues."""
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
        for pattern in UNSAFE_DEPLOY_PATTERNS:
            if pattern.search(line):
                finding = {
                    "severity": "medium",
                    "check_id": "soc2.change_mgmt.unsafe_deploy",
                    "category": "CC8-change-management",
                    "title": "Unsafe deployment practice detected",
                    "description": f"Manual/unsafe deployment at line {line_num}",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Use CI/CD pipelines with approval gates",
                }
                finding["code_snippet"] = extract_snippet(lines, line_num)
                findings.append(finding)
                break


check_change_management_tool = function_tool(check_change_management)
