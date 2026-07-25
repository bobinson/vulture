"""Fallback pattern analysis skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

FALLBACK_PATTERNS = [
    re.compile(r"fallback|Fallback|default.?value|graceful.?degrad", re.IGNORECASE),
    re.compile(r"cache\.get|cached_response|stale.?cache", re.IGNORECASE),
    re.compile(r"except.*:[\s\S]*?return|catch.*\{[\s\S]*?return"),
]

ERROR_PRONE_PATTERNS = [
    re.compile(r"requests\.(get|post)\("),
    re.compile(r"http\.(Get|Post)\("),
    re.compile(r"\.query\(|\.execute\(|\.find\("),
]


def check_fallback_patterns(source_path: str) -> dict:
    """Analyze source code for fallback pattern implementation.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of fallback issues.
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
    """Check a file for missing fallback patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_fallback = any(p.search(content) for p in FALLBACK_PATTERNS)
    if has_fallback:
        return

    line_num = 0
    for ln, line in enumerate(content.splitlines(), start=1):
        for pat in ERROR_PRONE_PATTERNS:
            if pat.search(line):
                line_num = ln
                break
        if line_num:
            break
    if line_num == 0:
        return

    findings.append({
        "severity": "medium",
        "check_id": "chaos.fallback.missing",
        "category": "fallback-pattern",
        "title": "Missing fallback mechanism",
        "description": f"File {file_path.name} lacks fallback for failure scenarios",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Implement fallback responses or cached defaults",
    })


check_fallback_patterns_tool = function_tool(check_fallback_patterns)
