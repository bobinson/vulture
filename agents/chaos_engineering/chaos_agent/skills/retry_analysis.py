"""Retry pattern analysis skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

RETRY_PATTERNS = [
    re.compile(r"retry|retries|backoff|exponential.?back", re.IGNORECASE),
    re.compile(r"@retry|Retry\(|tenacity|urllib3\.util\.retry", re.IGNORECASE),
    re.compile(r"MaxRetries|retry_count|max_retries", re.IGNORECASE),
]

HTTP_CALL_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete|patch)\("),
    re.compile(r"http\.(Get|Post|Do)\("),
    re.compile(r"fetch\(|axios\.|HttpClient"),
    re.compile(r"aiohttp\.ClientSession"),
]


def check_retry_patterns(source_path: str) -> dict:
    """Analyze source code for retry pattern implementation.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of retry-related issues.
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
    """Analyze a single file for retry patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_http_calls = any(p.search(content) for p in HTTP_CALL_PATTERNS)
    has_retry = any(p.search(content) for p in RETRY_PATTERNS)

    if has_http_calls and not has_retry:
        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern in HTTP_CALL_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "severity": "high",
                        "category": "retry-pattern",
                        "title": "Missing retry logic for HTTP call",
                        "description": f"HTTP call at line {line_num} has no retry mechanism",
                        "file_path": str(file_path),
                        "line_start": line_num,
                        "line_end": line_num,
                        "recommendation": "Implement retry with exponential backoff",
                    })
                    break


check_retry_patterns_tool = function_tool(check_retry_patterns)
