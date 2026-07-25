"""Retry pattern analysis skill."""

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

RETRY_PATTERNS = [
    re.compile(r"retry|retries|backoff|exponential.?back", re.IGNORECASE),
    re.compile(r"@retry|Retry\(|tenacity|urllib3\.util\.retry", re.IGNORECASE),
    re.compile(r"MaxRetries|retry_count|max_retries", re.IGNORECASE),
    # TypeScript/Node.js retry wrappers and npm packages
    re.compile(r"withRetry|retryOrThrow|createApiRetryConfig|createDbRetryConfig", re.IGNORECASE),
    re.compile(r"from\s+['\"](?:p-retry|async-retry|cockatiel|ts-retry)", re.IGNORECASE),
]

HTTP_CALL_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete|patch)\("),
    re.compile(r"http\.(Get|Post|Do)\("),
    re.compile(r"fetch\(|axios\.|HttpClient"),
    re.compile(r"aiohttp\.ClientSession"),
]

# OAuth token exchange endpoints — codes are single-use, retry is incorrect.
_OAUTH_SKIP = re.compile(
    r"grant_type.*authorization_code|client_secret.*code|token.*exchange"
    r"|googleapis\.com/token|graph\.facebook\.com.*access_token"
    r"|/oauth/token|/token\b.*POST",
    re.IGNORECASE,
)

# Cap total retry findings per scan to avoid overwhelming reports.
_MAX_FINDINGS = 10


def check_retry_patterns(source_path: str) -> dict:
    """Analyze source code for retry pattern implementation.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of retry-related issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if len(findings) >= _MAX_FINDINGS:
            break
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

    if not has_http_calls or has_retry:
        return
    # Skip OAuth token exchange files — codes are single-use.
    if _OAUTH_SKIP.search(content):
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SAFE_IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        for pattern in HTTP_CALL_PATTERNS:
            if pattern.search(line):
                finding = {
                    "severity": "high",
                    "check_id": "chaos.retry.missing",
                    "category": "retry-pattern",
                    "title": "Missing retry logic for HTTP call",
                    "description": f"HTTP call at line {line_num} has no retry mechanism",
                    "file_path": str(file_path),
                    "line_start": line_num,
                    "line_end": line_num,
                    "recommendation": "Implement retry with exponential backoff",
                }
                finding["code_snippet"] = extract_snippet(lines, line_num)
                findings.append(finding)
                break  # One finding per line, continue to next line


check_retry_patterns_tool = function_tool(check_retry_patterns)
