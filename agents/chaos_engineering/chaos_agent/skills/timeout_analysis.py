"""Timeout handling analysis skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

TIMEOUT_PATTERNS = [
    re.compile(r"timeout|Timeout|time\.After|context\.WithTimeout", re.IGNORECASE),
    re.compile(r"connect_timeout|read_timeout|request_timeout"),
    re.compile(r"\.setTimeout\(|AbortController|signal"),
    # TypeScript/Node.js timeout patterns
    re.compile(r"timeoutMs|attemptTimeout|requestTimeout|withTimeout", re.IGNORECASE),
    re.compile(r"timeout:\s*\d+", re.IGNORECASE),
]

NETWORK_PATTERNS = [
    re.compile(r"requests\.(get|post|put|delete)\("),
    re.compile(r"http\.(Get|Post|Do|NewRequest)\("),
    re.compile(r"net\.Dial|sql\.Open"),
    re.compile(r"fetch\(|axios\.|aiohttp"),
]


# Cap total timeout findings per scan to avoid overwhelming reports.
_MAX_FINDINGS = 10


def check_timeout_handling(source_path: str) -> dict:
    """Analyze source code for proper timeout handling.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of timeout issues.
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
    """Check a file for missing timeout handling.

    Reports the line of the FIRST detected network call rather than
    pinning every finding to line 1 (the file's import statement). The
    underlying signal is file-scoped (no timeout anywhere AND a
    network call exists), but pointing at the actual call site makes
    triage faster.
    """
    content = read_file_safe(file_path)
    if content is None:
        return

    has_timeout = any(p.search(content) for p in TIMEOUT_PATTERNS)
    if has_timeout:
        return

    network_line = _first_network_line(content)
    if network_line == 0:
        return

    findings.append({
        "severity": "high",
        "check_id": "chaos.timeout.missing",
        "category": "timeout-handling",
        "title": "Missing timeout for network operation",
        "description": f"File {file_path.name} performs network operations without timeouts",
        "file_path": str(file_path),
        "line_start": network_line,
        "line_end": network_line,
        "recommendation": "Add explicit timeouts to all network operations",
    })


def _first_network_line(content: str) -> int:
    """Return the 1-indexed line number of the first network-call match.
    Returns 0 when no network call is found."""
    for ln, line in enumerate(content.splitlines(), start=1):
        for pat in NETWORK_PATTERNS:
            if pat.search(line):
                return ln
    return 0


check_timeout_handling_tool = function_tool(check_timeout_handling)
