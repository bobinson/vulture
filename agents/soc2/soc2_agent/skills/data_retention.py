"""Data retention audit skill for SOC2."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

RETENTION_PATTERNS = [
    re.compile(r"retention|expire|ttl|time.?to.?live|max.?age", re.IGNORECASE),
    re.compile(r"purge|cleanup|archive|rotate", re.IGNORECASE),
    re.compile(r"GDPR|data.?deletion|right.?to.?be.?forgotten", re.IGNORECASE),
]

DATA_PATTERNS = [
    re.compile(r"INSERT INTO|\.save\(|\.create\(|\.put\("),
    re.compile(r"user.?data|personal.?info|PII|sensitive", re.IGNORECASE),
    re.compile(r"\.write\(|store|persist", re.IGNORECASE),
]


def check_data_retention(source_path: str) -> dict:
    """Check for data retention and lifecycle management.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of data retention issues.
    """
    findings: list[dict] = []

    has_data_ops = False
    has_retention = False

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        content = read_file_safe(file_path)
        if content is None:
            continue
        if any(p.search(content) for p in DATA_PATTERNS):
            has_data_ops = True
        if any(p.search(content) for p in RETENTION_PATTERNS):
            has_retention = True

    if has_data_ops and not has_retention:
        finding = {
            "severity": "medium",
            "check_id": "soc2.data_retention.missing_policy",
            "category": "CC6-data-retention",
            "title": "No data retention policy detected",
            "description": "Data storage found but no retention/expiry/cleanup logic",
            "file_path": source_path,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Implement data retention policies with TTL and cleanup jobs",
        }
        finding["code_snippet"] = extract_snippet([], 0)
        findings.append(finding)

    return {"findings": findings}


check_data_retention_tool = function_tool(check_data_retention)
