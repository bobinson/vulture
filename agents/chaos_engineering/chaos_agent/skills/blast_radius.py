"""Blast radius assessment skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

ISOLATION_PATTERNS = [
    re.compile(r"bulkhead|Bulkhead|thread.?pool|semaphore", re.IGNORECASE),
    re.compile(r"rate.?limit|RateLimit|throttle", re.IGNORECASE),
    re.compile(r"namespace|isolation|partition", re.IGNORECASE),
]

SHARED_STATE_PATTERNS = [
    re.compile(r"global\s|shared.?state|singleton", re.IGNORECASE),
    re.compile(r"\.Lock\(|sync\.Mutex|threading\.Lock"),
    re.compile(r"shared.?database|common.?cache|global.?config", re.IGNORECASE),
]


def assess_blast_radius(source_path: str) -> dict:
    """Assess potential blast radius of failures in the codebase.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of blast radius issues.
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
    """Check a file for blast radius issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    has_shared_state = any(p.search(content) for p in SHARED_STATE_PATTERNS)
    has_isolation = any(p.search(content) for p in ISOLATION_PATTERNS)

    if has_shared_state and not has_isolation:
        findings.append({
            "severity": "medium",
            "category": "blast-radius",
            "title": "Shared state without isolation",
            "description": f"File {file_path.name} uses shared state without isolation mechanisms",
            "file_path": str(file_path),
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Apply bulkhead pattern to isolate failure domains",
        })


assess_blast_radius_tool = function_tool(assess_blast_radius)
