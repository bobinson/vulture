"""DO-178C non-deterministic timing and unbounded I/O detection."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# Non-deterministic timing calls.
_NONDETERMINISTIC_TIMING = re.compile(
    r"(?<!\w)(?:"
    r"time\.sleep|time\.Now|time\.time|datetime\.now|Date\.now|"
    r"Thread\.sleep|setTimeout|setInterval|usleep|nanosleep"
    r")\s*\("
)

# Unbounded network I/O.
_UNBOUNDED_IO = re.compile(
    r"(?<!\w)(?:"
    r"requests\.(?:get|post)|urllib\.request\.urlopen|"
    r"http\.(?:Get|Post)|fetch|socket\.connect"
    r")\s*\("
)


def check_timing(source_path: str) -> dict:
    """Check for non-deterministic timing and unbounded I/O.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a single file for timing and I/O patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    line_list = list(lines)
    for line_num, line in enumerate(line_list, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        _check_timing(file_path, line, line_num, line_list, findings)
        _check_io(file_path, line, line_num, line_list, findings)


def _check_timing(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Flag non-deterministic timing calls."""
    if not _NONDETERMINISTIC_TIMING.search(line):
        return
    findings.append({
        "severity": "high",
        "check_id": "do178c.timing.nondeterministic",
        "category": "timing",
        "title": "Non-deterministic timing call",
        "description": f"Non-deterministic timing at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use deterministic timing with bounded WCET analysis",
        "code_snippet": extract_snippet(lines, line_num),
    })


def _check_io(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Flag unbounded network I/O calls."""
    if not _UNBOUNDED_IO.search(line):
        return
    findings.append({
        "severity": "high",
        "check_id": "do178c.timing.unbounded_io",
        "category": "timing",
        "title": "Unbounded network I/O",
        "description": f"Unbounded I/O call at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Add timeout and bounded retry policy to all I/O operations",
        "code_snippet": extract_snippet(lines, line_num),
    })


check_timing_tool = function_tool(check_timing)
