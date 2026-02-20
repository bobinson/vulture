"""Resource management vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-476: NULL pointer dereference
NULL_DEREF_PATTERNS = [
    re.compile(r"(\w+)\s*:=\s*\w+\.\w+\(.*\)\s*$"),  # Go: no nil check after call
    re.compile(r"\*(\w+)\s*(?:=|\.)"),  # Pointer dereference
]
GO_NIL_CHECK = re.compile(r"if\s+\w+\s*[!=]=\s*nil")

# CWE-400: Uncontrolled resource consumption
RESOURCE_CONSUMPTION_PATTERNS = [
    re.compile(r"for\s*\{", re.IGNORECASE),  # Go: infinite loop
    re.compile(r"while\s*(?:True|1)\s*:"),  # Python: infinite loop
    re.compile(r"while\s*\(\s*(?:true|1)\s*\)"),  # C/Java: infinite loop
]
BREAK_OR_RETURN = re.compile(r"\b(?:break|return|sys\.exit|os\.Exit)\b")

# CWE-404: Improper resource shutdown
RESOURCE_OPEN_PATTERNS = [
    re.compile(r"(?:open|fopen|os\.Open|os\.Create)\s*\("),
    re.compile(r"(?:sql\.Open|pgx\.Connect|mongo\.Connect)\s*\("),
    re.compile(r"net\.(?:Dial|Listen)\s*\("),
]
RESOURCE_CLOSE_SAFE = re.compile(
    r"\b(?:defer\s|\.close\(\)|\.Close\(\)|with\s+open|context\s*manager)\b",
    re.IGNORECASE,
)

# CWE-770: Allocation without limits
UNBOUNDED_ALLOC_PATTERNS = [
    re.compile(r"\.append\(.*\)\s*$"),  # Python list append in loop
    re.compile(r"make\(\[\]\w+,\s*0\)"),  # Go: unbounded slice
]
SIZE_LIMIT = re.compile(r"\b(?:max_size|maxlen|capacity|limit|MAX_)\b", re.IGNORECASE)

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")


def check_resource_management(source_path: str) -> dict:
    """Check for resource management vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of resource management issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for resource management issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_resource_consumption(file_path, line, line_num, findings, is_test=is_test)
        _check_improper_shutdown(file_path, line, line_num, lines, findings, is_test=is_test)


def _check_resource_consumption(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool,
) -> None:
    """Check for uncontrolled resource consumption (CWE-400)."""
    for pattern in RESOURCE_CONSUMPTION_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-400",
            "title": "Potential uncontrolled resource consumption",
            "description": f"Unbounded loop without visible exit at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add explicit bounds, timeouts, or break conditions to loops",
        })
        return


def _check_improper_shutdown(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
    *,
    is_test: bool,
) -> None:
    """Check for improper resource shutdown (CWE-404)."""
    for pattern in RESOURCE_OPEN_PATTERNS:
        if not pattern.search(line):
            continue
        # Look for close/defer in surrounding context (next 5 lines)
        context_end = min(line_num + 5, len(lines))
        context = "\n".join(lines[line_num - 1 : context_end])
        if RESOURCE_CLOSE_SAFE.search(context):
            return
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-404",
            "title": "Resource opened without proper cleanup",
            "description": f"Resource opened at line {line_num} without close/defer/with",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use defer (Go), with statement (Python), or try-finally to ensure cleanup",
        })
        return


check_resource_management_tool = function_tool(check_resource_management)
