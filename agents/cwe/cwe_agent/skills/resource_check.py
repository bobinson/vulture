"""Resource management vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,

    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

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
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for resource management issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_resource_consumption(file_path, line, line_num, lines, findings)
        _check_improper_shutdown(file_path, line, line_num, lines, findings)
        _check_null_deref(file_path, line, line_num, lines, findings)
        _check_unbounded_alloc(file_path, line, line_num, lines, findings)


def _check_resource_consumption(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for uncontrolled resource consumption (CWE-400)."""
    for pattern in RESOURCE_CONSUMPTION_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.uncontrolled_consumption",
            "category": "CWE-400",
            "title": "Potential uncontrolled resource consumption",
            "description": f"Unbounded loop without visible exit at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add explicit bounds, timeouts, or break conditions to loops",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "400"))
        return


def _check_improper_shutdown(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
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
        finding = {
            "severity": "high",
            "check_id": "cwe.resource.improper_shutdown",
            "category": "CWE-404",
            "title": "Resource opened without proper cleanup",
            "description": f"Resource opened at line {line_num} without close/defer/with",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use defer (Go), with statement (Python), or try-finally to ensure cleanup",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "404"))
        return


def _check_null_deref(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for NULL pointer dereference (CWE-476)."""
    # Focus on Go pattern: assignment from method call without nil check
    if not NULL_DEREF_PATTERNS[0].search(line):
        return
    # Check following lines for nil check before use
    window_end = min(line_num + 5, len(lines))
    window = "\n".join(lines[line_num:window_end])
    if GO_NIL_CHECK.search(window):
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.resource.null_deref",
        "category": "CWE-476",
        "title": "Potential NULL pointer dereference",
        "description": f"Return value used without nil check at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Check for nil/null before dereferencing pointers",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "476"))


def _check_unbounded_alloc(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for allocation without limits (CWE-770)."""
    # Check surrounding context for size limits
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SIZE_LIMIT.search(context):
        return
    for pattern in UNBOUNDED_ALLOC_PATTERNS:
        if not pattern.search(line):
            continue
        finding = {
            "severity": "medium",
            "check_id": "cwe.resource.unbounded_alloc",
            "category": "CWE-770",
            "title": "Allocation without resource limits",
            "description": f"Unbounded allocation at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Add size limits, max capacity, or bounded data structures",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "770"))
        return


check_resource_management_tool = function_tool(check_resource_management)
