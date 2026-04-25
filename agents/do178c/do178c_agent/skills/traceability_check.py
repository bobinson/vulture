"""DO-178C requirements traceability detection."""

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

# Function definitions across languages.
_FUNC_DEF = re.compile(
    r"^\s*(?:def|func|function)\s+\w+"
)

# Typed method signatures: `public void foo(`, `private static int bar(`
_TYPED_METHOD = re.compile(
    r"^\s*(?:public|private|protected|static|async|export)[\s\w]*\s+\w+\s*\("
)

# Requirement tags in comments.
_REQ_TAG = re.compile(
    r"(?:@requirement|REQ-\d+|HLR-\d+|LLR-\d+|SRS-\d+)",
    re.IGNORECASE,
)


def check_traceability(source_path: str) -> dict:
    """Check that functions have requirement traceability tags.

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
    """Scan a single file for functions missing requirement tags."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    line_list = list(lines)
    for line_num, line in enumerate(line_list, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        _check_func_tag(file_path, line, line_num, line_list, findings)


def _check_func_tag(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Flag function definitions without a requirement tag in the 5 lines above."""
    if not (_FUNC_DEF.match(line) or _TYPED_METHOD.match(line)):
        return
    if _has_req_tag(lines, line_num):
        return
    findings.append({
        "severity": "high",
        "check_id": "do178c.trace.missing_req_tag",
        "category": "traceability",
        "title": "Function missing requirement traceability tag",
        "description": f"No requirement tag found above function at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Add @requirement, REQ-NNN, HLR-NNN, LLR-NNN, or SRS-NNN tag",
        "code_snippet": extract_snippet(lines, line_num),
    })


def _has_req_tag(lines: list[str], line_num: int) -> bool:
    """Check 5 lines above line_num for a requirement tag."""
    start = max(0, line_num - 1 - 5)
    end = line_num - 1
    return any(_REQ_TAG.search(lines[i]) for i in range(start, end))


check_traceability_tool = function_tool(check_traceability)
