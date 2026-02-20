"""CWE buffer handling vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# Only scan C/C++/Go files
BUFFER_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".go"})

# CWE-120: Buffer overflow (unbounded copy)
UNBOUNDED_COPY_PATTERNS = [
    re.compile(r"\bstrcpy\s*\("),
    re.compile(r"\bstrcat\s*\("),
    re.compile(r"\bsprintf\s*\("),
    re.compile(r"\bgets\s*\("),
    re.compile(r"\bwcscpy\s*\("),
    re.compile(r"\bwcscat\s*\("),
]

SAFE_BOUNDED_ALTERNATIVES = re.compile(
    r"\b(?:strncpy|strncat|snprintf|fgets|strlcpy|strlcat)\s*\("
)

# CWE-787: Out-of-bounds write (memcpy/memmove without validation)
OOB_WRITE_PATTERNS = [
    re.compile(r"\bmemcpy\s*\("),
    re.compile(r"\bmemmove\s*\("),
    re.compile(r"\bcopy\s*\([^)]*,\s*\w+\s*\["),
]

SAFE_SIZEOF_CHECK = re.compile(r"sizeof\s*\(")

# CWE-125: Out-of-bounds read (array access without bounds check)
OOB_READ_PATTERNS = [
    re.compile(r"\w+\s*\[\s*\w+\s*\]"),
]

SAFE_BOUNDS_CHECK = re.compile(r"(?:len\(|\.(?:size|length|Len)\b|<\s*\w+\s*\)|sizeof)")

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
INCLUDE_LINE = re.compile(r"^\s*#\s*include\b")


def check_buffer_handling(source_path: str) -> dict:
    """Check for CWE buffer handling vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of buffer vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=BUFFER_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for buffer handling patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if INCLUDE_LINE.match(line):
            continue
        _check_unbounded_copy(file_path, line, line_num, findings, is_test=is_test)
        _check_oob_write(file_path, line, line_num, findings, is_test=is_test)
        _check_oob_read(file_path, line, line_num, findings, is_test=is_test)


def _check_unbounded_copy(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-120 unbounded buffer copy."""
    if SAFE_BOUNDED_ALTERNATIVES.search(line):
        return
    for pattern in UNBOUNDED_COPY_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-120",
                "title": "Unbounded buffer copy",
                "description": f"Use of unbounded copy function at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use bounded alternatives: strncpy, snprintf, fgets",
            })
            return


def _check_oob_write(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-787 out-of-bounds write."""
    if SAFE_SIZEOF_CHECK.search(line):
        return
    for pattern in OOB_WRITE_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-787",
                "title": "Potential out-of-bounds write",
                "description": f"Memory copy without size validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate buffer sizes before memcpy/memmove operations",
            })
            return


def _check_oob_read(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-125 out-of-bounds read."""
    if SAFE_BOUNDS_CHECK.search(line):
        return
    for pattern in OOB_READ_PATTERNS:
        if pattern.search(line):
            # Skip simple constant index access like arr[0] or arr[1]
            if re.search(r"\w+\s*\[\s*\d+\s*\]", line):
                return
            findings.append({
                "severity": "low" if is_test else "medium",
                "category": "CWE-125",
                "title": "Potential out-of-bounds read",
                "description": f"Array access without bounds check at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Add bounds checking before array access",
            })
            return


check_buffer_handling_tool = function_tool(check_buffer_handling)
