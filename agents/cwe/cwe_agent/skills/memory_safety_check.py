"""Memory safety vulnerability detection skill.

Covers memory management issues beyond basic buffer overflows, focusing on
lifecycle and initialization bugs in C, C++, Go, and Rust (unsafe blocks).
"""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

MEMORY_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".go", ".rs"})

# CWE-401: Missing Release of Memory after Effective Lifetime (memory leak)
MEMORY_ALLOC_PATTERNS = [
    re.compile(r"\bmalloc\s*\("),
    re.compile(r"\bcalloc\s*\("),
    re.compile(r"\brealloc\s*\("),
    re.compile(r"\bnew\s+\w+(?:\[|\()"),  # C++ new
    re.compile(r"\bstrdup\s*\("),
]

MEMORY_FREE_PATTERNS = re.compile(
    r"\b(?:free|delete(?:\[\])?|defer)\b|Close\(\)"
)

# CWE-415: Double Free
DOUBLE_FREE_FREE_CALL = re.compile(r"\bfree\s*\(\s*(\w+)\s*\)")

# CWE-457: Use of Uninitialized Variable
UNINIT_VAR_PATTERNS = [
    re.compile(r"^\s*(?:int|char|float|double|long|short|unsigned)\s+(\w+)\s*;"),  # C/C++ uninitialized decl
    re.compile(r"^\s*(?:int|char|float|double)\s+\*(\w+)\s*;"),  # Uninitialized pointer
]

INIT_PATTERNS = re.compile(r"(?:=\s*\S|memset|bzero|ZeroMemory|calloc)")

# CWE-824: Access of Uninitialized Pointer
UNINIT_POINTER_PATTERNS = [
    re.compile(r"^\s*(?:\w+\s*\*+)\s+(\w+)\s*;"),  # type *ptr; (no init)
]

POINTER_USE_TEMPLATE = r"(?:\*{var}|\b{var}\s*->|\b{var}\s*\[)"

# CWE-562: Return of Stack Variable Address
RETURN_STACK_PATTERNS = [
    re.compile(r"return\s+&\s*\w+\s*;"),  # C: return &local;
    re.compile(r"return\s+\w+\s*;\s*//.*stack"),  # annotated
]

# CWE-467: Use of sizeof() on a Pointer Type
SIZEOF_POINTER_PATTERNS = [
    re.compile(r"sizeof\s*\(\s*\w+\s*\*\s*\)"),
    re.compile(r"sizeof\s*\(\s*\*?\w+\s*\)\s*/\s*sizeof"),  # sizeof(ptr) / sizeof(elem) — wrong
]

INCLUDE_LINE = re.compile(r"^\s*(?:#\s*include|import|package|use)\b")


def check_memory_safety(source_path: str) -> dict:
    """Check for memory safety vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of memory safety issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path, extensions=MEMORY_EXTENSIONS):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for memory safety issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    content = read_file_safe(file_path) or ""
    has_free = MEMORY_FREE_PATTERNS.search(content) is not None

    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if INCLUDE_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_memory_leak(file_path, line, line_num, has_free, lines, findings)
        _check_double_free(file_path, line, line_num, lines, findings)
        _check_uninit_var(file_path, line, line_num, lines, findings)
        _check_uninit_pointer(file_path, line, line_num, lines, findings)
        _check_return_stack(file_path, line, line_num, lines, findings)
        _check_sizeof_pointer(file_path, line, line_num, lines, findings)


def _check_memory_leak(
    file_path: Path, line: str, line_num: int, has_free: bool,
    lines: list[str], findings: list[dict],
) -> None:
    """Check for CWE-401 memory leak (alloc without matching free)."""
    if has_free:
        return
    for pattern in MEMORY_ALLOC_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.memory_safety.memory_leak",
                "category": "CWE-401",
                "title": "Potential memory leak",
                "description": f"Memory allocation at line {line_num} with no visible free/delete in file",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Ensure every malloc/new has a matching free/delete; use RAII in C++",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "401"))
            return


def _check_double_free(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-415 double free."""
    match = DOUBLE_FREE_FREE_CALL.search(line)
    if not match:
        return
    freed_var = match.group(1)
    # Look for another free of the same variable within next 10 lines
    window_end = min(line_num + 10, len(lines))
    for i in range(line_num, window_end):
        if re.search(rf"\bfree\s*\(\s*{re.escape(freed_var)}\s*\)", lines[i]):
            finding = {
                "severity": "critical",
                "check_id": "cwe.memory_safety.double_free",
                "category": "CWE-415",
                "title": "Potential double free",
                "description": f"Variable '{freed_var}' freed at line {line_num} and again nearby",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": i + 1,
                "recommendation": "Set pointer to NULL after free; check before subsequent free",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "415"))
            return


def _check_uninit_var(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-457 use of uninitialized variable."""
    for pattern in UNINIT_VAR_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        var_name = match.group(1)
        # Check next 3 lines for initialization
        window_end = min(line_num + 3, len(lines))
        window = "\n".join(lines[line_num:window_end])
        if re.search(rf"\b{re.escape(var_name)}\s*=", window):
            return
        if INIT_PATTERNS.search(window):
            return
        finding = {
            "severity": "medium",
            "check_id": "cwe.memory_safety.uninit_var",
            "category": "CWE-457",
            "title": "Use of uninitialized variable",
            "description": f"Variable '{var_name}' declared without initialization at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Initialize variables at declaration; use = 0 or = NULL",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(enrich_finding(finding, "457"))
        return


def _check_uninit_pointer(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-824 access of uninitialized pointer."""
    for pattern in UNINIT_POINTER_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        var_name = match.group(1)
        # Check next 3 lines for initialization before use
        window_end = min(line_num + 3, len(lines))
        window = "\n".join(lines[line_num:window_end])
        if re.search(rf"\b{re.escape(var_name)}\s*=", window):
            return
        # Check if pointer is used (dereferenced)
        use_pattern = POINTER_USE_TEMPLATE.replace("{var}", re.escape(var_name))
        if re.search(use_pattern, window):
            finding = {
                "severity": "critical",
                "check_id": "cwe.memory_safety.uninit_pointer",
                "category": "CWE-824",
                "title": "Access of uninitialized pointer",
                "description": f"Pointer '{var_name}' used before initialization at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Initialize pointers to NULL and check before dereferencing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "824"))
            return


def _check_return_stack(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-562 return of stack variable address."""
    for pattern in RETURN_STACK_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.memory_safety.return_stack_addr",
                "category": "CWE-562",
                "title": "Return of stack variable address",
                "description": f"Address of local variable returned at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Return heap-allocated memory or use output parameters",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "562"))
            return


def _check_sizeof_pointer(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-467 use of sizeof() on pointer type."""
    for pattern in SIZEOF_POINTER_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.memory_safety.sizeof_pointer",
                "category": "CWE-467",
                "title": "sizeof() applied to pointer type",
                "description": f"sizeof() on pointer returns pointer size, not buffer size at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use sizeof on the pointed-to type or track buffer size separately",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "467"))
            return


check_memory_safety_tool = function_tool(check_memory_safety)
