"""DO-178C dynamic memory allocation detection."""

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

# C/C++ heap allocation and deallocation.
_C_ALLOC = re.compile(
    r"(?<!\w)(?:malloc|calloc|realloc|free)\s*\("
)

# 'new' keyword for C++/Java/C#/JS/TS object allocation.
_NEW_KEYWORD = re.compile(
    r"(?<!\w)new\s+[A-Z]\w*"
)

# Go dynamic allocation: make([]...) or append().
#
# VLT-4421 hardening: this pattern is Go-specific and MUST be gated to
# `.go` files only. `(?<!\w)append\s*\(` matches Python `list.append(`
# (and JS `arr.append(`, etc.) — those are NOT heap allocations in the
# DO-178C sense. Without the language gate the Python half of any
# codebase produces a flood of false-positive findings.
_GO_ALLOC = re.compile(
    r"(?:make\s*\(\s*\[|(?<!\w)append\s*\()"
)

# Java/C++ dynamic containers.
_CONTAINER = re.compile(
    r"(?<!\w)(?:ArrayList|LinkedList|HashMap|vector)\s*[<(]"
)

# Patterns that fire regardless of language extension (the call shape is
# unambiguous across languages or has the same heap-allocation semantics).
_LANGUAGE_AGNOSTIC_PATTERNS: list[re.Pattern[str]] = [_C_ALLOC, _NEW_KEYWORD, _CONTAINER]

# Per-language patterns: only run when the file's suffix is in the set.
_GO_FILE_SUFFIXES: frozenset[str] = frozenset({".go"})


def check_malloc(source_path: str) -> dict:
    """Check for dynamic memory allocation.

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
    """Scan a single file for dynamic allocation patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    line_list = list(lines)
    for line_num, line in enumerate(line_list, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        _check_alloc(file_path, line, line_num, line_list, findings)


def _patterns_for_file(file_path: Path) -> list[re.Pattern[str]]:
    """Return the patterns that apply to this file's language.

    Language-agnostic patterns (malloc, new, ArrayList) always run.
    The Go-flavoured pattern (make([]T) / append()) is added only for
    `.go` files so Python `list.append(...)` and JS `arr.append(...)`
    don't produce false-positive DO-178C malloc findings.
    """
    if file_path.suffix.lower() in _GO_FILE_SUFFIXES:
        return [*_LANGUAGE_AGNOSTIC_PATTERNS, _GO_ALLOC]
    return _LANGUAGE_AGNOSTIC_PATTERNS


def _check_alloc(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Flag any dynamic allocation pattern on this line."""
    for pattern in _patterns_for_file(file_path):
        if pattern.search(line):
            findings.append({
                "severity": "high",
                "check_id": "do178c.malloc.dynamic_alloc",
                "category": "malloc",
                "title": "Dynamic memory allocation detected",
                "description": f"Dynamic allocation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use static allocation or pre-allocated pools for DO-178C compliance",
                "code_snippet": extract_snippet(lines, line_num),
            })
            return


check_malloc_tool = function_tool(check_malloc)
