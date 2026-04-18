"""Dedicated skill for CWE-369 (divide-by-zero).

Flags ``/`` or ``%`` operations where the right-hand side is a non-literal
identifier and no zero-guard appears in the 5-line preceding window. Gated
to undefined-behavior languages (C, C++, Go, Rust) where divide-by-zero is
a runtime crash or undefined behavior, rather than an expected exception.
"""
import re
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# Language gate: C, C++, Go, Rust — divide-by-zero is UB or a crash here.
_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".go", ".rs",
})

# Divide or modulo by an identifier (not a digit literal).
_DIV_OP = re.compile(r"\b(\w+)\s*([/%])\s*([A-Za-z_]\w*)\b")

# Safe-context guard: zero-check within the 5-line preceding window.
_SAFE_CONTEXT = re.compile(
    r"(?:!=|==|>|<)\s*0\b"
    r"|\bis_zero\b"
    r"|\bisZero\b"
    r"|\.is_zero\s*\("
    r"|assert\b[^;]*(?:!=|==)\s*0",
)


def _is_safe_context(lines: tuple[str, ...], lineno: int) -> bool:
    """Return True if a zero-check guard appears in the prior 5 lines."""
    start = max(0, lineno - 6)
    end = lineno  # exclusive of current line but includes 5 prior
    window = "\n".join(lines[start:end])
    return _SAFE_CONTEXT.search(window) is not None


def _build_finding(
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single CWE-369 finding dict."""
    finding = {
        "severity": "medium",
        "check_id": "cwe.divide_by_zero.cwe_369",
        "category": "CWE-369",
        "title": "Divide By Zero",
        "description": (
            f"Division or modulo operation with non-literal divisor at "
            f"line {lineno} without a preceding zero-check."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Validate the divisor against zero before the operation "
            "(e.g., `if (b != 0)` or assert it is non-zero)."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, "369")


def _scan_line(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a single line for unguarded divide/modulo-by-identifier."""
    if not _DIV_OP.search(line):
        return
    if _is_safe_context(lines, lineno):
        return
    findings.append(_build_finding(file_path, lineno, lines))


def _should_scan(file_path: Path) -> bool:
    """Return True if file passes language-gate and non-generated/test filters."""
    if file_path.suffix.lower() not in _LANG_EXTENSIONS:
        return False
    return not (is_generated_file(file_path) or is_test_file(file_path))


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan each one for divide-by-zero candidates."""
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_line(line, lineno, path_str, lines, findings)


def check_divide_by_zero(source_path: str) -> dict[str, Any]:
    """Scan source files for unguarded divide/modulo operations (CWE-369)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_divide_by_zero_tool = function_tool(check_divide_by_zero)
