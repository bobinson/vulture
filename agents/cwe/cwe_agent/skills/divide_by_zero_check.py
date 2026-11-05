"""Dedicated skill for CWE-369 (divide-by-zero).

Flags ``/`` or ``%`` operations where the right-hand side is a non-literal
identifier and no zero-guard appears in the 5-line preceding window. Gated
to undefined-behavior languages (C, C++, Go, Rust) where divide-by-zero is
a runtime crash or undefined behavior, rather than an expected exception.
A division in a constant declaration is evaluated by the compiler and is
not reported.
"""
import re
from pathlib import Path
from typing import Any

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._lexical import stripped_code
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# Language gate: C, C++, Go, Rust — divide-by-zero is UB or a crash here.
_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".go", ".rs",
})

# Divide or modulo by an identifier (not a digit literal).
_DIV_OP = re.compile(r"\b(\w+)\s*([/%])\s*([A-Za-z_]\w*)\b")

# Pre-strip strings and comments before regex search so URLs ("http://"),
# file paths in string literals, and inline doc comments don't trigger
# the divide pattern. Handles C/C++ // and /* */, double- and single-
# quoted strings.
_STRING_OR_COMMENT = re.compile(
    r"""
    "(?:\\.|[^"\\])*"        # double-quoted string
    | '(?:\\.|[^'\\])*'      # single-quoted string / char
    | //[^\n]*               # C++/Go/Rust line comment
    | /\*.*?\*/              # C block comment (single-line variant)
    """,
    re.VERBOSE | re.DOTALL,
)


def _strip_strings_and_comments(line: str) -> str:
    """Replace string literals / line comments with spaces of equal length.

    Equal-length substitution preserves column positions so the line
    number context stays meaningful, while the divide-op regex no
    longer matches `/` characters embedded in `"http://..."` or in a
    `// note: x/y` comment.
    """
    return _STRING_OR_COMMENT.sub(lambda m: " " * len(m.group(0)), line)

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


# A division the compiler evaluates cannot fault at run time: a zero divisor in a
# constant expression fails the build (Go, Rust) or is not a constant expression
# (C++). These declarations require one: a Go `const` (alone, or inside a
# `const (` group), a Rust `const`/`static` item (`NAME: T =`; a `const fn` is a
# function and also runs at run time), and a C/C++ `constexpr` variable (the `=`
# comes before any parenthesis, so a `constexpr` function is not one). A C
# `#define` is not one either: it expands into each use.
_CONSTEXPR_VARIABLE = re.compile(r"\bconstexpr\b[^=(){};]{1,120}=")
_CONST_DECLARATION = {
    ".go": re.compile(r"^\s*const\s+[A-Za-z_]"),
    ".rs": re.compile(
        r"^\s*(?:pub(?:\s*\([^()]{0,40}\))?\s+)?(?:const|static)\s+(?:mut\s+)?[A-Za-z_]\w{0,63}\s*:"
    ),
    **dict.fromkeys((".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"), _CONSTEXPR_VARIABLE),
}
# Go `const (` opens a group whose every spec is a constant. Walking up from a
# line, the group's opener is reached before any line that cannot sit inside it:
# its `)` closer, a brace (a body or a literal), or another declaration keyword.
_GO_CONST_GROUP = re.compile(r"^\s*const\s*\(\s*$")
_GO_GROUP_EDGE = re.compile(r"^\s*(?:\)|(?:var|type|func|import|package)\b)|[{}]")
_GROUP_LOOKBACK = 200


def _is_compile_time(lines: tuple[str, ...], lineno: int, suffix: str) -> bool:
    """True when line ``lineno`` declares a constant, so the compiler divides."""
    declaration = _CONST_DECLARATION.get(suffix)
    if declaration is not None and declaration.search(stripped_code(lines[lineno - 1])):
        return True
    return suffix == ".go" and _in_go_const_group(lines, lineno)


def _in_go_const_group(lines: tuple[str, ...], lineno: int) -> bool:
    """True when line ``lineno`` is a spec inside a Go `const (` group."""
    for text in reversed(lines[max(0, lineno - 1 - _GROUP_LOOKBACK):lineno - 1]):
        code = stripped_code(text)
        if _GO_CONST_GROUP.match(code):
            return True
        if _GO_GROUP_EDGE.search(code):
            return False
    return False


def _excused(lines: tuple[str, ...], lineno: int, file_path: str) -> bool:
    """A zero check just above the division, or a division the compiler evaluates."""
    suffix = Path(file_path).suffix.lower()
    return _is_safe_context(lines, lineno) or _is_compile_time(lines, lineno, suffix)


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
    """Scan a single line for unguarded divide/modulo-by-identifier.

    Skip lines that are entirely a comment, and run the divide-op match
    against a string-and-comment-stripped copy of the line so e.g.
    `url = "http://example.com/x"` doesn't trigger CWE-369.
    """
    if COMMENT_INDICATORS.match(line):
        return
    cleaned = _strip_strings_and_comments(line)
    if not _DIV_OP.search(cleaned) or _excused(lines, lineno, file_path):
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
