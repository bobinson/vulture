"""DO-178C recursion and unbounded loop detection."""

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

# Function definition: captures the function name.
# Handles: def, async def, func, export function, export async function.
_FUNC_DEF = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?(?:def|func|function)\s+(\w+)"
)

# Go method receiver: func (r *Receiver) Name(
_GO_METHOD_DEF = re.compile(
    r"^\s*func\s+\([^)]*\)\s+(\w+)"
)

# Unbounded loops.
_UNBOUNDED_LOOP = re.compile(
    r"(?:while\s+(?:True|true)\s*[:{]|for\s*\(\s*;\s*;\s*\)|loop\s*\{)"
)

# Normalizes self./this. prefix so self.foo() and this.foo() are treated as
# direct calls (potential recursion), but other_obj.foo() is not.
_SELF_PREFIX = re.compile(r"\b(?:self|this)\.")


def check_recursion(source_path: str) -> dict:
    """Check for direct recursion and unbounded loops.

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
    """Scan a single file for recursion and unbounded loops."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    line_list = list(lines)
    _check_direct_recursion(file_path, line_list, findings)
    _check_unbounded_loops(file_path, line_list, findings)


def _check_direct_recursion(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Detect functions that call themselves.

    Tracks function scope by indentation: when a new function definition
    appears at the same or lower indentation, the previous function's scope
    ends. Only lines within a function's body (higher indentation) are checked.
    """
    current_func: str | None = None
    current_indent: int = -1

    for line_num, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if not stripped or COMMENT_INDICATORS.match(stripped):
            continue

        indent = len(line) - len(stripped)

        # Check for a new function definition.
        func_name = _extract_func_name(line)
        if func_name is not None:
            current_func = func_name
            current_indent = indent
            continue

        # If we've left the function scope (same or lower indent), reset.
        if current_func is not None and indent <= current_indent:
            current_func = None
            current_indent = -1
            # Re-check: this line itself might be a new function def (already handled above).
            continue

        if current_func and _calls_self(stripped, current_func):
            findings.append(_finding(
                "do178c.recursion.direct", "Direct recursion detected",
                f"Function '{current_func}' calls itself at line {line_num}",
                file_path, line_num, lines,
                "Replace recursion with iterative approach or prove termination",
            ))


def _extract_func_name(line: str) -> str | None:
    """Extract function name from a definition line, or return None."""
    m = _FUNC_DEF.match(line) or _GO_METHOD_DEF.match(line)
    return m.group(1) if m else None


def _calls_self(line: str, func_name: str) -> bool:
    """Return True if line contains a direct call to func_name.

    Handles two false-positive patterns:
    1. obj.func_name() — a method call on a different object, not recursion.
       Only self.func_name() and this.func_name() are treated as potential
       recursion (since they call the same method on the same instance).
    2. Unrelated function with the same name in a different scope (handled
       by the scope-tracking caller, not here).
    """
    # Normalize: strip self./this. so self.foo() becomes foo() (potential recursion).
    # Leave other_obj.foo() as .foo() — the dot will block the match below.
    normalized = _SELF_PREFIX.sub("", line)

    # Match func_name( NOT preceded by a dot (which would mean obj.func_name).
    pattern = re.compile(rf"(?<!\.)(?<!\w){re.escape(func_name)}\s*\(")
    return bool(pattern.search(normalized))


def _check_unbounded_loops(
    file_path: Path, lines: list[str], findings: list[dict],
) -> None:
    """Detect unbounded loop constructs."""
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if _UNBOUNDED_LOOP.search(line):
            findings.append(_finding(
                "do178c.recursion.unbounded_loop", "Unbounded loop detected",
                f"Potentially unbounded loop at line {line_num}",
                file_path, line_num, lines,
                "Add bounded iteration limit or prove termination",
            ))


def _finding(
    check_id: str, title: str, description: str,
    file_path: Path, line_num: int, lines: list[str],
    recommendation: str,
) -> dict:
    """Build a standard finding dict."""
    return {
        "severity": "critical",
        "check_id": check_id,
        "category": "recursion",
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": recommendation,
        "code_snippet": extract_snippet(lines, line_num),
    }


check_recursion_tool = function_tool(check_recursion)
