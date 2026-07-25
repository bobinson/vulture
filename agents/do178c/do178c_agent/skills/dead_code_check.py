"""DO-178C dead code detection: unreachable code and constant conditionals."""

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

# Statements that unconditionally terminate control flow.
_TERMINATOR = re.compile(
    r"^\s+(?:return\b|raise\b|panic\(|sys\.exit\(|os\.Exit\(|process\.exit\()"
)

# Constant-true conditionals.
_CONST_TRUE = re.compile(
    r"^\s*(?:if|elif|while)\s*[\(]?\s*(?:True|true|1)\s*[\)]?\s*[:{]"
)

# Constant-false conditionals.
_CONST_FALSE = re.compile(
    r"^\s*(?:if|elif|while)\s*[\(]?\s*(?:False|false|0)\s*[\)]?\s*[:{]"
)


def check_dead_code(source_path: str) -> dict:
    """Check for dead code: unreachable statements and constant conditionals.

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
    """Scan a single file for dead code patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    line_list = list(lines)
    for line_num, line in enumerate(line_list, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        _check_unreachable(file_path, line, line_num, line_list, findings)
        _check_const_conditional(file_path, line, line_num, line_list, findings)


def _check_unreachable(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Detect code after return/raise/panic/exit at the same indentation."""
    if not _TERMINATOR.match(line):
        return
    indent = len(line) - len(line.lstrip())
    if line_num >= len(lines):
        return
    next_line = lines[line_num]  # 0-based index = line_num (since line_num is 1-based)
    if not next_line.strip() or COMMENT_INDICATORS.match(next_line):
        return
    next_indent = len(next_line) - len(next_line.lstrip())
    if next_indent != indent:
        return
    findings.append(_finding(
        "do178c.dead_code.unreachable", "Unreachable code after terminator",
        f"Code at line {line_num + 1} is unreachable after terminator at line {line_num}",
        file_path, line_num + 1, lines,
        "Remove unreachable code or restructure control flow",
    ))


def _check_const_conditional(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Detect constant-true or constant-false conditionals."""
    if _CONST_TRUE.match(line):
        findings.append(_finding(
            "do178c.dead_code.const_true", "Constant-true conditional",
            f"Condition is always true at line {line_num}",
            file_path, line_num, lines,
            "Replace constant condition with explicit logic or remove the branch",
        ))
        return
    if _CONST_FALSE.match(line):
        findings.append(_finding(
            "do178c.dead_code.const_false", "Constant-false conditional",
            f"Condition is always false at line {line_num}",
            file_path, line_num, lines,
            "Remove dead branch guarded by constant-false condition",
        ))


def _finding(
    check_id: str, title: str, description: str,
    file_path: Path, line_num: int, lines: list[str],
    recommendation: str,
) -> dict:
    """Build a standard finding dict."""
    return {
        "severity": "high",
        "check_id": check_id,
        "category": "dead_code",
        "title": title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": recommendation,
        "code_snippet": extract_snippet(lines, line_num),
    }


check_dead_code_tool = function_tool(check_dead_code)
