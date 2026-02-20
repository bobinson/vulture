"""Injection vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

SQL_INJECTION_PATTERNS = [
    re.compile(r'f"[^"]*SELECT[^"]*\{'),
    re.compile(r"f'[^']*SELECT[^']*\{"),
    re.compile(r'format\([^)]*SELECT'),
    re.compile(r'SELECT.*\.format\('),
    re.compile(r'%s.*execute\(|execute\(.*%'),
    re.compile(r'query\s*=\s*[f"\'].*\+'),
    re.compile(r'Sprintf\([^)]*SELECT', re.IGNORECASE),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"os\.system\("),
    re.compile(r"subprocess\.call\([^)]*shell\s*=\s*True"),
    re.compile(r"(?<!\.)(?:exec|eval)\("),
    re.compile(r"os\.popen\("),
]

SAFE_STATIC_CALL = re.compile(r"""(?:exec|eval)\(\s*(?:'[^']*'|"[^"]*")\s*[,)]""")
# Shell function definitions: `func_name() {`
SHELL_FUNC_DEF = re.compile(r"^\s*\w+\s*\(\s*\)\s*\{")
COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")


def check_injection(source_path: str) -> dict:
    """Check for injection vulnerabilities (SQL, command, etc).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of injection vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for injection patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        _check_sql_injection(file_path, line, line_num, findings, is_test=is_test)
        _check_command_injection(file_path, line, line_num, findings, is_test=is_test)


def _check_sql_injection(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check a line for SQL injection patterns."""
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "A03-injection",
                "title": "Potential SQL injection",
                "description": f"String interpolation in SQL query at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use parameterized queries instead of string formatting",
            })
            return


def _check_command_injection(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check a line for command injection patterns."""
    if SHELL_FUNC_DEF.match(line):
        return
    for pattern in COMMAND_INJECTION_PATTERNS:
        if pattern.search(line):
            if SAFE_STATIC_CALL.search(line):
                return
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "A03-injection",
                "title": "Potential command injection",
                "description": f"Unsafe command execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use subprocess with shell=False and list arguments",
            })
            return


check_injection_tool = function_tool(check_injection)
