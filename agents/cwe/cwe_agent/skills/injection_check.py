"""CWE injection vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-89: SQL Injection
SQL_INJECTION_PATTERNS = [
    re.compile(r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"]*\{'),
    re.compile(r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^']*\{"),
    re.compile(r"\.format\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
    re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\s.*\.format\(", re.IGNORECASE),
    re.compile(r'Sprintf\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
    re.compile(r'(?:query|sql)\s*=\s*[f"\'"].*\+'),
]

# CWE-78: OS Command Injection
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"os\.system\("),
    re.compile(r"os\.popen\("),
    re.compile(r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True"),
    re.compile(r'exec\.Command\([^)]*\+'),
]

# CWE-79: Cross-site Scripting (XSS)
XSS_PATTERNS = [
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"document\.write\("),
    re.compile(r"dangerouslySetInnerHTML"),
    re.compile(r"\$\(\s*['\"]#?\w+['\"]\s*\)\.html\("),
    re.compile(r"v-html\s*="),
]

# CWE-94: Code Injection
CODE_INJECTION_PATTERNS = [
    re.compile(r"(?<!\w)eval\s*\("),
    re.compile(r"(?<!\w)exec\s*\("),
    re.compile(r"new\s+Function\s*\("),
    re.compile(r"setTimeout\s*\(\s*['\"`]"),
    re.compile(r"setInterval\s*\(\s*['\"`]"),
]

SAFE_STATIC_CALL = re.compile(r"""(?:exec|eval)\(\s*(?:'[^']*'|"[^"]*")\s*[,)]""")
SAFE_IMPORT_LINE = re.compile(r"^\s*(?:from|import)\s")
SHELL_FUNC_DEF = re.compile(r"^\s*\w+\s*\(\s*\)\s*\{")
COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")


def check_injection(source_path: str) -> dict:
    """Check for CWE injection vulnerabilities (SQL, command, XSS, code).

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
        if SAFE_IMPORT_LINE.match(line):
            continue
        _check_sql(file_path, line, line_num, findings, is_test=is_test)
        _check_command(file_path, line, line_num, findings, is_test=is_test)
        _check_xss(file_path, line, line_num, findings, is_test=is_test)
        _check_code_injection(file_path, line, line_num, findings, is_test=is_test)


def _check_sql(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-89 SQL injection."""
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-89",
                "title": "SQL injection via string interpolation",
                "description": f"SQL query built with string formatting at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use parameterized queries or prepared statements",
            })
            return


def _check_command(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-78 OS command injection."""
    if SHELL_FUNC_DEF.match(line):
        return
    for pattern in COMMAND_INJECTION_PATTERNS:
        if pattern.search(line):
            if SAFE_STATIC_CALL.search(line):
                return
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-78",
                "title": "OS command injection",
                "description": f"Unsafe command execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use subprocess with shell=False and list arguments",
            })
            return


def _check_xss(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-79 cross-site scripting."""
    for pattern in XSS_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "low" if is_test else "high",
                "category": "CWE-79",
                "title": "Potential cross-site scripting (XSS)",
                "description": f"Unescaped HTML output at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Sanitize user input before rendering as HTML",
            })
            return


def _check_code_injection(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool
) -> None:
    """Check for CWE-94 code injection."""
    for pattern in CODE_INJECTION_PATTERNS:
        if pattern.search(line):
            if SAFE_STATIC_CALL.search(line):
                return
            findings.append({
                "severity": "medium" if is_test else "critical",
                "category": "CWE-94",
                "title": "Code injection via dynamic execution",
                "description": f"Dynamic code execution at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Avoid eval/exec; use safe alternatives or whitelisted operations",
            })
            return


check_injection_tool = function_tool(check_injection)
