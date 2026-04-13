"""Reflected XSS detection skill (CWE-79).

Detects user input reflected in HTTP responses without proper encoding:
template unsafe rendering, direct DOM writes, framework-specific patterns.
"""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# Template unsafe rendering
TEMPLATE_UNSAFE_PATTERNS = [
    re.compile(r"\|\s*safe\b"),                          # Jinja2/Django |safe
    re.compile(r"mark_safe\s*\("),                       # Django mark_safe()
    re.compile(r"\{!!\s*.*\s*!!\}"),                     # Blade {!! !!}
    re.compile(r"<%-\s*"),                                  # EJS <%- %> (unescaped only; <%= is safe)
    re.compile(r"dangerouslySetInnerHTML"),               # React
]

# Direct DOM writes with variables
DOM_WRITE_PATTERNS = [
    re.compile(r"\.innerHTML\s*=\s*[^'\";\s]"),          # innerHTML = variable
    re.compile(r"\.outerHTML\s*=\s*[^'\";\s]"),          # outerHTML = variable
    re.compile(r"document\.write\s*\([^)]*[+`$]"),       # document.write with concat/template
    re.compile(r"document\.writeln\s*\([^)]*[+`$]"),     # document.writeln with concat/template
]

# Server response with request params
SERVER_RESPONSE_PATTERNS = [
    re.compile(r"fmt\.Fprintf\s*\(\s*w\s*,.*(?:r\.|request|req\.)", re.IGNORECASE),
    re.compile(r"Response\s*\([^)]*(?:request|req\.|input)", re.IGNORECASE),
    re.compile(r"HttpResponse\s*\([^)]*(?:request|req\.|input)", re.IGNORECASE),
    re.compile(r"res\.send\s*\([^)]*(?:req\.|request)", re.IGNORECASE),
    re.compile(r"res\.write\s*\([^)]*(?:req\.|request)", re.IGNORECASE),
    re.compile(r"echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\["),  # PHP echo $_GET[...]
    re.compile(r"<\?=\s*\$"),                                    # PHP <?= $var ?>
]

# Safe sanitization patterns (context-aware ±5 lines)
SAFE_PATTERNS = re.compile(
    r"(?:html\.EscapeString|bleach\.clean|DOMPurify|sanitize|"
    r"encodeURIComponent|htmlspecialchars|escape\(|escapeHtml|"
    r"Content-Type.*application/json|textContent|innerText|"
    r"createTextNode|xss\(|clean\(|purify)",
    re.IGNORECASE,
)

COMMENT_LINE = COMMENT_INDICATORS
IMPORT_LINE = SAFE_IMPORT_LINE
SCANNER_DEF = SCANNER_DEF_LINE


def check_reflected_xss(source_path: str) -> dict:
    """Check for reflected XSS vulnerabilities (CWE-79).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of reflected XSS vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        if is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_LINE.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF.search(line):
            continue
        _check_template_unsafe(file_path, line, line_num, lines, findings)
        _check_dom_writes(file_path, line, line_num, lines, findings)
        _check_server_response(file_path, line, line_num, lines, findings)


def _has_safe_context(lines: list[str], line_num: int, radius: int = 5) -> bool:
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    context = "\n".join(lines[start:end])
    return bool(SAFE_PATTERNS.search(context))


def _check_template_unsafe(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in TEMPLATE_UNSAFE_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "critical",
                "category": "CWE-79",
                "title": "Reflected XSS via unsafe template rendering",
                "description": (
                    f"Template renders content without escaping at line {line_num}. "
                    f"User input may be reflected in the response unencoded."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Remove |safe filter or mark_safe() call. Use auto-escaping "
                    "provided by the template engine, or sanitize with bleach.clean() "
                    "or DOMPurify.sanitize() before rendering."
                ),
            })
            return


def _check_dom_writes(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in DOM_WRITE_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "critical",
                "category": "CWE-79",
                "title": "Reflected XSS via innerHTML/document.write",
                "description": (
                    f"Dynamic content written to DOM without sanitization "
                    f"at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Use textContent instead of innerHTML, or sanitize with "
                    "DOMPurify.sanitize() before rendering."
                ),
            })
            return


def _check_server_response(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in SERVER_RESPONSE_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "critical",
                "category": "CWE-79",
                "title": "Reflected XSS via server response",
                "description": (
                    f"User input written directly to HTTP response without "
                    f"encoding at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "HTML-encode user input before including in responses. "
                    "Use html.EscapeString (Go), bleach.clean (Python), "
                    "or htmlspecialchars (PHP)."
                ),
            })
            return


check_reflected_xss_tool = function_tool(check_reflected_xss)
