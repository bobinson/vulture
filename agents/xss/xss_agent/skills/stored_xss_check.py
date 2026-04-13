"""Stored XSS detection skill (CWE-79).

Detects database/store reads rendered unsafely in templates or DOM:
ORM results in |safe/innerHTML, markdown as raw HTML, user uploads as text/html.
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

# DB read indicators (preceding lines)
DB_READ_INDICATORS = re.compile(
    r"(?:\.query|\.execute|\.find|\.get|\.filter|\.all\(\)|"
    r"\.objects\.|\.fetch|cursor\.|SELECT\s|\.first\(\)|"
    r"\.find_one|\.aggregate|\.search)",
    re.IGNORECASE,
)

# Unsafe rendering after DB read
UNSAFE_RENDER_PATTERNS = [
    re.compile(r"\|\s*safe\b"),
    re.compile(r"mark_safe\s*\("),
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"\.outerHTML\s*="),
    re.compile(r"dangerouslySetInnerHTML"),
    re.compile(r"\{!!\s*.*\s*!!\}"),
    re.compile(r"v-html\s*="),
]

# Markdown rendered as raw HTML
MARKDOWN_RAW_PATTERNS = [
    re.compile(r"markdown\.markdown\s*\(.*\)\s*.*\|\s*safe"),
    re.compile(r"Markup\s*\(\s*markdown"),
    re.compile(r"\.innerHTML\s*=.*(?:marked|markdown|showdown)", re.IGNORECASE),
    re.compile(r"dangerouslySetInnerHTML.*(?:marked|markdown|showdown)", re.IGNORECASE),
]

# User uploads served as text/html
UPLOAD_HTML_PATTERNS = [
    re.compile(r"content_type\s*=\s*['\"]text/html['\"]", re.IGNORECASE),
    re.compile(r"Content-Type.*text/html.*upload", re.IGNORECASE),
    re.compile(r"send_file\s*\(.*(?:upload|user|attachment)", re.IGNORECASE),
]

SAFE_PATTERNS = re.compile(
    r"(?:bleach\.clean|DOMPurify|sanitize|escape\(|escapeHtml|"
    r"htmlspecialchars|clean\(|purify|textContent|innerText|"
    r"Content-Type.*application/json)",
    re.IGNORECASE,
)

COMMENT_LINE = COMMENT_INDICATORS
IMPORT_LINE = SAFE_IMPORT_LINE
SCANNER_DEF = SCANNER_DEF_LINE


def check_stored_xss(source_path: str) -> dict:
    """Check for stored XSS vulnerabilities (CWE-79).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of stored XSS vulnerabilities.
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
        _check_db_to_unsafe_render(file_path, line, line_num, lines, findings)
        _check_markdown_raw(file_path, line, line_num, lines, findings)
        _check_upload_html(file_path, line, line_num, lines, findings)


def _has_safe_context(lines: list[str], line_num: int, radius: int = 5) -> bool:
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    context = "\n".join(lines[start:end])
    return bool(SAFE_PATTERNS.search(context))


def _has_db_read_nearby(lines: list[str], line_num: int, radius: int = 10) -> bool:
    start = max(0, line_num - 1 - radius)
    end = line_num - 1
    context = "\n".join(lines[start:end])
    return bool(DB_READ_INDICATORS.search(context))


def _check_db_to_unsafe_render(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in UNSAFE_RENDER_PATTERNS:
        if pattern.search(line):
            if not _has_db_read_nearby(lines, line_num):
                return
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "critical",
                "category": "CWE-79",
                "title": "Stored XSS via database content rendered unsafely",
                "description": (
                    f"Database content rendered without escaping at line {line_num}. "
                    f"A DB read was detected within 10 lines above."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Sanitize database content before rendering. Use bleach.clean() "
                    "for Python, DOMPurify.sanitize() for JavaScript, or remove "
                    "the |safe filter and rely on auto-escaping."
                ),
            })
            return


def _check_markdown_raw(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in MARKDOWN_RAW_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "high",
                "category": "CWE-79",
                "title": "Stored XSS via markdown rendered as raw HTML",
                "description": (
                    f"Markdown output inserted as raw HTML at line {line_num}. "
                    f"Malicious markdown content can inject scripts."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Sanitize markdown HTML output with bleach.clean() or "
                    "DOMPurify.sanitize() before rendering. Consider using "
                    "a markdown library with built-in XSS protection."
                ),
            })
            return


def _check_upload_html(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in UPLOAD_HTML_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "high",
                "category": "CWE-79",
                "title": "Stored XSS via user upload served as HTML",
                "description": (
                    f"User-uploaded content served with text/html Content-Type "
                    f"at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Serve user uploads with Content-Type: application/octet-stream "
                    "or Content-Disposition: attachment. Never serve user uploads "
                    "as text/html."
                ),
            })
            return


check_stored_xss_tool = function_tool(check_stored_xss)
