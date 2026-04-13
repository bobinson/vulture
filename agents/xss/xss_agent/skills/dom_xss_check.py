"""DOM-based XSS detection skill (CWE-79).

Detects JavaScript/TypeScript source-to-sink data flows where user-controlled
DOM sources reach dangerous sinks without sanitization.
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

# DOM sources — user-controllable input in the browser
SOURCE_PATTERNS = [
    re.compile(r"location\.(?:hash|search|href|pathname|protocol)"),
    re.compile(r"document\.(?:URL|referrer|documentURI)"),
    re.compile(r"window\.name"),
    re.compile(r"(?:addEventListener|on)\s*\(\s*['\"]message['\"]"),  # postMessage
    re.compile(r"URLSearchParams\s*\("),
    re.compile(r"new\s+URL\s*\([^)]*location"),
]

# DOM sinks — dangerous output points
SINK_PATTERNS = [
    re.compile(r"\.innerHTML\s*="),
    re.compile(r"\.outerHTML\s*="),
    re.compile(r"document\.write\s*\("),
    re.compile(r"document\.writeln\s*\("),
    re.compile(r"(?<!\w)eval\s*\("),
    re.compile(r"setTimeout\s*\(\s*[^,)]*(?:location|document|window|hash|search|href|name)"),
    re.compile(r"setInterval\s*\(\s*[^,)]*(?:location|document|window|hash|search|href|name)"),
    re.compile(r"new\s+Function\s*\("),
    re.compile(r"\$\([^)]*\)\.html\s*\("),               # jQuery .html()
    re.compile(r"insertAdjacentHTML\s*\("),
    re.compile(r"v-html\s*="),                            # Vue v-html
    re.compile(r"\[innerHTML\]\s*="),                     # Angular [innerHTML]
]

# Combined: source feeding directly into sink on same line
SOURCE_TO_SINK_PATTERNS = [
    re.compile(r"\.innerHTML\s*=.*location\.(?:hash|search|href)"),
    re.compile(r"\.innerHTML\s*=.*document\.(?:URL|referrer)"),
    re.compile(r"\.innerHTML\s*=.*window\.name"),
    re.compile(r"document\.write\s*\(.*location\."),
    re.compile(r"eval\s*\(.*location\."),
    re.compile(r"\$\([^)]*\)\.html\s*\(.*location\."),
    re.compile(r"insertAdjacentHTML\s*\(.*location\."),
]

SAFE_PATTERNS = re.compile(
    r"(?:textContent|innerText|DOMPurify\.sanitize|createTextNode|"
    r"encodeURIComponent|escapeHtml|sanitize\()",
    re.IGNORECASE,
)

COMMENT_LINE = COMMENT_INDICATORS
IMPORT_LINE = SAFE_IMPORT_LINE
SCANNER_DEF = SCANNER_DEF_LINE

# Only scan JS/TS files for DOM XSS
JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue", ".svelte"}


def check_dom_xss(source_path: str) -> dict:
    """Check for DOM-based XSS vulnerabilities (CWE-79).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of DOM XSS vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if file_path.suffix not in JS_TS_EXTENSIONS:
            continue
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
        _check_direct_flow(file_path, line, line_num, lines, findings)
        _check_source_near_sink(file_path, line, line_num, lines, findings)


def _has_safe_context(lines: list[str], line_num: int, radius: int = 5) -> bool:
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    context = "\n".join(lines[start:end])
    return bool(SAFE_PATTERNS.search(context))


def _check_direct_flow(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Check for source→sink on the same line."""
    for pattern in SOURCE_TO_SINK_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "critical",
                "category": "CWE-79",
                "title": "DOM XSS via direct source-to-sink flow",
                "description": (
                    f"User-controlled DOM source flows directly into a "
                    f"dangerous sink at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Sanitize the DOM source with DOMPurify.sanitize() before "
                    "assigning to innerHTML, or use textContent/innerText instead."
                ),
            })
            return


def _has_source_nearby(lines: list[str], line_num: int, radius: int = 10) -> bool:
    start = max(0, line_num - 1 - radius)
    end = line_num - 1
    context = "\n".join(lines[start:end])
    return any(p.search(context) for p in SOURCE_PATTERNS)


def _check_source_near_sink(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Check for a sink with a source within ±10 lines."""
    for pattern in SINK_PATTERNS:
        if pattern.search(line):
            if not _has_source_nearby(lines, line_num):
                return
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "high",
                "category": "CWE-79",
                "title": "DOM XSS via source near dangerous sink",
                "description": (
                    f"A DOM source (location, document.URL, etc.) was found "
                    f"near a dangerous sink at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Sanitize input with DOMPurify.sanitize() before passing "
                    "to innerHTML/eval/document.write. Prefer textContent or "
                    "createTextNode for safe DOM updates."
                ),
            })
            return


check_dom_xss_tool = function_tool(check_dom_xss)
