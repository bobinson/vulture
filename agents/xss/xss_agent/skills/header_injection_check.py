"""Header injection and missing security headers skill (CWE-113/CWE-644).

Detects HTTP header injection vectors and missing security headers that
enable or fail to mitigate XSS attacks.
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

# User input in response headers (CWE-113)
HEADER_INJECTION_PATTERNS = [
    re.compile(r"(?:set_header|add_header|Header\(\)\.Set|Header\(\)\.Add|setHeader|header\()\s*\([^)]*(?:request|req\.|input|user|body|query|param)", re.IGNORECASE),
    re.compile(r"Content-Disposition.*(?:request|req\.|input|user|query|param)", re.IGNORECASE),
    re.compile(r"Content-Type.*(?:request|req\.|input|user|query|param)", re.IGNORECASE),
    re.compile(r"Location.*(?:request|req\.|input|user|query|param)", re.IGNORECASE),
    re.compile(r"w\.Header\(\)\.Set\s*\([^)]*(?:r\.|request)", re.IGNORECASE),
]

# Weak or missing CSP (CWE-644)
WEAK_CSP_PATTERNS = [
    re.compile(r"Content-Security-Policy.*unsafe-inline", re.IGNORECASE),
    re.compile(r"Content-Security-Policy.*unsafe-eval", re.IGNORECASE),
    re.compile(r"Content-Security-Policy.*\*", re.IGNORECASE),
    re.compile(r"CSP.*unsafe-inline", re.IGNORECASE),
    re.compile(r"CSP.*unsafe-eval", re.IGNORECASE),
]

# Meta refresh with user-controlled URLs
META_REFRESH_PATTERNS = [
    re.compile(r"meta.*http-equiv\s*=\s*['\"]refresh['\"].*(?:request|req\.|input|user|query|param|\$|{)", re.IGNORECASE),
    re.compile(r"Refresh.*url=.*(?:request|req\.|input|user|query|param)", re.IGNORECASE),
]

SAFE_PATTERNS = re.compile(
    r"(?:sanitize|validate|escape|allowlist|whitelist|urlparse|"
    r"nonce-|strict-dynamic)",
    re.IGNORECASE,
)

COMMENT_LINE = COMMENT_INDICATORS
IMPORT_LINE = SAFE_IMPORT_LINE
SCANNER_DEF = SCANNER_DEF_LINE

# Security-relevant config files
CONFIG_EXTENSIONS = {
    ".py", ".js", ".ts", ".go", ".rb", ".php",
    ".yaml", ".yml", ".json", ".conf", ".ini",
    ".jsx", ".tsx",
}


def check_header_injection(source_path: str) -> dict:
    """Check for header injection and missing security headers (CWE-113/644).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of header injection vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if file_path.suffix not in CONFIG_EXTENSIONS:
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
        _check_header_injection(file_path, line, line_num, lines, findings)
        _check_weak_csp(file_path, line, line_num, lines, findings)
        _check_meta_refresh(file_path, line, line_num, lines, findings)


def _has_safe_context(lines: list[str], line_num: int, radius: int = 5) -> bool:
    start = max(0, line_num - 1 - radius)
    end = min(len(lines), line_num + radius)
    context = "\n".join(lines[start:end])
    return bool(SAFE_PATTERNS.search(context))


def _check_header_injection(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in HEADER_INJECTION_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "high",
                "category": "CWE-113",
                "title": "HTTP header injection via user input",
                "description": (
                    f"User input included in HTTP response header "
                    f"at line {line_num}. An attacker can inject CRLF "
                    f"characters to manipulate headers or inject content."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Validate and sanitize all user input before including "
                    "in HTTP headers. Strip CR/LF characters. Use framework "
                    "header-setting methods that auto-encode values."
                ),
            })
            return


def _check_weak_csp(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in WEAK_CSP_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "medium",
                "category": "CWE-644",
                "title": "Weak Content-Security-Policy allows XSS",
                "description": (
                    f"CSP contains unsafe-inline, unsafe-eval, or wildcard "
                    f"at line {line_num}. This weakens XSS protections."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Remove unsafe-inline and unsafe-eval from CSP. Use "
                    "nonce-based or hash-based CSP. Replace wildcards with "
                    "specific domain allowlists."
                ),
            })
            return


def _check_meta_refresh(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    for pattern in META_REFRESH_PATTERNS:
        if pattern.search(line):
            if _has_safe_context(lines, line_num):
                return
            findings.append({
                "severity": "high",
                "category": "CWE-113",
                "title": "Meta refresh with user-controlled URL",
                "description": (
                    f"Meta refresh or Refresh header uses user-controlled "
                    f"URL at line {line_num}."
                ),
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": (
                    "Validate redirect URLs against an allowlist. Never use "
                    "user input directly in meta refresh or Refresh headers."
                ),
            })
            return


check_header_injection_tool = function_tool(check_header_injection)
