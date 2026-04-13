"""Web security vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_lines,

    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-601: URL Redirection to Untrusted Site (Open Redirect)
OPEN_REDIRECT_PATTERNS = [
    re.compile(r"redirect\s*\(\s*(?:request|req)\.(?:args|params|query|GET)", re.IGNORECASE),
    re.compile(r"(?:res|response)\.redirect\s*\(\s*(?:req|request)\.", re.IGNORECASE),
    re.compile(r"http\.Redirect\([^,]+,\s*[^,]+,\s*r\.", re.IGNORECASE),
    re.compile(r"Location.*(?:request|req|params|query|user|input)", re.IGNORECASE),
    re.compile(r"(?:redirect_to|return_to|next|url)\s*=\s*(?:request|req|params)", re.IGNORECASE),
]

SAFE_REDIRECT_PATTERNS = re.compile(
    r"(?:url_has_allowed_host|is_safe_url|validate_redirect|"
    r"allowed_hosts|whitelist|ALLOWED_REDIRECT|urlparse|"
    r"startswith\s*\(\s*['\"/])",
    re.IGNORECASE,
)

# CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
# Detection relies on matching cookie-setting calls and then checking context
# for HttpOnly via SAFE_COOKIE_PATTERNS (avoids broken negative lookaheads).
COOKIE_NO_HTTPONLY_PATTERNS = [
    re.compile(r"Set-Cookie:", re.IGNORECASE),
    re.compile(r"\.set_cookie\s*\(", re.IGNORECASE),
    re.compile(r"http\.SetCookie\s*\("),
    re.compile(r"(?:res|response)\.cookie\s*\(", re.IGNORECASE),
]

SAFE_COOKIE_PATTERNS = re.compile(
    r"(?:HttpOnly|httponly|http_only|httpOnly\s*[:=]\s*[Tt]rue)",
    re.IGNORECASE,
)

# CWE-384: Session Fixation
SESSION_FIXATION_PATTERNS = [
    re.compile(r"session\[.*\]\s*=.*(?:request|req|params|input)", re.IGNORECASE),
    re.compile(r"session\.(?:set|put|setAttribute)\s*\(.*(?:request|req|user)", re.IGNORECASE),
]

SAFE_SESSION_PATTERNS = re.compile(
    r"(?:regenerate|rotate|new_session|invalidate|session\.clear|flush)",
    re.IGNORECASE,
)

# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure'
COOKIE_NO_SECURE_PATTERNS = [
    re.compile(r"\.set_cookie\s*\("),
    re.compile(r"http\.SetCookie\s*\("),
    re.compile(r"(?:res|response)\.cookie\s*\("),
    re.compile(r"Set-Cookie:"),
]

SAFE_SECURE_PATTERNS = re.compile(
    r"(?:secure\s*[:=]\s*[Tt]rue|[;,]\s*[Ss]ecure\b|__Secure-|__Host-)",
    re.IGNORECASE,
)

# CWE-113: HTTP Response Splitting (CRLF Injection)
CRLF_PATTERNS = [
    re.compile(r"(?:header|Header)\s*\(.*(?:request|req|params|input|user)", re.IGNORECASE),
    re.compile(r"(?:add_header|set_header|setHeader|w\.Header\(\)\.Set)\s*\(.*(?:request|req|params|input)", re.IGNORECASE),
    re.compile(r"(?:response|res)\.headers?\[.*\]\s*=.*(?:request|req|params)", re.IGNORECASE),
]

SAFE_CRLF_PATTERNS = re.compile(
    r"(?:strip|replace|sanitize|escape|encode|\\r|\\n|CRLF)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")


def check_web_security(source_path: str) -> dict:
    """Check for web security vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of web security issues.
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
    """Analyze a file for web security patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_open_redirect(file_path, line, line_num, lines, findings)
        _check_cookie_httponly(file_path, line, line_num, lines, findings)
        _check_session_fixation(file_path, line, line_num, lines, findings)
        _check_cookie_secure(file_path, line, line_num, lines, findings)
        _check_crlf_injection(file_path, line, line_num, lines, findings)


def _check_open_redirect(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-601 open redirect."""
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_REDIRECT_PATTERNS.search(context):
        return
    for pattern in OPEN_REDIRECT_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.web_security.open_redirect",
                "category": "CWE-601",
                "title": "Open redirect vulnerability",
                "description": f"User-controlled redirect target at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate redirect URLs against an allowlist of trusted hosts",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "601"))
            return


def _check_cookie_httponly(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-1004 cookie without HttpOnly flag."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_COOKIE_PATTERNS.search(context):
        return
    for pattern in COOKIE_NO_HTTPONLY_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.web_security.cookie_no_httponly",
                "category": "CWE-1004",
                "title": "Cookie without HttpOnly flag",
                "description": f"Cookie set without HttpOnly protection at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Set HttpOnly flag on cookies to prevent XSS cookie theft",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1004"))
            return


def _check_session_fixation(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-384 session fixation."""
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SESSION_PATTERNS.search(context):
        return
    for pattern in SESSION_FIXATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.web_security.session_fixation",
                "category": "CWE-384",
                "title": "Potential session fixation",
                "description": f"Session populated from user input without regeneration at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Regenerate session ID after authentication or privilege change",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "384"))
            return


def _check_cookie_secure(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-614 cookie without Secure flag."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_SECURE_PATTERNS.search(context):
        return
    for pattern in COOKIE_NO_SECURE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.web_security.cookie_no_secure",
                "category": "CWE-614",
                "title": "Cookie without Secure flag",
                "description": f"Cookie set without Secure flag at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Set Secure flag on cookies to prevent transmission over HTTP",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "614"))
            return


def _check_crlf_injection(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-113 HTTP response splitting."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_CRLF_PATTERNS.search(context):
        return
    for pattern in CRLF_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.web_security.crlf_injection",
                "category": "CWE-113",
                "title": "HTTP response splitting (CRLF injection)",
                "description": f"User input in HTTP header at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Strip CR/LF characters from user input before placing in headers",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "113"))
            return


check_web_security_tool = function_tool(check_web_security)
