"""Information exposure vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

# CWE-209: Error message information disclosure
ERROR_DISCLOSURE_PATTERNS = [
    re.compile(r"traceback\.print_exc\s*\("),
    re.compile(r"traceback\.format_exc\s*\("),
    re.compile(r"\.printStackTrace\s*\("),  # Java
    re.compile(r"debug\.PrintStack\s*\("),  # Go
    re.compile(r"return\s+.*(?:traceback|stacktrace|stack_trace)", re.IGNORECASE),
]

# CWE-532: Information through log files
LOG_SENSITIVE_PATTERNS = [
    re.compile(r"(?:log(?:ger)?|print|fmt\.Print)\w*\(.*(?:password|passwd|secret|token|api_key|apikey)", re.IGNORECASE),
    re.compile(r"logging\.(?:debug|info|warning|error)\(.*(?:password|secret|token|api_key)", re.IGNORECASE),
    re.compile(r"console\.log\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
    re.compile(r"log\.(?:Info|Debug|Warn|Error)\w*\(.*(?:password|secret|token|apiKey)", re.IGNORECASE),
]

# CWE-200: Exposure of sensitive info
SENSITIVE_RESPONSE_PATTERNS = [
    re.compile(r"(?:json|JSON)\w*\(.*(?:internal_path|db_host|database_url|dsn)", re.IGNORECASE),
    re.compile(r"(?:Response|response|w\.Write)\(.*(?:stack|internal|debug_info)", re.IGNORECASE),
]

# CWE-312: Cleartext storage of sensitive info
CLEARTEXT_STORAGE_PATTERNS = [
    re.compile(r"(?:password|secret|token|api_key)\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE),
    re.compile(r"(?:set|put|store|save)\w*\(.*(?:password|secret|token).*,\s*[\"']", re.IGNORECASE),
]
# Exclude safe patterns: hashing, env vars, config constants
SAFE_STORAGE = re.compile(
    r"\b(?:hash|bcrypt|encrypt|sha256|os\.(?:environ|getenv)|ENV\[|config\.|PLACEHOLDER|example|changeme|xxx)\b",
    re.IGNORECASE,
)

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
IMPORT_LINE = re.compile(r"^\s*(?:import|from)\s+")
STRING_ONLY = re.compile(r"^\s*[\"']")


def check_information_exposure(source_path: str) -> dict:
    """Check for information exposure vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of information exposure issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for information exposure issues."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        _check_error_disclosure(file_path, line, line_num, findings, is_test=is_test)
        _check_log_sensitive(file_path, line, line_num, findings, is_test=is_test)
        _check_cleartext_storage(file_path, line, line_num, findings, is_test=is_test)


def _check_error_disclosure(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool,
) -> None:
    """Check for error message information disclosure (CWE-209)."""
    for pattern in ERROR_DISCLOSURE_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "low" if is_test else "high",
            "category": "CWE-209",
            "title": "Error message information disclosure",
            "description": f"Stack trace or error details exposed at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Return generic error messages; log detailed errors server-side only",
        })
        return


def _check_log_sensitive(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool,
) -> None:
    """Check for sensitive data in log output (CWE-532)."""
    for pattern in LOG_SENSITIVE_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "medium" if is_test else "critical",
            "category": "CWE-532",
            "title": "Sensitive data written to log",
            "description": f"Potential password/token/secret logged at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Never log sensitive data; use redaction or masked output",
        })
        return


def _check_cleartext_storage(
    file_path: Path, line: str, line_num: int, findings: list[dict], *, is_test: bool,
) -> None:
    """Check for cleartext storage of sensitive info (CWE-312)."""
    if SAFE_STORAGE.search(line):
        return
    for pattern in CLEARTEXT_STORAGE_PATTERNS:
        if not pattern.search(line):
            continue
        findings.append({
            "severity": "medium" if is_test else "critical",
            "category": "CWE-312",
            "title": "Cleartext storage of sensitive information",
            "description": f"Sensitive value stored in cleartext at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use environment variables, vaults, or encryption for sensitive data",
        })
        return


check_information_exposure_tool = function_tool(check_information_exposure)
