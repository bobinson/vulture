"""PW.9 - Secure defaults audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

_HARDCODED_CRED_PATTERNS = [
    re.compile(r"""password\s*=\s*["'][^"']{3,}["']""", re.IGNORECASE),
    re.compile(r"""api_key\s*=\s*["'][^"']{3,}["']""", re.IGNORECASE),
    re.compile(r"""secret\s*=\s*["'][^"']{3,}["']""", re.IGNORECASE),
]

_DEBUG_PATTERNS = [
    re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"""debug\s*:\s*["']?true["']?""", re.IGNORECASE),
]

_PERMISSIVE_CORS = re.compile(
    r"""Access-Control-Allow-Origin.*\*|cors.*origin.*\*|AllowOrigins.*\*""",
    re.IGNORECASE,
)

_COMMENT_LINE = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
_SAFE_IMPORT = re.compile(r"^\s*(?:from|import)\s")
_SCANNER_DEF = re.compile(r"re\.compile\(|=\s*\[?\s*re\.", re.IGNORECASE)
_ENV_READ_PATTERN = re.compile(r"os\.(?:environ|getenv)|env\.\w+|process\.env\.", re.IGNORECASE)


def check_secure_defaults(source_path: str) -> dict:
    """Check for secure default configurations (PW.9).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
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
    """Analyze a file for insecure defaults."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if _COMMENT_LINE.match(line):
            continue
        if _SAFE_IMPORT.match(line):
            continue
        if _SCANNER_DEF.search(line):
            continue
        if _ENV_READ_PATTERN.search(line):
            continue

        _check_hardcoded_creds(file_path, lines, line, line_num, findings)
        _check_debug_mode(file_path, lines, line, line_num, findings)
        _check_permissive_cors(file_path, lines, line, line_num, findings)


def _check_hardcoded_creds(
    file_path: Path, lines: list[str], line: str, line_num: int, findings: list[dict],
) -> None:
    for pattern in _HARDCODED_CRED_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "critical",
                "check_id": "ssdf.pw9.hardcoded_credentials",
                "category": "PW-produce-well-secured-software",
                "title": "Hardcoded credentials detected",
                "description": f"Possible hardcoded credential at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use environment variables or a secrets manager for credentials",
                "code_snippet": extract_snippet(lines, line_num),
            })
            return


def _check_debug_mode(
    file_path: Path, lines: list[str], line: str, line_num: int, findings: list[dict],
) -> None:
    for pattern in _DEBUG_PATTERNS:
        if pattern.search(line):
            findings.append({
                "severity": "medium",
                "check_id": "ssdf.pw9.debug_enabled",
                "category": "PW-produce-well-secured-software",
                "title": "Debug mode enabled in configuration",
                "description": f"Debug mode enabled at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Ensure debug mode is disabled in production configurations",
                "code_snippet": extract_snippet(lines, line_num),
            })
            return


def _check_permissive_cors(
    file_path: Path, lines: list[str], line: str, line_num: int, findings: list[dict],
) -> None:
    if _PERMISSIVE_CORS.search(line):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.pw9.permissive_cors",
            "category": "PW-produce-well-secured-software",
            "title": "Permissive CORS configuration detected",
            "description": f"Wildcard CORS origin at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Restrict CORS to specific trusted origins instead of wildcard",
            "code_snippet": extract_snippet(lines, line_num),
        })


check_secure_defaults_tool = function_tool(check_secure_defaults)
