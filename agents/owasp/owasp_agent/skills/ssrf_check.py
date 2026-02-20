"""SSRF detection skill (A10)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

SSRF_PATTERNS = [
    re.compile(r"requests\.(?:get|post|put|delete|head|patch)\(\s*[a-zA-Z_]"),
    re.compile(r"urllib\.request\.urlopen\(\s*[a-zA-Z_]"),
    re.compile(r"http\.(?:Get|Post|Put|Delete)\(\s*[a-zA-Z_]"),
    re.compile(r"httpx\.(?:get|post|put|delete)\(\s*[a-zA-Z_]"),
]

COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")
# URL concatenation with literal path — likely internal API call, not SSRF
SAFE_URL_CONCAT = re.compile(r'http\.(?:Get|Post|Put|Delete)\(\s*\w+\s*\+\s*"/')


def check_ssrf(source_path: str) -> dict:
    """Check for server-side request forgery vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of SSRF issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path):
            continue
        _analyze_file(file_path, findings, is_test=is_test_file(file_path))

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict], *, is_test: bool) -> None:
    """Analyze a file for SSRF patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    for line_num, line in enumerate(content.splitlines(), start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if any(p.search(line) for p in SSRF_PATTERNS) and not SAFE_URL_CONCAT.search(line):
            findings.append({
                "severity": "medium" if is_test else "high",
                "category": "A10-ssrf",
                "title": "Potential SSRF vulnerability",
                "description": f"HTTP request with variable URL at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate and whitelist URLs before making requests",
            })


check_ssrf_tool = function_tool(check_ssrf)
