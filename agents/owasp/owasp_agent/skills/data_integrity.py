"""Data integrity / unsafe deserialization detection skill (A08)."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.snippet import extract_snippet

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SAFE_IMPORT_LINE,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

UNSAFE_DESER_PATTERNS = [
    re.compile(r"pickle\.loads?\("),
    re.compile(r"marshal\.loads?\("),
    re.compile(r"shelve\.open\("),
    re.compile(r"jsonpickle\.decode"),
    re.compile(r"dill\.loads?\("),
]

UNSAFE_YAML_PATTERN = re.compile(r"yaml\.load\(")
SAFE_YAML_PATTERN = re.compile(r"yaml\.load\(.*Loader\s*=\s*SafeLoader|yaml\.safe_load")


def check_data_integrity(source_path: str) -> dict:
    """Check for unsafe deserialization and data integrity issues.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of data integrity issues.
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
    """Analyze a file for unsafe deserialization patterns."""
    content = read_file_safe(file_path)
    if content is None:
        return

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if SAFE_IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_deserialization(file_path, line, line_num, findings, lines)
        _check_yaml(file_path, line, line_num, findings, lines)


def _check_deserialization(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check a line for unsafe deserialization patterns."""
    if any(p.search(line) for p in UNSAFE_DESER_PATTERNS):
        finding = {
            "severity": "critical",
            "check_id": "owasp.integrity.unsafe_deserialization",
            "category": "A08-data-integrity",
            "title": "Unsafe deserialization",
            "description": f"Unsafe deserialization at line {line_num}",
            "file_path": str(file_path),
            "line_start": line_num,
            "line_end": line_num,
            "recommendation": "Use safe serialization formats like JSON",
        }
        finding["code_snippet"] = extract_snippet(lines, line_num)
        findings.append(finding)


def _check_yaml(
    file_path: Path, line: str, line_num: int, findings: list[dict],
    lines: list[str],
) -> None:
    """Check a line for unsafe YAML loading."""
    if not UNSAFE_YAML_PATTERN.search(line):
        return
    if SAFE_YAML_PATTERN.search(line):
        return
    finding = {
        "severity": "critical",
        "check_id": "owasp.integrity.unsafe_yaml",
        "category": "A08-data-integrity",
        "title": "Unsafe YAML deserialization",
        "description": f"Unsafe yaml.load at line {line_num}",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use yaml.safe_load() or pass Loader=SafeLoader",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(finding)


check_data_integrity_tool = function_tool(check_data_integrity)
