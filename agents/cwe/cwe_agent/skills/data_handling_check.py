"""Data handling and type safety vulnerability detection skill."""

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

# CWE-134: Use of Externally-Controlled Format String
FORMAT_STRING_PATTERNS = [
    re.compile(r"printf\s*\(\s*(?:argv|args|request|req|params|input|user)", re.IGNORECASE),
    re.compile(r"sprintf\s*\(\s*\w+\s*,\s*(?:argv|args|request|params|user)", re.IGNORECASE),
    re.compile(r"fprintf\s*\(\s*\w+\s*,\s*(?:argv|args|request|params)", re.IGNORECASE),
    re.compile(r"syslog\s*\(\s*\w+\s*,\s*(?:argv|args|request|user)", re.IGNORECASE),
    re.compile(r"fmt\.(?:Printf|Sprintf|Fprintf)\s*\(\s*(?:r\.|req\.|request|params|input)", re.IGNORECASE),
    re.compile(r"logging\.(?:info|debug|warning|error)\s*\(\s*(?:request|req|user)", re.IGNORECASE),
]

SAFE_FORMAT_PATTERNS = re.compile(
    r"(?:%[dsifu]|%v|%s.*(?:sanitize|escape|validate)|format\s*\()",
    re.IGNORECASE,
)

# CWE-681: Incorrect Conversion between Numeric Types
NUMERIC_CONVERSION_PATTERNS = [
    re.compile(r"(?:int|int8|int16|int32|uint8|uint16|uint32)\s*\(\s*\w+\s*\)"),  # Go narrow cast
    re.compile(r"\((?:byte|short|char)\)\s*\w+"),  # Java narrowing cast
    re.compile(r"(?:int|float)\s*\(\s*(?:request|req|params|input|user)", re.IGNORECASE),
    re.compile(r"(?:atoi|atol|strtol)\s*\([^)]*(?:argv|args|input|buf)", re.IGNORECASE),
]

SAFE_CONVERSION_PATTERNS = re.compile(
    r"(?:try|catch|except|if.*err|overflow|bounds|range|clamp|saturating)",
    re.IGNORECASE,
)

# CWE-704: Incorrect Type Conversion or Cast
UNSAFE_CAST_PATTERNS = [
    re.compile(r"\(\s*\*\s*\w+\s*\)\s*\(\s*(?:unsafe\.Pointer|void\s*\*)"),  # Go/C unsafe cast
    re.compile(r"reinterpret_cast\s*<"),  # C++
    re.compile(r"\(\s*(?:void|char)\s*\*\s*\)\s*\w+"),  # C void* cast
    re.compile(r"(?:as\s+any|<any>)\s*\w+"),  # TypeScript any cast
]

# CWE-838: Inappropriate Encoding for Output Context
ENCODING_MISMATCH_PATTERNS = [
    re.compile(r"\.encode\s*\(\s*['\"](?:ascii|latin-?1|iso-8859)['\"]", re.IGNORECASE),
    re.compile(r"\.decode\s*\(\s*['\"](?:ascii|latin-?1|iso-8859)['\"].*errors\s*=\s*['\"]ignore", re.IGNORECASE),
    re.compile(r"(?:innerHTML|textContent|\.html\()\s*.*\.(?:encode|decode)", re.IGNORECASE),
    re.compile(r"(?:write|send|response)\s*\(.*\.encode\s*\(\s*['\"]ascii", re.IGNORECASE),
]

SAFE_ENCODING_PATTERNS = re.compile(
    r"(?:utf-?8|unicode|errors\s*=\s*['\"](?:replace|strict)|html\.escape|markupsafe)",
    re.IGNORECASE,
)

# CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
PROTOTYPE_POLLUTION_PATTERNS = [
    re.compile(r"\[\s*(?:__proto__|constructor|prototype)\s*\]"),
    re.compile(r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:req|request|params|body|input)", re.IGNORECASE),
    re.compile(r"(?:merge|extend|assign|defaults)\s*\([^)]*(?:req|request|body|params|input)", re.IGNORECASE),
    re.compile(r"for\s*\(\s*(?:let|var|const)\s+\w+\s+in\s+(?:req|request|body|params|input)", re.IGNORECASE),
    re.compile(r"\{\s*\.\.\.(?:req|request|body|params|input)", re.IGNORECASE),
]

SAFE_PROTOTYPE_PATTERNS = re.compile(
    r"(?:Object\.create\s*\(\s*null|hasOwnProperty|Object\.keys|JSON\.parse|"
    r"(?:joi|yup|zod|ajv|schema|validate))",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")


def check_data_handling(source_path: str) -> dict:
    """Check for data handling and type safety vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of data handling issues.
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
    """Analyze a file for data handling issues."""
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
        _check_format_string(file_path, line, line_num, lines, findings)
        _check_numeric_conversion(file_path, line, line_num, lines, findings)
        _check_unsafe_cast(file_path, line, line_num, lines, findings)
        _check_encoding_mismatch(file_path, line, line_num, lines, findings)
        _check_prototype_pollution(file_path, line, line_num, lines, findings)


def _check_format_string(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-134 externally-controlled format string."""
    if SAFE_FORMAT_PATTERNS.search(line):
        return
    for pattern in FORMAT_STRING_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.data_handling.format_string",
                "category": "CWE-134",
                "title": "Externally-controlled format string",
                "description": f"User input used as format string at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Never pass user input as format string; use it as an argument instead",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "134"))
            return


def _check_numeric_conversion(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-681 incorrect numeric conversion."""
    context_start = max(0, line_num - 3)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_CONVERSION_PATTERNS.search(context):
        return
    for pattern in NUMERIC_CONVERSION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.data_handling.numeric_conversion",
                "category": "CWE-681",
                "title": "Potentially unsafe numeric type conversion",
                "description": f"Narrowing or unchecked numeric conversion at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Check for overflow/truncation before narrowing casts",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "681"))
            return


def _check_unsafe_cast(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-704 incorrect type conversion or cast."""
    for pattern in UNSAFE_CAST_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.data_handling.unsafe_cast",
                "category": "CWE-704",
                "title": "Unsafe type cast",
                "description": f"Unsafe or unvalidated type cast at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Avoid unsafe casts; use type-safe conversions or validate before casting",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "704"))
            return


def _check_encoding_mismatch(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-838 inappropriate encoding for output."""
    if SAFE_ENCODING_PATTERNS.search(line):
        return
    for pattern in ENCODING_MISMATCH_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "medium",
                "check_id": "cwe.data_handling.encoding_mismatch",
                "category": "CWE-838",
                "title": "Inappropriate encoding for output context",
                "description": f"Encoding mismatch or lossy encoding at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use UTF-8 encoding; avoid lossy encoding with errors='ignore'",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "838"))
            return


def _check_prototype_pollution(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-1321 prototype pollution."""
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_PROTOTYPE_PATTERNS.search(context):
        return
    for pattern in PROTOTYPE_POLLUTION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.data_handling.prototype_pollution",
                "category": "CWE-1321",
                "title": "Prototype pollution vulnerability",
                "description": f"User input merged into object without prototype protection at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use Object.create(null), validate keys, or use a schema validator",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "1321"))
            return


check_data_handling_tool = function_tool(check_data_handling)
