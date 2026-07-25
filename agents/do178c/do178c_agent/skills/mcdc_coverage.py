"""DO-178C MC/DC coverage gap detection: compound boolean conditions."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# Compound boolean: 2+ conditions joined by &&/||/and/or inside
# if/while/elif/else if/assert statements.
_COMPOUND_STMT = re.compile(
    r"^\s*(?:if|elif|else\s+if|while|assert)\s*[\(]?"
    r".*(?:&&|\|\||(?<!\w)and(?!\w)|(?<!\w)or(?!\w))"
)

# Ternary with compound condition: `(a && b) ? x : y`
_COMPOUND_TERNARY = re.compile(
    r"(?:&&|\|\|).*\?\s*[^:]+\s*:"
)

# MC/DC coverage marker comment within context lines above.
_MCDC_MARKER = re.compile(
    r"(?:MCDC|MC/DC)[\s\-_:]*(?:verified|covered|tested|ok)",
    re.IGNORECASE,
)


def check_mcdc_coverage(source_path: str) -> dict:
    """Check for compound boolean conditions lacking MC/DC coverage evidence.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Scan a single file for uncovered compound conditions."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    line_list = list(lines)
    for line_num, line in enumerate(line_list, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        _check_compound(file_path, line, line_num, line_list, findings)


def _check_compound(
    file_path: Path, line: str, line_num: int,
    lines: list[str], findings: list[dict],
) -> None:
    """Detect compound boolean without MC/DC marker."""
    is_compound = _COMPOUND_STMT.search(line) or _COMPOUND_TERNARY.search(line)
    if not is_compound:
        return
    if _has_mcdc_marker(lines, line_num):
        return
    findings.append({
        "severity": "high",
        "check_id": "do178c.mcdc.compound_uncovered",
        "category": "mcdc_coverage",
        "title": "Compound condition without MC/DC coverage",
        "description": f"Compound boolean at line {line_num} lacks MC/DC coverage evidence",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Add MC/DC test cases and annotate with coverage marker",
        "code_snippet": extract_snippet(lines, line_num),
    })


def _has_mcdc_marker(lines: list[str], line_num: int) -> bool:
    """Check 3 lines above for an MC/DC coverage marker comment."""
    start = max(0, line_num - 1 - 3)
    end = line_num - 1
    return any(_MCDC_MARKER.search(lines[i]) for i in range(start, end))


check_mcdc_coverage_tool = function_tool(check_mcdc_coverage)
