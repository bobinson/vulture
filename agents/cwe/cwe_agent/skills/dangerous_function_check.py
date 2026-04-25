"""Dedicated skill for CWE-676 and CWE-242 (dangerous functions).

Flags calls to intrinsically unsafe functions (unbounded string handling,
shell-via-string) that CWE calls out as risky-by-design. Suppresses
findings when a bounded/safe alternative appears in the 5-line preceding
window (e.g., ``strncpy`` alongside ``strcpy`` in a migration, or
``subprocess.run([...])`` instead of ``os.system``).
"""
import re
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-242 "Use of Inherently Dangerous Function": calls that are unsafe
# by design with no safe alternative, e.g. gets() which has no length
# bound and was removed from C11 specifically for this reason.
_INHERENTLY_DANGEROUS_FN = re.compile(r"\bgets\s*\(")

# CWE-676 string-handling: unbounded copy/scan functions that HAVE safe
# alternatives (strncpy, snprintf, etc.).
_STRING_FN = re.compile(
    r"\b(strcpy|strcat|sprintf|vsprintf|scanf|sscanf)\s*\("
)

# CWE-676 shell/code-execution: dangerous command/eval APIs with safer
# alternatives (subprocess.run([...]), ast.literal_eval, etc.).
_EXEC_FN = re.compile(
    r"\b(system|popen|eval|exec)\s*\("
    r"|Runtime\.getRuntime\(\)\.exec\s*\("
    r"|\bos\.system\s*\("
    r"|\bos\.popen\s*\("
)

# Safe-context: a bounded/safe alternative in the 5-line preceding window.
_SAFE_CONTEXT = re.compile(
    r"\bstrncpy\b"
    r"|\bstrlcpy\b"
    r"|\bsnprintf\b"
    r"|\bsubprocess\.run\s*\(\s*\["
    r"|\bshlex\.quote\b"
    r"|\bhtml\.escape\b"
    r"|\bast\.literal_eval\b"
)


def _is_safe_context(lines: tuple[str, ...], lineno: int) -> bool:
    """Return True if a safe alternative is present in the prior 5 lines."""
    start = max(0, lineno - 6)
    end = lineno
    window = "\n".join(lines[start:end])
    return _SAFE_CONTEXT.search(window) is not None


def _classify_match(line: str) -> tuple[str, str] | None:
    """Return (cwe_id, severity) for a dangerous-function match on this line."""
    if _INHERENTLY_DANGEROUS_FN.search(line):
        return ("242", "critical")
    if _EXEC_FN.search(line):
        return ("676", "critical")
    if _STRING_FN.search(line):
        return ("676", "high")
    return None


def _build_finding(
    cwe_id: str,
    severity: str,
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single dangerous-function finding dict."""
    finding = {
        "severity": severity,
        "check_id": f"cwe.dangerous_function.cwe_{cwe_id}",
        "category": f"CWE-{cwe_id}",
        "title": "Use of Inherently Dangerous Function",
        "description": (
            f"Call to an intrinsically unsafe function at line {lineno}. "
            f"CWE-676 marks this API as risky-by-design."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Replace with a bounded/safe alternative: strncpy/snprintf "
            "for string handling, subprocess.run([...]) without shell=True "
            "for external commands, ast.literal_eval for parsing."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, cwe_id)


def _scan_line(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a single line for dangerous-function calls."""
    # Pure comment lines (Python `#`, Go/JS/Java/C++ `//`, C-style `/*` or `*`,
    # HTML `<!--`) cannot themselves invoke dangerous APIs — the matched
    # tokens are documentation. This prevents the detector from flagging
    # security-fix commentary that mentions os.system / strcpy / eval by
    # name. (VLT-4768 hardening.)
    if COMMENT_INDICATORS.match(line):
        return
    classification = _classify_match(line)
    if classification is None:
        return
    if _is_safe_context(lines, lineno):
        return
    cwe_id, severity = classification
    findings.append(_build_finding(cwe_id, severity, file_path, lineno, lines))


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan each one for dangerous-function candidates."""
    if is_generated_file(file_path) or is_test_file(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_line(line, lineno, path_str, lines, findings)


def check_dangerous_function(source_path: str) -> dict[str, Any]:
    """Scan source files for dangerous-function calls (CWE-676 / CWE-242)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_dangerous_function_tool = function_tool(check_dangerous_function)
