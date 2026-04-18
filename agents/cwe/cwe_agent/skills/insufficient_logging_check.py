"""Dedicated skill for CWE-778 (insufficient logging).

Flags exception handlers (``catch`` / ``except`` blocks) whose body does
not emit a logging call within the first five non-blank lines. Failing
to log swallowed exceptions hides evidence needed for incident response.
"""
import re
from pathlib import Path
from typing import Any

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import collect_handler_body, extract_snippet

from cwe_agent.catalog import enrich_finding

# Language gate — logging conventions differ and the regex targets these.
_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".java", ".js", ".ts", ".go", ".cs", ".rb", ".php",
})

# Python except header (we need next lines of body).
_PY_EXCEPT = re.compile(r"^\s*except\b[^:]*:\s*$")

# Same-line Python except with a trivial body (pass / None / etc.).
_PY_EXCEPT_INLINE = re.compile(r"^\s*except\b[^:]*:\s*(?:pass|None|\.\.\.)\s*$")

# Java/JS/C#/Go/PHP catch clause — may be single-line or open a block.
_CATCH_LINE = re.compile(r"\bcatch\s*\([^)]*\)\s*\{")

# Single-line catch with empty/near-empty body: `catch (...) {}` or `catch (...) { ; }`.
_CATCH_EMPTY = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*[;]?\s*\}")

# Logging-call regex — anchors the handler-body test.
_LOG_CALL = re.compile(
    r"\blog\."
    r"|\blogger\."
    r"|\blogging\."
    r"|\bslf4j\b"
    r"|\bconsole\.(?:error|warn)\s*\("
    r"|\bsyslog\b"
    r"|\bLOG_[A-Z]"
    r"|\bfmt\.Fprintf\s*\(\s*os\.Stderr"
)


def _body_has_logging(body_lines: list[str]) -> bool:
    """Return True if any line in the handler body invokes a logging call."""
    for line in body_lines:
        if _LOG_CALL.search(line):
            return True
    return False


def _build_finding(
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single CWE-778 finding dict."""
    finding = {
        "severity": "medium",
        "check_id": "cwe.insufficient_logging.cwe_778",
        "category": "CWE-778",
        "title": "Insufficient Logging",
        "description": (
            f"Exception handler at line {lineno} does not log the error. "
            f"Swallowed exceptions break incident-response workflows."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Emit a logging call (e.g., ``logger.error(e)`` / ``logging.exception``) "
            "within the handler body so diagnostic evidence is preserved."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, "778")


def _scan_py_except(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a Python ``except`` header for an unlogged handler body."""
    if _PY_EXCEPT_INLINE.search(line):
        findings.append(_build_finding(file_path, lineno, lines))
        return
    if not _PY_EXCEPT.search(line):
        return
    body = collect_handler_body(lines, lineno)  # lineno is 1-based → start at index lineno
    if not _body_has_logging(body):
        findings.append(_build_finding(file_path, lineno, lines))


def _scan_catch(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a Java/JS-style ``catch`` clause for an unlogged handler body."""
    if _CATCH_EMPTY.search(line):
        findings.append(_build_finding(file_path, lineno, lines))
        return
    if not _CATCH_LINE.search(line):
        return
    body = collect_handler_body(lines, lineno)
    if not _body_has_logging(body):
        findings.append(_build_finding(file_path, lineno, lines))


def _should_scan(file_path: Path) -> bool:
    """Return True if file passes language-gate and non-generated/test filters."""
    if file_path.suffix.lower() not in _LANG_EXTENSIONS:
        return False
    return not (is_generated_file(file_path) or is_test_file(file_path))


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan each one for un-logged exception handlers."""
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_py_except(line, lineno, path_str, lines, findings)
        _scan_catch(line, lineno, path_str, lines, findings)


def check_insufficient_logging(source_path: str) -> dict[str, Any]:
    """Scan source files for silent exception handlers (CWE-778)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_insufficient_logging_tool = function_tool(check_insufficient_logging)
