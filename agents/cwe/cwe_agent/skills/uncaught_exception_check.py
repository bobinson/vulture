"""Dedicated skill for CWE-248 (uncaught exception).

Flags two specific uncaught-exception antipatterns:

* Java method declarations that declare ``throws Exception`` (generic
  checked exception, not a specific subclass) — calling code cannot
  distinguish failure modes.
* Python handlers that catch ``Exception`` broadly and either ``pass``
  silently or bare-re-raise without wrapping in a domain-specific error.

Suppressed when the handler body wraps/re-raises with chaining
(``raise X(...) from e``, ``__cause__``, or ``throw new X``).
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

# Language gate — Java and Python patterns only.
_LANG_EXTENSIONS: frozenset[str] = frozenset({".java", ".py"})

# Java: method decl with generic ``throws Exception``.
_JAVA_THROWS = re.compile(r"\bthrows\s+Exception\b")

# Python: ``except Exception`` header (generic catch-all).
_PY_EXCEPT_EXCEPTION = re.compile(r"^\s*except\s+Exception\b")

# Bare-pass / bare-re-raise bodies that signal uncaught-exception misuse.
_BARE_PASS = re.compile(r"^\s*pass\s*$")
_BARE_RAISE = re.compile(r"^\s*raise\s*$")

# Safe-context: re-raise with wrapping, chaining, or a new wrapped exception.
_SAFE_CONTEXT = re.compile(
    r"\braise\s+\w+(?:Error|Exception)\s*\("
    r"|\bthrow\s+new\s+\w+Exception\s*\("
    r"|\bfrom\s+\w+"
    r"|\bchain\s*\("
    r"|__cause__"
)


def _body_is_safe(body_lines: list[str]) -> bool:
    """Return True if any body line wraps/re-raises with chaining."""
    for line in body_lines:
        if _SAFE_CONTEXT.search(line):
            return True
    return False


def _build_finding(
    file_path: str,
    lineno: int,
    lines: tuple[str, ...],
) -> dict[str, Any]:
    """Construct a single CWE-248 finding dict."""
    finding = {
        "severity": "medium",
        "check_id": "cwe.uncaught_exception.cwe_248",
        "category": "CWE-248",
        "title": "Uncaught Exception",
        "description": (
            f"Generic exception handling at line {lineno} without "
            f"wrapping or meaningful recovery."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Catch specific exception subclasses, or re-raise with "
            "``raise DomainError(...) from original`` to preserve chaining."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, "248")


def _body_is_bare(body_lines: list[str]) -> bool:
    """Return True if the first body line is a bare ``pass`` or bare ``raise``."""
    if not body_lines:
        return False
    first = body_lines[0].strip()
    return bool(_BARE_PASS.match(first) or _BARE_RAISE.match(first))


def _scan_py_except(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a Python ``except Exception`` header for bare-pass/raise bodies."""
    if not _PY_EXCEPT_EXCEPTION.search(line):
        return
    body = collect_handler_body(lines, lineno)
    if _body_is_safe(body):
        return
    if _body_is_bare(body):
        findings.append(_build_finding(file_path, lineno, lines))


def _scan_java_throws(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Scan a Java line for a generic ``throws Exception`` method declaration."""
    if _JAVA_THROWS.search(line):
        findings.append(_build_finding(file_path, lineno, lines))


def _select_scanner(ext: str):
    """Return the appropriate per-line scanner for the file extension."""
    if ext == ".java":
        return _scan_java_throws
    return _scan_py_except


def _should_scan(file_path: Path) -> bool:
    """Return True if file passes language-gate and non-generated/test filters."""
    if file_path.suffix.lower() not in _LANG_EXTENSIONS:
        return False
    return not (is_generated_file(file_path) or is_test_file(file_path))


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan for CWE-248 signatures."""
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    scanner = _select_scanner(file_path.suffix.lower())
    for lineno, line in enumerate(lines, 1):
        scanner(line, lineno, path_str, lines, findings)


def check_uncaught_exception(source_path: str) -> dict[str, Any]:
    """Scan source files for uncaught-exception antipatterns (CWE-248)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_uncaught_exception_tool = function_tool(check_uncaught_exception)
