"""Dedicated skill for CWE-248 (uncaught exception) and CWE-397
(declaration of throws for a generic exception).

Flags:

* Java method declarations that declare ``throws Exception`` (generic
  checked exception, not a specific subclass) — calling code cannot
  distinguish failure modes. Reported as CWE-248.
* Python handlers that catch ``Exception`` broadly and either ``pass``
  silently or bare-re-raise without wrapping in a domain-specific error.
  Reported as CWE-248.
* CWE-397 — a generic exception THROWN rather than caught, in the dialects
  where that is the language's own spelling of the same weakness: the
  (deprecated) C++ dynamic exception specification ``) throw(std::exception)``,
  and ``throw new Exception(`` in C# (which has no checked exceptions at all,
  so it has no ``throws`` clause to inspect) / ``raise Exception(`` in Python.

Suppressed when the handler body wraps/re-raises with chaining
(``raise X(...) from e``, ``__cause__``, or ``throw new X``).
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
from shared.tools.snippet import collect_handler_body, extract_snippet

from cwe_agent.catalog import enrich_finding

# Language gate. Only extensions the scanner actually yields are listed:
# ``.cc``/``.cxx``/``.hpp`` are in neither CODE_EXTENSIONS nor
# WHITELIST_EXTENSIONS, so declaring them would be dead code.
_LANG_EXTENSIONS: frozenset[str] = frozenset({
    ".java", ".py", ".cs", ".cpp", ".c", ".h",
})

# Java: method decl with generic ``throws Exception``.
#
# Anchored on the parameter list's closing paren and on end-of-statement, which
# is what separates a declaration from its documentation: the previous bare
# ``\bthrows\s+Exception\b`` also matched the javadoc line
# ``* @throws Exception if it fails`` and the string literal
# ``"throws Exception"``. ``\bException\b`` keeps
# ``throws ExceptionInInitializerError`` out.
_JAVA_THROWS = re.compile(
    r"\)\s*throws\s+[\w.\s,]*\bException\b[\w.\s,]*[{;]?\s*$"
)

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

# ── CWE-397: a generic exception THROWN (not caught) ──────────────────
# One arm per dialect, each pinned to the exact generic type so a
# domain-specific exception cannot match. One row per FILE: these are style-
# level weaknesses whose per-line volume would swamp their value.
_CPP_THROW_SPEC = re.compile(r"\)\s*throw\s*\(\s*(?:std::)?exception\s*\)")
_CS_GENERIC_THROW = re.compile(
    r"^\s*throw\s+new\s+(?:System\.)?"
    r"(?:Exception|SystemException|ApplicationException)\s*\("
)
_PY_GENERIC_RAISE = re.compile(r"^\s*raise\s+(?:Exception|BaseException)\s*\(")

_GENERIC_THROW_ARMS = (
    {
        "extensions": frozenset({".cpp", ".c", ".h"}),
        "pattern": _CPP_THROW_SPEC,
        "severity": "medium",
        "detail": "Dynamic exception specification declares a generic exception",
    },
    {
        "extensions": frozenset({".cs"}),
        "pattern": _CS_GENERIC_THROW,
        "severity": "medium",
        "detail": "Generic exception thrown instead of a specific subclass",
    },
    {
        "extensions": frozenset({".py"}),
        "pattern": _PY_GENERIC_RAISE,
        "severity": "low",
        "detail": "Generic exception raised instead of a specific subclass",
    },
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


# Per-line scanners by extension. A dict, not an if/else fallback: with the
# extension set widened for the CWE-397 arms, a fallback would run the Python
# ``except Exception`` scanner over C# and C++ sources.
_LINE_SCANNERS: dict[str, tuple] = {
    ".java": (_scan_java_throws,),
    ".py": (_scan_py_except,),
}


def _build_397_finding(
    file_path: str, lineno: int, lines: tuple[str, ...], arm: dict,
) -> dict[str, Any]:
    """Construct a single CWE-397 finding dict."""
    finding = {
        "severity": arm["severity"],
        "check_id": "cwe.uncaught_exception.generic_throw",
        "category": "CWE-397",
        "title": "Generic exception thrown",
        "description": f"{arm['detail']} at line {lineno}.",
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Throw a specific exception type so callers can distinguish "
            "failure modes and recover selectively."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, "397")


def _first_match(pattern: re.Pattern, lines: tuple[str, ...]) -> int | None:  # type: ignore[type-arg]
    """1-based line number of the first non-comment match, if any."""
    for lineno, line in enumerate(lines, 1):
        if pattern.search(line) and not COMMENT_INDICATORS.match(line):
            return lineno
    return None


def _scan_generic_throw(
    file_path: Path, lines: tuple[str, ...], findings: list[dict],
) -> None:
    """Emit at most one CWE-397 row per file."""
    suffix = file_path.suffix.lower()
    for arm in _GENERIC_THROW_ARMS:
        if suffix not in arm["extensions"]:
            continue
        lineno = _first_match(arm["pattern"], lines)
        if lineno is not None:
            findings.append(
                _build_397_finding(str(file_path), lineno, lines, arm)
            )
        return


def _should_scan(file_path: Path) -> bool:
    """Return True if file passes language-gate and non-generated/test filters."""
    if file_path.suffix.lower() not in _LANG_EXTENSIONS:
        return False
    return not (is_generated_file(file_path) or is_test_file(file_path))


def _scan_lines(
    file_path: Path, lines: tuple[str, ...], findings: list[dict],
) -> None:
    """Run every per-line scanner registered for this file's extension."""
    scanners = _LINE_SCANNERS.get(file_path.suffix.lower(), ())
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        for scanner in scanners:
            scanner(line, lineno, path_str, lines, findings)


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan for CWE-248 / CWE-397 signatures."""
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    _scan_generic_throw(file_path, lines, findings)
    _scan_lines(file_path, lines, findings)


def check_uncaught_exception(source_path: str) -> dict[str, Any]:
    """Scan source files for uncaught-exception antipatterns (CWE-248/397)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_uncaught_exception_tool = function_tool(check_uncaught_exception)
