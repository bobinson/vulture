"""Dedicated skill for CWE-676 / CWE-242 — inherently dangerous *library*
functions in memory-unsafe systems languages.

Feature 0060 narrowed this skill: it now flags ONLY functions that are unsafe
*by design* in C/C++, Go, and Rust — where using them at all is the weakness,
independent of dataflow. Execution sinks (``eval``/``exec``/``os.system``/
``os.popen``/``Runtime.exec`` etc.) were **ceded to the injection skill**
(CWE-78 command injection / CWE-94 code injection), which already matches them
with a receiver-boundary that excludes benign method calls like
``RegExp.exec()`` and ioredis ``pipeline.exec()``. This removed a class of
false positives (idattestor VLT-1037/1038/1039/1043) and the historical
CWE-676↔CWE-78 double-report.

Detection is **language-aware**: the file's language (via
``shared.validate.language.detect_language``) selects its sink set, so a name
that is a dangerous C library call is not flagged in a JavaScript file that
merely defines a same-named function.
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
from shared.env import env_truthy
from shared.tools.snippet import extract_snippet
from shared.validate.language import detect_language

from cwe_agent.catalog import enrich_finding

# --- Sink patterns (data) -------------------------------------------------
# Each is ReDoS-safe (bounded, no nested quantifiers). The C/Rust bare-name
# sinks carry a fixed-width receiver-reject lookbehind ``(?<![\w.>])`` so a
# member access (``obj.strcpy(``, ``obj->transmute(``) is NOT matched as the
# bare library call — mirrors the injection skill's boundary convention.

# CWE-242 "Use of Inherently Dangerous Function": no safe bound exists at all
# (``gets`` was removed from C11 for exactly this reason).
_C_GETS = re.compile(r"(?<![\w.>])gets\s*\(")

# CWE-676 C/C++ string-handling: unbounded copy/scan/format + race-prone temp
# name + stack-alloc-by-size primitives that HAVE safe alternatives.
_C_STRING = re.compile(
    r"(?<![\w.>])(?:"
    r"strcpy|strcat|sprintf|vsprintf|scanf|sscanf|"
    r"strdup|strndup|vfprintf|vprintf|"
    r"tmpnam|tempnam|mktemp|alloca|getwd"
    r")\s*\("
)

# CWE-676 Go: the memory-unsafe escape hatch — using ``unsafe.*`` at all is the
# risk CWE-676 marks (bypasses the type/memory-safety guarantees).
_GO_UNSAFE = re.compile(
    r"\bunsafe\.(?:Pointer|Sizeof|Alignof|Offsetof"
    r"|Slice|SliceData|Add|String|StringData)\s*\("
)

# CWE-676 Rust: transmute (reinterpret bits), unchecked slice access (bypasses
# bounds checks), and raw-pointer read/write.
_RUST_UNSAFE = re.compile(
    r"\btransmute\s*\("
    r"|\.get_unchecked(?:_mut)?\s*\("
    r"|\bptr::(?:read|write)\w*\s*\("
)

_C_FAMILY_SINKS = ((_C_GETS, "242", "critical"), (_C_STRING, "676", "high"))

# language name (from detect_language) -> tuple of (pattern, cwe_id, severity)
_SINKS_BY_LANG: dict[str, tuple[tuple[re.Pattern, str, str], ...]] = {
    "c":    _C_FAMILY_SINKS,
    "cpp":  _C_FAMILY_SINKS,
    "objc": _C_FAMILY_SINKS,   # Objective-C(.m/.mm) is a C superset
    "go":   ((_GO_UNSAFE, "676", "high"),),
    "rust": ((_RUST_UNSAFE, "676", "high"),),
}

# A sink token that is itself the function being DEFINED (``fn transmute(...)``,
# ``def gets(...)``) is a same-named declaration, not a dangerous call, and must
# not be flagged (RED-2 H1). Detected by a definition keyword immediately
# preceding the matched sink — NOT a line-level skip, so a single-line function
# that *calls* a sink (``func f() { unsafe.Pointer(p) }``) still fires.
_DEF_BEFORE = re.compile(r"\b(?:fn|func|def|sub)\s+$")

# Escape hatch (mirrors the VULTURE_CWE_DISABLE_* convention): fully disable
# this skill for one release if the narrowed matcher misbehaves (feature 0060).
_ENV_DISABLE = "VULTURE_CWE_DISABLE_DANGEROUS_FN"

# Safe-context: a bounded/safe alternative in the 5-line preceding window
# suppresses a C string-handling finding (e.g. a strncpy migration).
_SAFE_CONTEXT = re.compile(r"\bstrncpy\b|\bstrlcpy\b|\bsnprintf\b|\bstrlcat\b")


def _is_safe_context(lines: tuple[str, ...], lineno: int) -> bool:
    """Return True if a safe alternative is present in the prior 5 lines."""
    start = max(0, lineno - 6)
    window = "\n".join(lines[start:lineno])
    return _SAFE_CONTEXT.search(window) is not None


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
            f"CWE-{cwe_id} marks this API as risky-by-design."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Replace with a bounded/safe alternative: strncpy/snprintf for C "
            "string handling; avoid Go unsafe.* and Rust transmute/"
            "get_unchecked unless the invariant is proven and documented."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    return enrich_finding(finding, cwe_id)


def _scan_line(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    sinks: tuple[tuple[re.Pattern, str, str], ...],
    findings: list[dict],
) -> None:
    """Scan a single line for this language's dangerous-function sinks."""
    # Pure comment lines cannot invoke an API — the matched token is prose.
    if COMMENT_INDICATORS.match(line):
        return
    for pattern, cwe_id, severity in sinks:
        m = pattern.search(line)
        if m is None:
            continue
        # Skip when the sink token is the function being DEFINED on this line
        # (e.g. Rust `fn transmute(...)`), not a dangerous call (RED-2 H1).
        if _DEF_BEFORE.search(line[:m.start()]):
            continue
        # Safe-context suppression applies to the C string-handling family.
        if cwe_id == "676" and pattern is _C_STRING and _is_safe_context(lines, lineno):
            return
        findings.append(_build_finding(cwe_id, severity, file_path, lineno, lines))
        return


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan each one for this file's language sinks."""
    if is_generated_file(file_path) or is_test_file(file_path):
        return
    sinks = _SINKS_BY_LANG.get(detect_language(str(file_path)))
    if not sinks:
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    for lineno, line in enumerate(lines, 1):
        _scan_line(line, lineno, path_str, lines, sinks, findings)


def check_dangerous_function(source_path: str) -> dict[str, Any]:
    """Scan source files for inherently-dangerous library calls (CWE-676 / CWE-242)."""
    if env_truthy(_ENV_DISABLE):
        return {"findings": []}
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_dangerous_function_tool = function_tool(check_dangerous_function)
