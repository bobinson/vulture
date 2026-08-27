"""Dedicated skill for CWE-778 (insufficient logging).

Flags two patterns:

  1. Exception handlers (``catch`` / ``except`` blocks) whose body does
     not emit a logging call. Swallowed exceptions hide evidence
     needed for incident response.
  2. Authentication/authorization decision points (login_failed,
     access_denied, permission denied, token invalid, MFA failure)
     that don't log the event. CWE-778 specifically calls out auth
     decisions as critical events that must be logged for forensics
     and intrusion detection.
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
from shared.tools.line_context import strip_strings_and_comments
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
    r"|\bconsole\.(?:error|warn|info|log)\s*\("
    r"|\bsyslog\b"
    r"|\bLOG_[A-Z]"
    r"|\bfmt\.Fprintf\s*\(\s*os\.Stderr"
    r"|\bzap\.\w+\s*\("
    r"|\bzerolog\.\w+\s*\("
    r"|\baudit_log\b"
    r"|\bsecurity_log\b"
)


# Authentication/authorization decision points that should be audit-
# logged. Lines matching these are scanned for nearby logging calls;
# absence emits a CWE-778 finding.
_AUTH_DECISION = re.compile(
    r"(?:"
    r"\b(?:login|authentication|auth)[_\-]?(?:failed|fail|denied|invalid|reject)\b"
    r"|\b(?:permission|access)[_\-]?denied\b"
    r"|\bmfa[_\-]?(?:failed|fail|invalid)\b"
    r"|\btoken[_\-]?(?:invalid|expired|reject)\b"
    r"|\bunauthorized\b"
    r"|\bforbidden\b"
    r"|\binvalid[_\-]?credentials\b"
    r")",
    re.IGNORECASE,
)


def _has_log_within(lines: tuple[str, ...], lineno: int, radius: int = 4) -> bool:
    """True when a log call appears within ``radius`` lines of ``lineno``."""
    start = max(0, lineno - radius - 1)
    end = min(len(lines), lineno + radius)
    for i in range(start, end):
        if _LOG_CALL.search(lines[i]):
            return True
    return False


def _body_has_logging(body_lines: list[str]) -> bool:
    """Return True if any line in the handler body invokes a logging call."""
    for line in body_lines:
        if _LOG_CALL.search(line):
            return True
    return False


# An error identifier a propagation call would be handed. Anchored with
# ``\b`` at both ends so ``entry`` / ``errCount`` are not error names.
# Case-sensitive by design (see the ``Exception``/``Error`` spellings
# listed explicitly rather than using re.IGNORECASE).
_ERR_ARG = (
    r"(?:e|ex|exc|err|error|exception|reason"
    r"|E|Ex|Exc|Err|Error|Exception|Reason)\b"
)

# Handler bodies that FORWARD the error instead of swallowing it. Not a
# logging defect: the caller still receives the evidence, so CWE-778
# does not apply. ``raise``/``throw`` are anchored to a statement start
# (line start, ``{``, ``;`` or ``:``). That anchor alone is NOT enough --
# ``:`` matches inside prose like "note: throw is avoided here" -- so
# _body_propagates strips comments and strings before matching.
# All quantifiers bounded; no nested repetition (ReDoS-safe).
# The handler hands the error to a dedicated error-handling routine, and that
# routine is where the logging lives. Measured on one real target: 95 of 168
# CWE-778 rows were `catch (error) { handleApiError(error, res); }`, and
# handleApiError logs `console.log("AppError", payload)` ONE HOP away. Matching
# only DIRECT log calls let a single hop of indirection defeat the whole rule.
#
# BOTH halves are required -- an error-handling NAME SHAPE and an error-shaped
# ARGUMENT -- so `cleanup(e)` and `swallow(e)` are still reported. Accepted
# limit: a routine NAMED like a handler that discards the error is excused
# here; resolving that needs cross-file analysis, and the defect would belong
# to that routine rather than to its caller.
_ERROR_DELEGATE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]{0,40}\.)?"
    r"(?:"
    r"(?:handle|report|capture|record|notify|forward|log|trace|emit)"
    r"[A-Za-z0-9_]{0,32}(?:Error|Err|Exception|Failure)"
    r"|[A-Za-z0-9_]{0,32}(?:Error|Exception)Handler"
    r"|onError"
    r")"
    r"\s*\(\s*" + _ERR_ARG
)


def _body_delegates(body_lines: list[str]) -> bool:
    """True if the body hands the error to a named error-handling routine."""
    return any(
        _ERROR_DELEGATE.search(strip_strings_and_comments(line))
        for line in body_lines
    )


_PROPAGATES = re.compile(
    r"(?:^|[{};:])\s{0,80}(?:raise|throw)\b"
    r"|\bnext\s*\(\s*" + _ERR_ARG +
    r"|\bnext\s*\(\s*new\s+[A-Za-z_][A-Za-z0-9_.]{0,63}"
    r"|\breject\s*\("
    r"|\bcallback\s*\(\s*" + _ERR_ARG +
    r"|\breturn\s+(?:[A-Za-z_][A-Za-z0-9_.]{0,40}\s*,\s*)?" + _ERR_ARG
)


def _body_propagates(body_lines: list[str]) -> bool:
    """Return True if the handler body re-raises or forwards the error.

    Propagation (``raise``, ``throw e``, ``next(err)``, ``reject(...)``,
    ``return err``, ``callback(err)``) preserves the error for the
    caller, so the handler is not "insufficient logging". An EMPTY body
    propagates nothing and is deliberately not covered here — empty
    handlers are reported by their own early-return paths.
    """
    for line in body_lines:
        # Strip comments and string literals FIRST. The statement-start anchor
        # below includes ``:``, so prose such as ``// note: throw is avoided
        # here`` would otherwise match and SUPPRESS a real finding. Stripping
        # fails safe in this direction: if it misses a comment the finding is
        # still reported, never silently dropped (see line_context's docstring
        # on not using it as a hard skip -- suppression here is the only use
        # that could lose a row, and a missed strip cannot cause that).
        if _PROPAGATES.search(strip_strings_and_comments(line)):
            return True
    return False


def _handler_is_excused(body: list[str], inline: str = "") -> bool:
    """True when a NON-EMPTY handler body neither swallows nor hides the
    error: it logs it, or it forwards it to the caller.

    Args:
        body: Body lines collected after the handler header.
        inline: Text following the opening brace on the header line
            itself (single-line ``catch (err) { next(err) }``), which
            ``collect_handler_body`` never returns.
    """
    lines = [inline, *body]
    return (
        _body_has_logging(body)
        or _body_propagates(lines)
        or _body_delegates(lines)
    )


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
    if _handler_is_excused(body):
        return
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
    match = _CATCH_LINE.search(line)
    if not match:
        return
    body = collect_handler_body(lines, lineno)
    # A single-line `catch (err) { next(err) }` keeps its whole body on
    # the header line, which collect_handler_body never returns — so the
    # text after the opening brace is part of the body for propagation.
    if _handler_is_excused(body, inline=line[match.end():]):
        return
    findings.append(_build_finding(file_path, lineno, lines))


def _should_scan(file_path: Path) -> bool:
    """Return True if file passes language-gate and non-generated/test filters."""
    if file_path.suffix.lower() not in _LANG_EXTENSIONS:
        return False
    return not (is_generated_file(file_path) or is_test_file(file_path))


def _scan_file(file_path: Path, findings: list[dict]) -> None:
    """Read file lines and scan each one for un-logged exception handlers
    or un-logged auth decisions."""
    if not _should_scan(file_path):
        return
    lines = read_file_lines(file_path)
    if lines is None:
        return
    path_str = str(file_path)
    seen_lines: set[int] = set()
    for lineno, line in enumerate(lines, 1):
        _scan_py_except(line, lineno, path_str, lines, findings)
        _scan_catch(line, lineno, path_str, lines, findings)
        _scan_auth_decision(line, lineno, path_str, lines, findings, seen_lines)


def _scan_auth_decision(
    line: str,
    lineno: int,
    file_path: str,
    lines: tuple[str, ...],
    findings: list[dict],
    seen_lines: set[int],
) -> None:
    """Flag auth-decision points that aren't audit-logged in the
    surrounding window. The same line is only reported once even if it
    matches multiple auth keywords."""
    if lineno in seen_lines:
        return
    if not _AUTH_DECISION.search(line):
        return
    if _has_log_within(lines, lineno, radius=4):
        return
    seen_lines.add(lineno)
    finding = {
        "severity": "medium",
        "check_id": "cwe.insufficient_logging.auth_decision",
        "category": "CWE-778",
        "title": "Authentication/authorization decision not logged",
        "description": (
            f"Auth decision at line {lineno} (e.g. login failure, access "
            "denied, invalid credentials) doesn't emit a logging call "
            "within 4 lines. Auth events must be audit-logged."
        ),
        "file_path": file_path,
        "line_start": lineno,
        "line_end": lineno,
        "recommendation": (
            "Log the decision and identifying context (subject, "
            "resource, reason) via your audit-log facility so security "
            "monitoring and forensics can reconstruct the event."
        ),
        "code_snippet": extract_snippet(lines, lineno),
    }
    findings.append(enrich_finding(finding, "778"))


def check_insufficient_logging(source_path: str) -> dict[str, Any]:
    """Scan source files for silent exception handlers (CWE-778)."""
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        _scan_file(file_path, findings)
    return {"findings": findings}


check_insufficient_logging_tool = function_tool(check_insufficient_logging)
