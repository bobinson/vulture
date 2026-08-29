"""Code-window production and window-absence accounting (feature 0082).

Two responsibilities, deliberately in one module because they are two halves of
one question — *does this finding carry evidence, and if not, why not?*

``ensure_code_window``
    Reads the source window for a batch of findings and REDACTS it in the same
    pass. Lifted out of ``audit_runner._attach_code_snippet`` (which was C(12))
    so the two operations cannot be performed separately. That inseparability is
    the point: feature 0082's E3 proposed a second, independent window read on
    the OWASP path, and it would have egressed secrets verbatim because
    ``_redact_finding_inplace`` keys on ``finding["category"]`` and the OWASP
    agent overwrites that with its own slug before emitting. A caller that
    cannot obtain a window without redaction cannot reproduce that bug.

``record_window_reason``
    Stamps WHY a finding has no window, into the existing ``validation`` blob.
    This is the part every agent needs and none of them had: an empty
    ``code_snippet`` was previously indistinguishable between "no code location
    exists for this finding class", "this is a rollup parent standing for many
    sites", "the file could not be read", and "nobody tried". 416 findings in
    the reference scan were in that undifferentiated state.

LEAF DISCIPLINE. ``shared.tools.*`` must not import ``shared.audit_runner`` at
module scope: ``audit_runner -> shared.tools.* -> __init__ -> file_reader``
closes a cycle that feature 0076 already hit once. ``record_window_reason``
touches nothing but the finding dict and is a true leaf. ``ensure_code_window``
needs the resolver/redactor that still live in ``audit_runner`` and imports them
INSIDE the function body — the same deferred-import pattern
``_attach_code_snippet`` already uses for ``read_file_lines``.

NO MODULE-LEVEL MUTABLE STATE, and no new cache. ``sse_app`` drives eight
generators in one interpreter; a module global or a ContextVar here would be
cross-audit contamination, and a new ``lru_cache`` would be invisible to
``file_scanner.clear_caches()`` — which already records two caches omitted
before.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any

# The closed vocabulary of reasons a finding can carry no code window. Closed on
# purpose: an open-ended free-text reason is how "unvalidated" became
# indistinguishable from "validated as fine" elsewhere in this system.
WINDOW_INHERITED = "inherited"          # carried from another agent's finding; not re-read
WINDOW_ROLLUP_PARENT = "rollup_parent"  # stands for N sites; one member's window would misrepresent
WINDOW_NO_CODE_LOCATION = "no_code_location"  # the finding class has no file/line by nature
WINDOW_UNREADABLE = "unreadable"        # path did not resolve, or the read failed
WINDOW_NO_LINE = "no_line"              # a file, but no usable line number
WINDOW_PRESENT = "present"              # a window was produced (recorded for symmetry)

WINDOW_REASONS = frozenset({
    WINDOW_INHERITED, WINDOW_ROLLUP_PARENT, WINDOW_NO_CODE_LOCATION,
    WINDOW_UNREADABLE, WINDOW_NO_LINE, WINDOW_PRESENT,
})

_WINDOW_CHECK = "window"

# Human-readable text for the UI tooltip, one per vocabulary member. Wrapped in
# MappingProxyType so it is genuinely read-only: this module must hold no
# mutable module-level state (eight audit generators share one interpreter), and
# a bare dict literal is indistinguishable from state to both a reader and the
# guard in test_0082_no_ambient_state.py.
_REASON_TEXT = MappingProxyType({
    WINDOW_INHERITED: "carried from another agent's finding; source not re-read",
    WINDOW_ROLLUP_PARENT: "groups several sites; no single line represents them",
    WINDOW_NO_CODE_LOCATION: "this finding class has no file or line",
    WINDOW_UNREADABLE: "the referenced file could not be read",
    WINDOW_NO_LINE: "a file, but no usable line number",
    WINDOW_PRESENT: "",
})


def record_window_reason(finding: dict[str, Any], reason: str) -> None:
    """Record why ``finding`` carries no code window, in its ``validation`` blob.

    Carried in the existing blob rather than a new top-level field on purpose:
    ``model.Finding`` has no window-reason column, and ``ParseDeltaFindings``
    does a plain ``json.Unmarshal`` with no ``DisallowUnknownFields``, so a new
    top-level key would vanish silently in Go. The blob already crosses every
    transport and is already persisted by Postgres, SQLite and the memory repos
    — no migration, no divergence to check.

    Additive and idempotent. Never overwrites an existing window reason, never
    touches ``status`` or ``confidence``, and never removes a check. Stamping a
    reason must not be able to move a verdict.
    """
    if not isinstance(finding, dict) or reason not in WINDOW_REASONS:
        return

    blob = finding.get("validation")
    if not isinstance(blob, dict):
        blob = {}
        finding["validation"] = blob

    checks = blob.get("checks")
    if not isinstance(checks, list):
        checks = []
        blob["checks"] = checks

    for check in checks:
        if isinstance(check, dict) and check.get("id") == _WINDOW_CHECK:
            return  # already accounted for; first reason wins

    # Shape matches ValidationCheck.to_json() exactly. `id` is REQUIRED:
    # ValidationCheck.from_json does `data["id"]` unguarded, so a check keyed
    # on anything else raises KeyError in the revote path
    # (validate/__init__.py:291) for every finding carrying a reason.
    checks.append({
        "id": _WINDOW_CHECK,
        "result": reason,
        # Weight zero: this is BOOKKEEPING, not evidence. A recorded absence
        # must never nudge a confidence score — the reason a finding has no
        # window says nothing about whether the finding is true.
        "weight": 0.0,
        "reason": _REASON_TEXT.get(reason, ""),
        "extras": {},
    })


def window_reason_of(finding: dict[str, Any]) -> str:
    """Read back the recorded window reason, or "" if none was recorded."""
    blob = finding.get("validation")
    if not isinstance(blob, dict):
        return ""
    checks = blob.get("checks")
    if not isinstance(checks, list):
        return ""
    for check in checks:
        if isinstance(check, dict) and check.get("id") == _WINDOW_CHECK:
            return str(check.get("result", ""))
    return ""


def ensure_code_window(
    findings: list[dict[str, Any]],
    source_path: str,
    *,
    record_reasons: bool = False,
) -> None:
    """Populate a redacted code window on every finding that lacks one.

    Byte-identical to the loop it was lifted from. Mutates in place. Additive:
    a finding that already carries a non-empty ``code_snippet`` keeps it, except
    for wide-scope classes, which are re-windowed to the line budget because 200
    characters cannot contain a mitigation that lives lines away.

    A finding whose path will not resolve, or whose line is missing or zero, is
    left with an empty window — the L5 selection layer then SKIPS it rather than
    judging blind.

    ``record_reasons`` (feature 0082 Step 5) additionally stamps WHY each empty
    window is empty. Off by default so the extraction itself is provably a pure
    refactor.
    """
    # Deferred imports: see LEAF DISCIPLINE in the module docstring.
    from shared.audit_runner import (
        _redact_finding_inplace,
        _resolve_finding_path,
        _snippet_params_for,
    )
    from shared.tools.file_scanner import read_file_lines
    from shared.tools.snippet import extract_snippet

    for f in findings:
        context, max_chars = _snippet_params_for(f.get("category", "") or "")
        wide = max_chars is None
        reason = WINDOW_PRESENT if f.get("code_snippet") else ""

        if wide or not f.get("code_snippet"):
            line_start = f.get("line_start", 0) or 0
            try:
                line_start = int(line_start)
            except (TypeError, ValueError):
                line_start = 0
            if line_start >= 1:
                resolved = _resolve_finding_path(f.get("file_path", ""), source_path)
                if resolved is not None:
                    lines = read_file_lines(resolved)
                    if lines:
                        snippet = extract_snippet(
                            lines, line_start,
                            context=context, max_chars=max_chars,
                        )
                        if snippet:
                            f["code_snippet"] = snippet
                            reason = WINDOW_PRESENT
                if not f.get("code_snippet"):
                    reason = WINDOW_UNREADABLE
            elif not f.get("code_snippet"):
                reason = WINDOW_NO_LINE if f.get("file_path") else WINDOW_NO_CODE_LOCATION

        # Mask secret VALUES for secret-bearing CWEs, whether the window was
        # back-filled above OR pre-set by a skill. In the same pass as the read,
        # so no caller can hold an unredacted window.
        _redact_finding_inplace(f)

        if record_reasons and reason:
            record_window_reason(f, reason)


def window_check(reason: str) -> dict[str, Any]:
    """The window check as a plain dict, for callers that build a validation
    blob directly rather than mutating a finding (e.g. rollup parents, which
    are constructed whole)."""
    holder: dict[str, Any] = {}
    record_window_reason(holder, reason)
    return holder["validation"]["checks"][0]
