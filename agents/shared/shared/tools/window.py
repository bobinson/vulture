"""Code-window production, coordinates and window-absence accounting.

Feature 0082, extended by feature 0089 item 4.2. Three responsibilities,
deliberately in one module because they are three parts of one question —
*does this finding carry evidence, where in the file is it, and if there is
none, why not?*

``ensure_code_window``
    Reads the source window for a batch of findings and REDACTS it in the same
    pass. Lifted out of ``audit_runner._attach_code_snippet`` (which was C(12))
    so the two operations cannot be performed separately. That inseparability is
    the point: feature 0082's E3 proposed a second, independent window read on
    the OWASP path, and it would have egressed secrets verbatim because
    ``_redact_finding_inplace`` keys on ``finding["category"]`` and the OWASP
    agent overwrites that with its own slug before emitting. A caller that
    cannot obtain a window without redaction cannot reproduce that bug.

``confirmed_window_start`` / ``CODE_SNIPPET_START``
    Records WHERE the window sits — the true 1-based file line of its first
    row — so the L5 render can number it instead of deriving a start from the
    finding's own line. That derivation was wrong for every window not
    symmetric about ``line_start``, and `evidence_line` and every
    ``citation_class`` figure to date were measured against its numbers.

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

from collections.abc import Sequence
from types import MappingProxyType
from typing import Any

from shared.tools.line_format import read_line_number, strip_line_number

# `audit_runner._REDACTION_PLACEHOLDER`, restated rather than imported: this
# module is a LEAF and may not name `audit_runner` at import time. The value is
# pinned equal to it by test_0089_4_2_evidence_coordinates.py, so the two cannot
# drift silently.
_REDACTED = "***REDACTED***"

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

# Where the window's own first FILE line is stamped (feature 0089 item 4.2).
#
# UNDERSCORE-PREFIXED ON PURPOSE, and not by style. ``emitter.finding_event(
# **_public_view(finding))`` forwards ``**extra`` verbatim while Go's fixed
# ``model.Finding`` has no such column, so a PLAIN name would appear on the live
# SSE stream and vanish on replay — one finding with two contents depending on
# when you looked. ``_public_view`` drops every ``_``-prefixed key, which is the
# mechanism the seven ``_anchor_*`` stamps already rely on.
#
# It is deliberately NOT on ``audit_runner._PRIVATE_FIELDS``: that roster is
# deleted by ``_apply_validation_to_finding``, which runs in the provisional
# vote BEFORE ``_run_l5_phase``, and the L5 render is this value's only
# consumer. Listing it there would ship the item inert — the same trap the
# ``_anchor_*`` comment records from the other end.
CODE_SNIPPET_START = "_code_snippet_start"

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


def _row_matches(row: str, expected: str) -> bool:
    """One snippet row against the numbered file line it claims to be.

    ``startswith`` rather than equality because every way ``extract_snippet``
    shortens a row leaves a PREFIX: ``max_chars`` cuts the joined snippet
    (which can land mid-prefix, leaving a last row of literally ``"20"``) and
    the line-budget mode caps each line at 400 characters. A row can therefore
    be shorter than the file's, never different from it.

    A redacted row is exempt from the TEXT comparison and from nothing else.
    ``_redact_snippet`` rewrites the secret in place, so a secret-bearing
    finding's window genuinely does not equal its source — and refusing those
    would leave exactly the CWE-798 findings a judge most wants to cite with no
    coordinates. Its neighbours still have to match at their own claimed lines,
    so the window's position is still fixed by the file, not by the row that
    was allowed to differ.
    """
    if _REDACTED in row:
        return True
    return expected.startswith(row)


def _window_matches(rows: list[str], lines: Sequence[str], claim: int) -> bool:
    """Does the file carry every row's text at the line that row claims?

    Compared against the NUMBERED form of the file line, so each row's own
    ``NN: `` prefix is checked too — not just the first one's. That is what
    makes the claim corroborated rather than merely plausible: a window
    shifted by one would have to be wrong on every row to pass.

    At least one row must carry actual content: a window of blank lines is a
    prefix of every blank line in the file, so it matches everywhere and may
    therefore confirm nowhere.
    """
    placed = all(
        _row_matches(row, f"{claim + i}: {lines[claim - 1 + i]}")
        for i, row in enumerate(rows)
    )
    return placed and any(strip_line_number(row).strip() for row in rows)


def confirmed_window_start(snippet: str, lines: Sequence[str]) -> int:
    """The 1-based FILE line ``snippet`` begins at, or 0 if the file disagrees.

    Feature 0089 item 4.2. ``extract_snippet`` writes absolute file numbers as
    ``"NN: "`` prefixes, so the coordinate the render needs is already in the
    window — the render simply threw it away and re-derived a wrong one.

    Reading the number back is not the same as believing it, which is what
    keeps A-3 (anti-spoofing) intact. The claim is accepted only when the FILE
    carries that exact text at that exact line, for every row, and only when at
    least one row is non-blank — a window of blank lines matches everywhere and
    so may confirm nowhere. A snippet that merely LOOKS numbered ("4: ...") is
    refused, and a finding whose start cannot be confirmed is rendered
    unnumbered rather than mis-numbered.
    """
    rows = snippet.splitlines()
    # `read_line_number` matches `\d+`, so a claim is never negative and 0 is
    # falsy — "no prefix" and "line 0" are refused by the same test.
    claim = read_line_number(rows[0]) if rows else None
    if not claim or claim + len(rows) - 1 > len(lines):
        return 0
    return claim if _window_matches(rows, lines, claim) else 0


def _record_window_start(finding: dict[str, Any], source_path: str) -> None:
    """Stamp the window's true first FILE line, decided by reading the file.

    One path for both cases, because ``extract_snippet`` is the only producer
    of code windows in this tree and it numbers every row absolutely: a window
    this module just read and a window a skill set earlier are corroborated by
    the same file, with the same comparison.

    That the skill case is covered at all is not a detail. Measured on a
    skills-only CWE run over ``backend/internal``, **99.0% of findings reach
    this function with a ``code_snippet`` already set**, which the loop below
    deliberately does not re-read. Recording only on the read branch — the
    literal reading of the 0089 LLD spec — would have left almost every judged
    finding with no line numbers at all.

    ``read_file_lines`` is ``lru_cache``d and the skill phase has just read
    these same files, so the confirming read is a cache hit in the ordinary
    case.
    """
    from shared.audit_runner import _resolve_finding_path
    from shared.tools.file_scanner import read_file_lines

    snippet = finding.get("code_snippet") or ""
    if not snippet:
        return
    resolved = _resolve_finding_path(finding.get("file_path", ""), source_path)
    lines = read_file_lines(resolved) if resolved is not None else None
    start = confirmed_window_start(snippet, lines or ())
    if start >= 1:
        finding[CODE_SNIPPET_START] = start


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
                        # Pass the declared END so a multi-line finding is
                        # windowed over its whole range, not just around its
                        # first line — see _SPAN_MAX_LINES in snippet.py.
                        try:
                            line_end = int(f.get("line_end") or 0)
                        except (TypeError, ValueError):
                            line_end = 0
                        snippet = extract_snippet(
                            lines, line_start,
                            context=context, max_chars=max_chars,
                            line_end=line_end or None,
                        )
                        if snippet:
                            f["code_snippet"] = snippet
                            reason = WINDOW_PRESENT
                if not f.get("code_snippet"):
                    reason = WINDOW_UNREADABLE
            elif not f.get("code_snippet"):
                reason = WINDOW_NO_LINE if f.get("file_path") else WINDOW_NO_CODE_LOCATION

        # Feature 0089 item 4.2: the window's own coordinates, before redaction
        # can alter the bytes the confirmation compares. The L5 render numbers
        # from this instead of re-deriving a start from `line_start`.
        _record_window_start(f, source_path)

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
