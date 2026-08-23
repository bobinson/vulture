"""Feature 0076 section 5.3 — the anchor verifier, one authority.

A model claim must be checkable *without* a model: given a parsed LLM finding and
the file it accuses, decide whether the evidence quote can be located there. That
decision is the whole business contract of 0076, and it is decidable offline from
``(claim, file)`` alone.

LEAF (D17). This module takes an **already-resolved** ``Path`` and never resolves
one — resolution needs ``audit_runner._resolve_finding_path`` and importing it here
would close a cycle. ``None`` means the caller could not resolve the path, which is
``unreadable``. It never writes, never calls a model, and never raises: it runs on
the audit-producer thread, where an exception loses a whole batch of findings, and
losing findings is exactly the failure mode this feature exists to prevent.

WHY THE NARROWINGS. The naive verifier — "search the file, and if the quote is not
there the finding is fabricated" — over-refutes, and over-refutation deletes real
defects. Four narrowings stand against it:

  * the signal floor    a 20-char paraphrase is ``unquoted``, never ``absent`` (AC7)
  * ``near_miss``       a Jaccard >= NEAR_MISS_MIN window is non-demoting
  * ``found_elsewhere`` an exact match in a sibling of the same batch is a WRONG
                        PATH, not a fabrication, and is non-demoting
  * the oversize clamp  a truncated needle can never resolve to ``absent`` (AC28)

And in the other direction: **no status promotes** (AC27). On the adjudicated
population the promotion signal is anti-correlated with truth — the rows that quote
real code accurately and accuse it falsely are the best-quoting false positives — so
every status resolves to weight 0.0 except ``absent``, which is negative only when
``VULTURE_LLM_QUOTE_DEMOTE_ABSENT`` is on.

Every numeric knob is read at CALL time (D14), never captured at import.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path

from shared.env import env_truthy
from shared.tools.line_format import strip_line_number

__all__ = [
    "STATUSES",
    "AnchorResult",
    "anchor_weight",
    "clear_cache",
    "collapse_ws",
    "distance",
    "key",
    "max_delta",
    "normalise",
    "tokens",
    "verify_anchor",
    "windows",
]

# The nine-status vocabulary. A tenth status would carry no weight rule and no
# quality rank, so the set is declared once and asserted against by AC12.
STATUSES: frozenset[str] = frozenset({
    "exact", "reanchored", "ambiguous", "near_miss", "found_elsewhere",
    "absent", "unquoted", "unreadable", "oversize",
})

# VULTURE_LLM_QUOTE_<name> defaults (section 5.3). MAX_LINE_CHARS is PER LINE
# (matching tools/snippet.py and the judge's per-line cap); MAX_CHARS bounds the
# WHOLE quote.
_KNOB_DEFAULTS: dict[str, float] = {
    "MIN_CHARS": 24,
    "MIN_TOKENS": 2,
    "MAX_LINES": 3,
    "MAX_LINE_CHARS": 400,
    "MAX_CHARS": 1200,
    "RADIUS": 25,
    "MAX_DELTA": 200,
    "NEAR_MISS_MIN": 0.6,
}

# The one demoting weight in the feature, and the switch that arms it.
_ABSENT_WEIGHT = -1.0
_DEMOTE_ABSENT = "VULTURE_LLM_QUOTE_DEMOTE_ABSENT"

_WS_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+")
_HEADER_RE = re.compile(r"^--- .+ ---$")
# audit_runner joins rendered windows with a bare "..." (`"\n...\n".join`).
_ELISION = "..."

# Statuses that truncation must not relabel: they are facts about the model's
# output or about the file, not about where the (truncated) needle landed.
_TRUNCATION_OPAQUE = frozenset({"unquoted", "unreadable"})


@dataclass(frozen=True)
class AnchorResult:
    """What the verifier observed. It REPORTS; every actuator lives at the call site."""

    status: str
    reason: str = ""
    new_line: int | None = None
    delta: int | None = None
    candidates: int = 0
    other_path: str | None = None   # found_elsewhere only; recorded, never applied
    quote_chars: int = 0
    quote_tokens: int = 0


# ── knobs (call-time, D14) ───────────────────────────────────────────────────


def _knob(name: str) -> float:
    """One reader for every ``VULTURE_LLM_QUOTE_*`` numeric knob, at CALL time.

    A knob captured at import cannot be flipped by an operator mid-fleet, and cannot
    be exercised by a test that does not reload the module.
    """
    raw = os.getenv(f"VULTURE_LLM_QUOTE_{name}", "").strip()
    try:
        return float(raw)
    except ValueError:
        return _KNOB_DEFAULTS[name]


def _knob_int(name: str) -> int:
    """The integer knobs (line counts, character caps, line distances)."""
    return int(_knob(name))


def anchor_weight(status: str) -> float:
    """The ONE authority for the weight the ``anchor`` ValidationCheck carries.

    Every status is 0.0 — no anchor status may promote (AC27) — except ``absent``,
    and only while ``VULTURE_LLM_QUOTE_DEMOTE_ABSENT`` is on. With the switch off the
    weight is 0.0, **not** -1.0: leaving -1.0 applied while withholding the
    AUTHORITATIVE_CHECKS membership demotes through the additive path instead
    (``clamp(0.5 - 1.0) = 0.0`` -> ``suspicious``), which is the exact outcome the
    switch exists to prevent (AC34).
    """
    if status != "absent":
        return 0.0
    return _ABSENT_WEIGHT if env_truthy(_DEMOTE_ABSENT) else 0.0


# ── the five primitives ──────────────────────────────────────────────────────


def collapse_ws(text: str) -> str:
    """Runs of ANY whitespace — tabs, a stray CR, a space mix — become one space.

    This is what makes an indentation-only difference a match, which matters because
    the model copies from a listing whose ``"NN: "`` prefix has already shifted the
    column.
    """
    return _WS_RE.sub(" ", text).strip()


def normalise(line: str) -> str:
    """``collapse_ws(strip_line_number(line))`` — the comparable form of one line.

    The inner ``collapse_ws`` runs first so the prefix strip is insensitive to the
    indentation a copied listing line carries in front of its ``"NN: "``; the outer
    one folds whatever the strip leaves behind. ``strip_line_number`` is identity on
    an unprefixed line, so this is safe to apply unconditionally.

    NOT case-folded and NOT comment/string-stripped: an accusation about
    ``// TODO: fix auth`` or a hardcoded literal must match on its literal text,
    which is exactly why ``line_context.strip_strings_and_comments`` is NOT used
    here — blanking literals would make ``password = "hunter2"`` match
    ``password = ""`` and turn a real credential finding into a false ``exact``.
    """
    return collapse_ws(strip_line_number(collapse_ws(line)))


def tokens(text: str) -> list[str]:
    """Identifier-ish runs and integer literals.

    Punctuation is deliberately NOT a token: ``});`` must score 0 so the floor
    rejects it. It is the tokeniser MIN_TOKENS counts and the one ``distance`` uses.
    """
    return _TOKEN_RE.findall(text)


def _is_presentation(norm: str) -> bool:
    """True for a normalised line that is rendering, not code.

    Blank lines, the bare ``...`` elision marker, and a ``--- path ---`` block header
    (with or without 0075's ``(lines a-b omitted)`` suffix). One predicate so ``key``
    and ``windows`` drop exactly the same things — the symmetry is what lets a quote
    whose blank line the model omitted still match a window that kept it.
    """
    return not norm or norm == _ELISION or _HEADER_RE.match(norm) is not None


def _code_lines(lines: Sequence[str]) -> list[str]:
    """The normalised, presentation-free lines of a quote or a file slice."""
    return [norm for norm in map(normalise, lines) if not _is_presentation(norm)]


def key(lines: Sequence[str]) -> str:
    """The comparable form of a multi-line window: normalised code lines, ``\\n``-joined."""
    return "\n".join(_code_lines(lines))


def _numbered_code_lines(file_lines: Sequence[str]) -> list[tuple[int, str]]:
    """``(1-based line number, normalised text)`` for every non-presentation line."""
    return [
        (index + 1, norm)
        for index, norm in enumerate(map(normalise, file_lines))
        if not _is_presentation(norm)
    ]


def windows(file_lines: list[str], n: int) -> Iterator[tuple[int, str]]:
    """Every candidate window of ``n`` NON-BLANK lines, as (1-based start, key).

    Blank lines inside a window are skipped and do not count toward ``n``, matching
    ``key``'s own dropping. A window is anchored at the first non-blank line it
    contains. A file with fewer non-blank lines than ``n`` yields nothing — never a
    short window.
    """
    yield from _windows_from(tuple(_numbered_code_lines(file_lines)), n)


def _windows_from(kept: Sequence[tuple[int, str]], n: int) -> Iterator[tuple[int, str]]:
    """The window enumeration itself, over an ALREADY-normalised index.

    Split out so the cross-file search can reuse a cached index instead of
    re-normalising a whole file per finding (see ``_code_index``).
    """
    if n <= 0:
        return
    for first in range(len(kept) - n + 1):
        yield kept[first][0], "\n".join(norm for _line, norm in kept[first:first + n])


def distance(a: str, b: str) -> float:
    """Token Jaccard on ``tokens()``: ``|A n B| / |A u B|``, 0.0-1.0.

    Used ONLY to classify a non-match as ``near_miss`` rather than ``absent``. It
    NEVER selects a candidate — selection is exact-match only, because a fuzzy anchor
    that rewrites a line is precisely the over-refutation this feature avoids.
    """
    left, right = set(tokens(a)), set(tokens(b))
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


# ── the verifier ─────────────────────────────────────────────────────────────


def verify_anchor(finding: dict, file_path: Path | None, *, mode: str,
                  batch_paths: Sequence[Path] | None = None) -> AnchorResult:
    """Locate ``finding['evidence_quote']`` in ``file_path``. Never raises.

    ``mode`` ("observe" / "enforce") is accepted and deliberately unused for
    classification: the status is a fact about ``(claim, file)`` and cannot depend on
    how loudly the caller intends to act on it. Modes gate actuators — line
    rewriting and weights — at the call site, which is what makes "observe changes
    nothing" (AC10) checkable at all.

    ``batch_paths`` bounds the cross-file search to the files rendered in the same
    request: ``found_elsewhere`` is a real, bounded search, not a repository grep and
    not a blanket refusal to ever say ``absent``.
    """
    try:
        return _verify(finding, file_path, batch_paths)
    except Exception:  # a verifier that raises deletes a whole batch of findings
        return AnchorResult("unreadable", "verifier_error")


def _verify(finding: dict, file_path: Path | None,
            batch_paths: Sequence[Path] | None) -> AnchorResult:
    """Classify, then stamp the measured quote size onto whatever came back."""
    quoted = _code_lines(str(finding.get("evidence_quote") or "").splitlines())
    whole = "\n".join(quoted)
    outcome = _classify(finding, file_path, batch_paths, quoted)
    return replace(outcome, quote_chars=len(whole), quote_tokens=len(tokens(whole)))


def _classify(finding: dict, file_path: Path | None,
              batch_paths: Sequence[Path] | None, quoted: list[str]) -> AnchorResult:
    """Size gates first, then location. Nothing here reads the file."""
    if not quoted:
        return AnchorResult("unquoted", "missing")
    if max(map(len, quoted)) > _knob_int("MAX_LINE_CHARS"):
        # Whole-line truncation cannot shorten a single line, and a mid-line cut
        # manufactures a needle that exists nowhere. Refuse it as evidence instead.
        return AnchorResult("unquoted", "line_too_long")
    needle_lines, truncated = _truncate(quoted)
    return _size_status(_locate(finding, file_path, batch_paths, needle_lines), truncated)


def _truncate(quoted: list[str]) -> tuple[list[str], bool]:
    """Whole-line truncation to MAX_LINES then MAX_CHARS. Returns (lines, truncated)."""
    kept = quoted[:_knob_int("MAX_LINES")]
    budget = _knob_int("MAX_CHARS")
    while len(kept) > 1 and len("\n".join(kept)) > budget:
        kept = kept[:-1]
    return kept, kept != quoted


def _size_status(outcome: AnchorResult, truncated: bool) -> AnchorResult:
    """``oversize`` is terminal, and the hard clamp keeps it off ``absent`` (AC28).

    Truncation discards lines the model may have quoted correctly, so a truncated
    evaluation that lands on ``absent`` is a fabrication manufactured by us, not by
    the model. It becomes ``unquoted(oversize_truncated)`` instead.
    """
    if not truncated or outcome.status in _TRUNCATION_OPAQUE:
        return outcome
    if outcome.status == "absent":
        return AnchorResult("unquoted", "oversize_truncated")
    # The status is terminal, but the VERDICT the truncated quote earned is real
    # evidence and must not be thrown away with it. Measured while dogfooding on
    # togetherapp: 5 of 19 LLM rows were `oversize` and THREE carried delta=0 —
    # their truncated prefix matched exactly at the cited line. Collapsing those
    # into the same bucket as a quote that located nowhere makes a quarter of the
    # tier read as failure when most of it succeeded, and leaves the operator no
    # way to tell which. `reason` carries the decomposition; `new_line`, `delta`
    # and `candidates` already survive via replace().
    return replace(outcome, status="oversize",
                   reason=f"truncated:{outcome.status}")


def _locate(finding: dict, file_path: Path | None,
            batch_paths: Sequence[Path] | None, needle_lines: list[str]) -> AnchorResult:
    """The floor, the file, then exact selection with a non-demoting fallback."""
    needle = "\n".join(needle_lines)
    if not _passes_floor(needle):
        # Not admissible EVIDENCE, so not a fabrication: the model failed to comply.
        return AnchorResult("unquoted", "below_floor")
    file_lines = _read_lines(file_path)
    if file_lines is None:
        return AnchorResult("unreadable", _unread_reason(file_path))
    span = len(needle_lines)
    hit = _select_hit(needle, span, file_lines, _claimed_line(finding))
    if hit is not None:
        return hit
    return _fallback(needle, span, file_lines, file_path, batch_paths)


def _unread_reason(file_path: Path | None) -> str:
    """Which half of ``unreadable`` this was: the caller resolved nothing, or the
    resolved path could not be read. Both weigh the same; only the metric differs."""
    return "no_path" if file_path is None else "unreadable"


def _passes_floor(needle: str) -> bool:
    """MIN_CHARS **and** MIN_TOKENS. Both halves are load-bearing and separable.

    A needle below the floor cannot discriminate a location — 91% of lines such as
    ``});`` are non-unique inside one file — so it must not be allowed to refute one.
    """
    return (len(needle) >= _knob_int("MIN_CHARS")
            and len(tokens(needle)) >= _knob_int("MIN_TOKENS"))


def _select_hit(needle: str, span: int, file_lines: list[str],
                claimed: int) -> AnchorResult | None:
    """Exact-match selection in the cited file, or ``None`` when nothing matches."""
    found = _candidates(needle, span, file_lines)
    if not found:
        return None
    if claimed in found:
        return AnchorResult("exact", new_line=claimed, delta=0, candidates=len(found))
    return _reanchor(found, claimed)


def _candidates(needle: str, span: int, file_lines: list[str]) -> list[int]:
    """Start lines of every window whose key EQUALS the needle. Never fuzzy."""
    return [start for start, text in windows(file_lines, span) if text == needle]


def _reanchor(found: list[int], claimed: int) -> AnchorResult:
    """Move the claim only when one candidate is unambiguously the nearest."""
    ordered = sorted(found, key=lambda start: (abs(start - claimed), start))
    delta = ordered[0] - claimed
    if not _may_move(ordered, claimed, delta):
        return AnchorResult("ambiguous", "not_unique", candidates=len(found))
    return AnchorResult("reanchored", new_line=ordered[0], delta=delta,
                        candidates=len(found))


def _may_move(ordered: list[int], claimed: int, delta: int) -> bool:
    """MAX_DELTA absolutely, then the STRICT tie-break bounded by RADIUS.

    A lone candidate re-anchors regardless of RADIUS — RADIUS arbitrates BETWEEN
    competing occurrences. Two occurrences equidistant from the claim stay
    ``ambiguous`` however wide the radius is, because picking one would be arbitrary.
    """
    if abs(delta) > _knob_int("MAX_DELTA"):
        return False
    if len(ordered) == 1:
        return True
    runner_up = abs(ordered[1] - claimed)
    return abs(delta) < runner_up and abs(delta) <= _knob_int("RADIUS")


def _fallback(needle: str, span: int, file_lines: list[str], file_path: Path | None,
              batch_paths: Sequence[Path] | None) -> AnchorResult:
    """No exact match in the cited file — narrow ``absent`` before reaching for it."""
    other = _search_batch(needle, span, file_path, batch_paths)
    if other is not None:
        return AnchorResult("found_elsewhere", "cross_file", other_path=other)
    if _best_distance(needle, span, file_lines) >= _knob("NEAR_MISS_MIN"):
        return AnchorResult("near_miss", "similar")
    return AnchorResult("absent", "not_found")


def _search_batch(needle: str, span: int, file_path: Path | None,
                  batch_paths: Sequence[Path] | None) -> str | None:
    """The first sibling of the batch containing the quote, recorded not applied."""
    for other in _siblings(file_path, batch_paths):
        if _contains(other, needle, span):
            return str(other)
    return None


def clear_cache() -> None:
    """Drop the normalised-line index. Called by ``file_scanner.clear_caches``.

    The index is keyed on the path STRING with no mtime, exactly like the
    ``read_file_lines`` cache beneath it, so the two must be invalidated
    TOGETHER. Left out, a second audit in the same process verified quotes
    against the previous run's content — and because a stale miss yields
    ``absent``, that is the one status that can demote.
    """
    _code_index.cache_clear()


def max_delta() -> int:
    """The absolute ceiling on how far a re-anchor may move a line (§5.3).

    Public because the ACTUATOR lives in ``audit_runner`` while the bound is part
    of this module's vocabulary; a caller reaching for ``_knob_int`` would be
    depending on a private name across a module boundary.
    """
    return _knob_int("MAX_DELTA")


def _siblings(file_path: Path | None,
              batch_paths: Sequence[Path] | None) -> list[Path]:
    """The batch minus the cited file itself — the bounded cross-file search space."""
    return [other for other in batch_paths or () if other != file_path]


@lru_cache(maxsize=1024)
def _code_index(path_str: str) -> tuple[tuple[int, str], ...]:
    """The file's numbered, normalised CODE lines — computed once per file.

    `windows()` maps `normalise` (two regex substitutions plus a prefix strip)
    over every line, and the cross-file `found_elsewhere` search calls it once
    per sibling PER FINDING. Uncached that is O(findings x files) full
    normalisation passes — measured at ~5 ms for a 3,300-line file, so ~8 s of
    pure re-normalisation for one batch of 40 findings over 40 files. The plan's
    §11 states the cost is per-FILE; this is what makes that true.

    Keyed on the path string because `read_file_lines` beneath it is keyed the
    same way, so the two caches hit or miss together.
    """
    lines = _read_lines(Path(path_str))
    return () if lines is None else tuple(_numbered_code_lines(lines))


def _windows_of(path: Path, n: int) -> Iterator[tuple[int, str]]:
    """`windows()` over the cached index rather than a fresh normalisation."""
    return _windows_from(_code_index(str(path)), n)


def _contains(path: Path, needle: str, span: int) -> bool:
    """Whether an exact window of ``path`` equals the needle. Unreadable is False."""
    return any(text == needle for _start, text in _windows_of(path, span))


def _best_distance(needle: str, span: int, file_lines: list[str]) -> float:
    """The closest any window in the cited file gets — the ``near_miss`` evidence."""
    return max((distance(needle, text) for _start, text in windows(file_lines, span)),
               default=0.0)


def _read_lines(path: Path | None) -> list[str] | None:
    """The file's lines, or ``None`` for "no path" and "cannot be read" alike.

    The caller owns resolution (D17); a path that resolves but cannot be read is the
    same fact to this verifier as no path at all, and both are charged once — by
    L1's own path check, never a second time here.
    """
    if path is None:
        return None
    from shared.tools.file_scanner import read_file_lines

    lines = read_file_lines(path)
    return None if lines is None else list(lines)


def _claimed_line(finding: dict) -> int:
    """The model's ``line_start``, or 0 when it gave none or gave nonsense."""
    try:
        return int(finding.get("line_start") or 0)
    except (TypeError, ValueError):
        return 0
