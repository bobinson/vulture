"""Feature 0091 §6.2 — answering the backend's lineage evidence questions.

THE QUESTION. The backend sends every LLM-tier lineage row it wants an opinion
on (§6.1 ``lineage_checks_requested``) and gets back one outcome per row. It
cannot decide these itself: the evidence quote never crosses the agent boundary
(``audit_runner._PRIVATE_FIELDS``), so only this process holds both the quote
and the current file.

THE LADDER, in priority order, and the order IS the design::

    quote absent from the store, or its hash disagrees  -> unconfirmable(no_quote)
    rel_path empty, or escaping the scanned root        -> unconfirmable(<reason>)
    file missing (ENOENT)                               -> gone(file_missing)
    a directory or other non-regular file               -> unconfirmable(not_a_file)
    any other stat error (ELOOP, ENOTDIR, EACCES, ...)  -> unconfirmable(unreadable:<code>)
    unreadable / binary / over VULTURE_MAX_FILE_SIZE    -> unconfirmable(<reason>)
    the verifier raises anything at all                 -> unconfirmable(error:<Type>)
    anchor exact | near_miss                            -> confirmed
    anchor reanchored | found_elsewhere                 -> reanchored (+ new window)
    anchor ambiguous                                    -> ambiguous
    anchor absent                                       -> gone

``gone`` is the ONLY outcome that closes a finding. Every failure that is a
fact about the CHECKER rather than about the CODE — a lost cache entry, a file
too large to read, a crashing verifier — therefore has to land on
``unconfirmable``. A checker that says ``gone`` when it merely could not look is
the cheapest possible way to close every finding in a codebase at once.

WHICH IS WHY THE STAT IS CLASSIFIED BY ERRNO. ``Path.is_file()`` answers False
for two entirely different facts — "there is no such file" and "I could not
find out" — and swallows ELOOP, ENOTDIR and EACCES into the same False as
ENOENT. Only the first fact may close a finding. A path naming a DIRECTORY is
the same trap from the other side and is not hypothetical: chaos and asvs
findings ("no circuit breaker patterns detected", "endpoints may lack rate
limiting") legitimately cite a package directory rather than a line.

CONFINEMENT. ``rel_path`` reaches here from a lineage row whose ``file_path``
was, for the LLM tier, authored by the model. ``base / rel`` yields ``rel``
verbatim when ``rel`` is absolute and pathlib never collapses ``..``, so
without a guard this module would stat, read, verify and return a sha256 of
any file on the host — the arbitrary-file-read channel
``audit_runner._resolve_finding_path`` documents and refuses for the finding
path. This is the second file-reading path on the same untrusted string and
obeys the same rule, through the same helper.

COST. One read per distinct FILE, not per row: the reader is the scan's own
warm ``file_scanner`` cache (the skill phase has already populated it), and the
per-call state map collapses many rows citing one file onto a single stat+read.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared import anchor
from shared.quote_store import lookup, lookup_by_hash, quote_hash
from shared.tools.confine import is_within_root

__all__ = ["quote_hash", "verify_lineage_checks"]

logger = logging.getLogger(__name__)

#: Reads one resolved file, returning its text or ``None`` when it cannot.
FileReader = Callable[[Path], "str | None"]

# The nine anchor statuses (0076) mapped onto the five wire outcomes (§6.1).
# Anything NOT here — ``unquoted``, ``unreadable``, ``oversize`` — is a fact
# about the quote or the reader, so it falls through to ``unconfirmable``
# rather than to a status that could close a live finding.
_OUTCOME_BY_ANCHOR_STATUS: dict[str, str] = {
    "exact": "confirmed",
    "near_miss": "confirmed",
    "reanchored": "reanchored",
    "found_elsewhere": "reanchored",
    "ambiguous": "ambiguous",
    "absent": "gone",
}

# ``anchor.verify_anchor`` swallows its own exceptions and reports this reason.
# Re-labelled so the wire says what the ladder says (S25) rather than hiding a
# crash inside a generic "unreadable".
_VERIFIER_ERROR = "verifier_error"


@dataclass(frozen=True)
class _FileState:
    """What one read of one cited file established. Computed at most once."""

    path: Path
    problem: str      # "" when the text is usable; otherwise the refusal reason
    text: str | None
    file_hash: str | None


def verify_lineage_checks(
    rows: list[dict[str, Any]] | None,
    root: str | Path,
    file_cache: FileReader | None = None,
) -> list[dict[str, Any]]:
    """One check per requested row, in request order.

    Args:
        rows: the ``lineage_checks_requested["rows"]`` payload (§6.1).
        root: the scanned source root; ``rel_path`` is resolved against it.
        file_cache: reader for a resolved path. Defaults to the scan's warm
            ``file_scanner`` cache, which is what makes this one read per file.

    Never drops a row: a requested row with no check is read by the backend as
    ``unconfirmable(missing)`` (§6.4), so silently omitting one would degrade a
    live finding on every scan.
    """
    if not rows:
        return []
    reader = file_cache or _read_through_scan_cache
    base = Path(root)
    states: dict[str, _FileState] = {}
    return [_check_row(row, base, reader, states) for row in rows]


def _check_row(row: dict[str, Any], base: Path, reader: FileReader,
               states: dict[str, _FileState]) -> dict[str, Any]:
    """The ladder itself, for one row."""
    lineage_id = str(row.get("lineage_id") or "")
    start, end = _row_window(row)
    quote = _resolve_quote(row)
    if quote is None:
        return _result(lineage_id, "unconfirmable", "no_quote", start, end, None)
    state = _state_for(states, base, str(row.get("rel_path") or ""), reader)
    if state.problem == "file_missing":
        return _result(lineage_id, "gone", "file_missing", start, end, None)
    if state.problem:
        return _result(lineage_id, "unconfirmable", state.problem, start, end,
                       state.file_hash)
    return _verified(lineage_id, quote, state, start, end)


def _resolve_quote(row: dict[str, Any]) -> str | None:
    """The quote this row was made from, or ``None`` (S9).

    ``fingerprint_v2`` first, because that is the identity §6.2 names. The hash
    fallback covers every row written by the emit path, which is
    content-addressed (the agent has no ``fingerprint_v2`` when it emits).
    A quote that disagrees with the row's hash is discarded rather than used:
    confirming a finding against evidence it was not made from is worse than
    not confirming it.
    """
    want = str(row.get("quote_hash") or "").strip()
    fp2 = str(row.get("fingerprint_v2") or "").strip()
    quote = lookup(fp2) if fp2 else None
    if not quote and want:
        quote = lookup_by_hash(want)
    if not quote:
        return None
    return quote if not want or quote_hash(quote) == want else None


def _verified(lineage_id: str, quote: str, state: _FileState,
              start: int, end: int) -> dict[str, Any]:
    """Run the 0076 verifier over the cited file and translate what it says.

    The verifier documents that it never raises; it is wrapped anyway, because
    the one thing this function must never do on an unexpected error is return
    ``gone`` (S25), and "documented not to raise" is not the same as "cannot".
    """
    claim = {"evidence_quote": quote, "line_start": start}
    try:
        outcome = anchor.verify_anchor(claim, state.path, mode="observe")
    except Exception as exc:  # never `gone` on an error path
        logger.warning("lineage_check_verifier_error id=%s error=%s", lineage_id, exc)
        return _result(lineage_id, "unconfirmable", f"error:{type(exc).__name__}",
                       start, end, state.file_hash)
    return _translate(lineage_id, outcome, quote, state, start, end)


def _translate(lineage_id: str, outcome: anchor.AnchorResult, quote: str,
               state: _FileState, start: int, end: int) -> dict[str, Any]:
    """One ``AnchorResult`` onto one wire row."""
    mapped = _OUTCOME_BY_ANCHOR_STATUS.get(outcome.status)
    if mapped is None:
        return _result(lineage_id, "unconfirmable", _unmapped_reason(outcome),
                       start, end, state.file_hash)
    new_start, new_end = _window(outcome, quote, start, end)
    return _result(lineage_id, mapped, outcome.reason or outcome.status,
                   new_start, new_end, state.file_hash)


def _unmapped_reason(outcome: anchor.AnchorResult) -> str:
    """Why a status outside the ladder could not decide anything."""
    reason = outcome.reason or outcome.status or "unknown"
    return f"error:{_VERIFIER_ERROR}" if reason == _VERIFIER_ERROR else reason


def _window(outcome: anchor.AnchorResult, quote: str,
            start: int, end: int) -> tuple[int, int]:
    """The verified window, or the claimed one when the verifier moved nothing."""
    if outcome.new_line is None:
        return start, end
    span = max(1, len(anchor.key(quote.splitlines()).splitlines()))
    return outcome.new_line, outcome.new_line + span - 1


def _row_window(row: dict[str, Any]) -> tuple[int, int]:
    """The window the row claims, coerced and ordered."""
    start = _as_int(row.get("line_start"))
    return start, max(start, _as_int(row.get("line_end")))


def _as_int(value: Any) -> int:
    """``value`` as a non-negative int; junk costs the field, never the row."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _state_for(states: dict[str, _FileState], base: Path, rel: str,
               reader: FileReader) -> _FileState:
    """The cited file's state, computed once per distinct ``rel_path``."""
    cached = states.get(rel)
    if cached is None:
        cached = _read_state(base, rel, reader)
        states[rel] = cached
    return cached


def _read_state(base: Path, rel: str, reader: FileReader) -> _FileState:
    """Confine, stat, guard, read, hash — the only I/O this module performs."""
    path, problem = _resolve_cited(base, rel)
    if problem:
        return _FileState(path, problem, None, None)
    problem = _read_problem(path)
    if problem:
        return _FileState(path, problem, None, None)
    text = reader(path)
    if text is None:
        return _FileState(path, "unreadable", None, None)
    if "\x00" in text:
        # A NUL byte survives the reader's errors="replace" decode, so this
        # costs no extra read. A binary file is not evidence either way.
        return _FileState(path, "binary", None, None)
    return _FileState(path, "", text, _hash_text(text))


def _resolve_cited(base: Path, rel: str) -> tuple[Path, str]:
    """The cited file as an on-disk path, CONFINED to the scanned root.

    Returns ``(path, "")`` when the citation may be read, otherwise
    ``(path, reason)``. Both refusals are facts about the REQUEST rather than
    about the code, so both resolve to ``unconfirmable`` and neither can close
    a finding.

    An empty ``rel_path`` is refused rather than silently resolving to the
    scan root — statting the root answered ``not_a_file`` (and, before that,
    ``gone``) for a question nobody asked.

    The containment DECISION stays with ``tools.confine.is_within_root``, so
    there is one definition of "inside the tree" shared with the LLM-facing
    file tools. Resolution is attempted here first only to tell the two
    failures apart: that helper fails closed, so an unresolvable path (a
    symlink loop, a permission denial part-way down) would otherwise be
    reported as an escape attempt when it is an ordinary checker fault.
    """
    if not rel:
        return base, "no_path"
    candidate = base / rel  # NB: an ABSOLUTE rel replaces base entirely
    try:
        root = base.resolve()
        resolved = candidate.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        return candidate, f"unreadable:{_fault_label(exc)}"
    if not is_within_root(resolved, root):
        return candidate, "outside_root"
    return candidate, ""


def _read_problem(path: Path) -> str:
    """``""`` when the file may be read; otherwise why the reader refuses.

    Classified from ``os.stat``'s errno rather than from ``Path.is_file()``,
    because ``is_file()`` collapses "there is no such file" and "I could not
    find out" (ELOOP, ENOTDIR, EACCES) into one False — and only the first of
    those may close a finding. ``Path.exists()`` swallows the same errors, so
    testing it first would not separate them either.

    A path that resolves to something OTHER than a regular file — a directory
    above all — is likewise not evidence of repair: architectural findings
    cite directories on purpose.

    ``oversize`` is deliberately distinct from every other refusal and from
    ``file_missing``: the quote may well still be in there, and closing a
    finding because a file grew past the read cap (S23) is precisely the
    failure this ladder exists to prevent.
    """
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return "file_missing"
    except OSError as exc:
        return f"unreadable:{_fault_label(exc)}"
    if not stat.S_ISREG(info.st_mode):
        return "not_a_file"
    cap = _max_file_size()
    return f"oversize:{info.st_size}>{cap}" if info.st_size > cap else ""


def _fault_label(exc: BaseException) -> str:
    """``ELOOP``/``ENOTDIR``/… for an OS error, the exception type name
    otherwise (pathlib reports a symlink loop as ``RuntimeError``). The label
    is operator-facing only: every value that reaches it lands on
    ``unconfirmable`` regardless."""
    if isinstance(exc, OSError):
        return errno.errorcode.get(exc.errno or 0) or type(exc).__name__
    return type(exc).__name__


def _max_file_size() -> int:
    """``VULTURE_MAX_FILE_SIZE`` at CALL time, falling back to the scanner's."""
    from shared.tools import file_scanner

    raw = os.getenv("VULTURE_MAX_FILE_SIZE", "").strip()
    try:
        return int(raw) if raw else file_scanner.MAX_FILE_SIZE
    except ValueError:
        return file_scanner.MAX_FILE_SIZE


def _read_through_scan_cache(path: Path) -> str | None:
    """The scan's own warm file cache — the same entry the skills read."""
    from shared.tools.file_scanner import read_file_safe

    return read_file_safe(path, _max_file_size())


def _hash_text(text: str) -> str:
    """``"sha256:" + sha256(text)`` over the DECODED file.

    Decoded rather than raw bytes so it is computed from the cache entry the
    scan already holds — no second read — and so the same file yields the same
    hash on every scan that reads it the same way. The backend only ever
    compares this value to another value produced here (§6.3).
    """
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _result(lineage_id: str, outcome: str, reason: str,
            line_start: int, line_end: int, file_hash: str | None) -> dict[str, Any]:
    """One row of the ``lineage_checks`` wire array (§6.1)."""
    return {
        "lineage_id": lineage_id,
        "outcome": outcome,
        "reason": reason,
        "line_start": line_start,
        "line_end": line_end,
        "file_hash": file_hash,
    }
