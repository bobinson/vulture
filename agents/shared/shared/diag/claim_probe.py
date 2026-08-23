"""Label a stored set of LLM claims against the tree they accuse (feature 0076 T0.2).

    python -m shared.diag.claim_probe /path/to/tree --claims claims.json

prints a JSON blob: one record per claim, a zero-filled label histogram, the anchor
status histogram, and the ``anchor_delta`` distribution.

WHY THIS EXISTS. The anchor histogram is 0076's headline measurement, and the only
other way to obtain it is a full scan: ~21-25 minutes through a tier that repeats
~29% of its own findings between identical runs, so any difference between two runs
is confounded with sampling noise before it can be attributed to a change. This
module replays a *saved* findings set through the same verifier the run uses, at
zero model cost — §11's "converts a 5-hours-per-arm stochastic experiment into a
JSON diff". Re-adjudicating the 108-row and 50-row unions becomes a command.

STRUCTURAL RULE (T0.4, mirroring 0075's ``feed_probe``). The probe **calls**
``anchor.verify_anchor`` and ``feed_probe.render_feed``; it re-derives neither. A
probe that reimplements the thing it measures reports a shape no real run produces,
which is worse than no probe because it looks like evidence. Path resolution,
dedup keys and the snippet radius come from ``audit_runner`` for the same reason.

CONSTRAINTS (T0.6 / AC22). No model, no socket, no write to the scanned tree, and a
bit-identical rerun on identical input. All four are asserted by
``tests/unit/test_0076_claim_probe.py``.

WHAT IT DOES NOT MEASURE. Localisation, never truth: a claim can be ``exact`` and
still be a false accusation. ``guard_within_window`` is a vocabulary proxy, not a
proof that the named mitigation is the one the finding says is missing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared import anchor
from shared.audit_runner import (
    _dedup_key,
    _normalize_dedup_path,
    _resolve_finding_path,
    _snippet_context_lines,
    _split_source_blocks,
)
from shared.diag import feed_probe
from shared.tools.file_scanner import read_file_lines
from shared.tools.line_context import (
    file_has_sink,
    is_declaration_context,
    is_diagnostic_line,
    strip_strings_and_comments,
)
from shared.tools.line_format import NUMBER_RE

# Every label the blob can carry, in report order. The histogram is ZERO-FILLED
# from this roster so a diff of two blobs never has to distinguish "absent key"
# from "count 0" — a probe whose output shape depends on its input is not
# diffable, which is the one job it has.
LABELS: tuple[str, ...] = (
    "quote_absent",
    "quote_not_in_file",
    "quote_at_other_line",
    "anchor_is_declaration",
    "anchor_is_diagnostic",
    "guard_within_window",
    "guard_outside_window",
    "guard_within_wide_window",
    "guard_outside_wide_window",
    "declarative_line_unset",
    "range_invalid",
    "intra_file_duplicate",
    "line_not_in_prompt",
)

# The quote located SOMEWHERE OTHER than the cited file (or nowhere at all).
# ``near_miss`` and ``found_elsewhere`` are non-demoting statuses, but both are
# still facts about the cited file not containing the text.
_NOT_IN_FILE = frozenset({"absent", "near_miss", "found_elsewhere"})

# The quote is in the cited file, at a line the model did not cite. ``ambiguous``
# belongs here: candidates exist and the claimed line is not among them (a claimed
# line that IS among them resolves to ``exact`` before re-anchoring is considered).
_OTHER_LINE = frozenset({"reanchored", "ambiguous"})

# Dialects where a finding is routinely scoped to the DOCUMENT rather than to a
# line. F1 measured 49 of 67 `.graphql` rows as `1 -> EOF` spans against 1 of 217
# elsewhere, so `line_start <= 1` means something different here than in code and
# must be counted separately rather than as a degenerate anchor.
_DECLARATIVE_SUFFIXES = frozenset({
    ".graphql", ".gql", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".xml", ".proto", ".sql", ".tf", ".hcl", ".tfvars",
})

# The mitigation vocabulary. §10 names the largest FP class — `guard_present`, 26 of
# 108 — and the deterministic check that would reach it: "does this file contain the
# guard the finding says is missing?". 0076 ships the INSTRUMENT and no actuator, so
# this is deliberately a coarse vocabulary proxy rather than a per-category rule, and
# it is a PARAMETER (`--guard-pattern`) so a sharper pattern can be swept over the
# same frozen claim set without touching this module.
_DEFAULT_GUARD_PATTERN = (
    r"\b(?:auth\w*|permission\w*|role\w*|scope\w*|"
    r"valid\w*|sanitiz\w*|sanitis\w*|escap\w*|encodeURI\w*|"
    r"verif\w*|assert\w*|guard\w*|require\w*|"
    r"allowlist|whitelist|denylist|blocklist|"
    r"csrf|xsrf|rate_?limit\w*|throttl\w*|"
    r"catch|except|ensure)\b"
)

# How much wider the second guard radius is than `_snippet_context_lines()`. The
# pair is the point: one radius cannot say whether a guard sat outside the window
# the model was shown, which is the only thing that quantifies the +/-10 claim.
_WIDE_RADIUS_MULTIPLIER = 5


def _radius() -> int:
    """RADIUS, read through ``anchor``'s own knob reader.

    T3.12 wants the share of re-anchor deltas inside RADIUS, and ``anchor`` exports
    ``max_delta()`` but no ``radius()``. Re-declaring the default here would make
    this module a SECOND authority for a ``VULTURE_LLM_QUOTE_*`` knob — the one
    thing §5.3 forbids — so the private reader is called instead. A public
    ``anchor.radius()`` is a one-line follow-up; this call site is why.
    """
    return anchor._knob_int("RADIUS")


# ── reading a stored claim ───────────────────────────────────────────────────


def _text(claim: dict, name: str) -> str:
    """A stored string field, normalised to "" — a claim is model output and any
    field of it can be missing, null, or a number."""
    return str(claim.get(name) or "")


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _checks(claim: dict) -> list:
    """The persisted ``validation.checks`` list, or ``[]``."""
    return (claim.get("validation") or {}).get("checks") or []


# The persisted `id` of the check `run_l1` emits for the verifier
# (`validate/context_heuristics.py:_ANCHOR_ID`). Named here as the READ side of a
# wire value rather than imported, because a probe must not pull the validate
# package in to read a JSON blob it was handed.
_ANCHOR_CHECK_ID = "anchor"


def _is_anchor_check(check: Any) -> bool:
    return isinstance(check, dict) and check.get("id") == _ANCHOR_CHECK_ID


def _anchor_extras(claim: dict) -> dict:
    """``validation.checks[id == "anchor"].extras`` — the ONE persisted egress route
    for the verifier's output (§5.4(4)), or ``{}`` for a row that predates it."""
    for check in _checks(claim):
        if _is_anchor_check(check):
            return check.get("extras") or {}
    return {}


def _claim_quote(claim: dict, extras: dict) -> str:
    """The evidence quote as persisted.

    ``evidence_quote`` is stripped before egress in EVERY configuration (§5.4(2)),
    so a row read back from the database carries it only under
    ``VULTURE_LLM_QUOTE_KEEP_TEXT``, redacted, in the anchor check's extras. A
    freshly captured in-process finding still has the top-level field, and that one
    wins because it is the unredacted original.
    """
    return str(claim.get("evidence_quote") or extras.get("quote_redacted") or "")


def _replay_finding(claim: dict, extras: dict) -> dict:
    """The dict handed to the verifier: the model's ORIGINAL claim.

    A persisted row may already carry a re-anchored ``line_start``. Verifying
    against the corrected line reports ``exact`` and erases the very delta this
    probe exists to measure, so the pre-correction line — which travels in the
    check's ``claimed_line`` extra — is preferred whenever it is there.
    """
    claimed = extras.get("claimed_line", claim.get("line_start"))
    return {"evidence_quote": _claim_quote(claim, extras), "line_start": _int(claimed)}


# ── the rendered feed, as the sweep rendered it ──────────────────────────────


def _rendered_numbers(block: str) -> set[int]:
    """The ABSOLUTE line numbers a rendered block actually shows the model.

    Read with ``line_format.NUMBER_RE`` — the one read-direction pattern (AC19/C1),
    the exact inverse of the writer that produced the block.
    """
    found = (NUMBER_RE.match(line) for line in block.split("\n"))
    return {int(match.group(2)) for match in found if match}


def _index_batch(text: str, paths: list[str], source_path: str,
                 index: dict[str, Any]) -> bool:
    """Fold one rendered batch into the feed index. False when it cannot be split.

    ``_split_source_blocks`` is the sweep's own segmentation and emits blocks in the
    same order ``_build_source_batches`` appended their paths, so the join needs no
    second header parser (T0.3(b)). A count mismatch means a content line imitated a
    block header; the batch is reported unmatched rather than mis-attributed.
    """
    blocks = _split_source_blocks(text)
    if len(blocks) != len(paths):
        return False
    for rel, block in zip(paths, blocks):
        key = _normalize_dedup_path(rel, source_path)
        index["lines"].setdefault(key, set()).update(_rendered_numbers(block))
        index["batch_of"][key] = tuple(
            _normalize_dedup_path(other, source_path) for other in paths
        )
        index["resolved"].setdefault(key, _resolve_finding_path(rel, source_path))
    return True


def _feed_index(feed: dict, source_path: str) -> dict[str, Any]:
    """Rendered line numbers, batch membership and resolved paths, per file."""
    index: dict[str, Any] = {
        "lines": {}, "batch_of": {}, "resolved": {}, "unmatched_batches": 0,
    }
    for text, paths in feed["batches"]:
        if not _index_batch(text, paths, source_path, index):
            index["unmatched_batches"] += 1
    return index


# ── the labels ───────────────────────────────────────────────────────────────


def _quote_labels(quote: str, result: anchor.AnchorResult) -> dict[str, bool]:
    """The three quote labels. ``quote_absent`` is a fact about the CLAIM (the field
    is missing — 100% of pre-0076 rows, T0.5's keystone), not about the search."""
    return {
        "quote_absent": not quote.strip(),
        "quote_not_in_file": result.status in _NOT_IN_FILE,
        "quote_at_other_line": result.status in _OTHER_LINE,
    }


def _line_text(path: Path | None, line: int) -> str:
    """The 1-based line, or "" when there is no such line to read."""
    lines = _file_lines(path)
    return lines[line - 1] if 0 < line <= len(lines) else ""


def _file_lines(path: Path | None) -> tuple[str, ...]:
    """The file's lines through the ONE cached reader, or () when unreadable."""
    if path is None:
        return ()
    return read_file_lines(path) or ()


_CALL_SITE_RE = re.compile(r"\b[A-Za-z_]\w*\s*\(")


def _match_start(text: str) -> int | None:
    """The offset a DETECTOR would have passed: the first call site on the line.

    Every skill that consults ``is_declaration_context`` passes the start of its own
    regex match, and every such match is a sink — a call. The probe holds a line and
    no match, so it uses the line's first call. A line with no call has no sink to be
    a declaration OF and is not classified at all: passing the first non-blank column
    instead trips the helper's bare-member branch, whose fallback is
    ``line.endswith(";")``, and then every ordinary statement (``const a = 1;``) is
    labelled a declaration and the label measures nothing.
    """
    match = _CALL_SITE_RE.search(text)
    return match.start() if match else None


def _context_labels(path: Path | None, line: int) -> dict[str, bool]:
    """Is the anchored line a DECLARATION or a DIAGNOSTIC rather than a sink?"""
    text = _line_text(path, line)
    start = _match_start(text)
    return {
        "anchor_is_declaration": start is not None and is_declaration_context(text, start),
        "anchor_is_diagnostic": is_diagnostic_line(text),
    }


def _guard_hits(path: Path | None, pattern: re.Pattern[str]) -> tuple[int, ...]:
    """1-based lines whose CODE matches the guard vocabulary.

    ``file_has_sink`` (:125) is the cheap cached whole-file gate; the per-line
    ``strip_strings_and_comments`` (:39) is the expensive half and must not run on a
    file with no occurrence at all. The strip is what makes a guard NAMED in a
    comment ("remember to validateToken here one day") not count as one present.
    """
    if path is None or not file_has_sink(path, pattern):
        return ()
    return _guard_lines(path, pattern)


def _guard_lines(path: Path, pattern: re.Pattern[str]) -> tuple[int, ...]:
    """The per-line half: every line whose CODE — literals blanked, comments cut —
    carries the vocabulary."""
    return tuple(
        number for number, text in enumerate(_file_lines(path), 1)
        if pattern.search(strip_strings_and_comments(text))
    )


def _within(hits: tuple[int, ...], line: int, radius: int) -> bool:
    return any(abs(hit - line) <= radius for hit in hits)


def _guard_labels(hits: tuple[int, ...], line: int, narrow: int,
                  wide: int) -> dict[str, bool]:
    """Evaluated at TWO radii. One radius cannot say whether the mitigation sat
    outside the window the model was shown, and that is the whole ±10 question."""
    near, far = _within(hits, line, narrow), _within(hits, line, wide)
    return {
        "guard_within_window": near,
        "guard_outside_window": bool(hits) and not near,
        "guard_within_wide_window": far,
        "guard_outside_wide_window": bool(hits) and not far,
    }


def _suffix(path_key: str) -> str:
    base = path_key.rsplit("/", 1)[-1]
    return ("." + base.rsplit(".", 1)[-1]).lower() if "." in base else ""


def _range_invalid(start: int, end: int, line_count: int) -> bool:
    """Unset, inverted, or past the end of a file we could actually read."""
    return start <= 0 or end < start or (line_count > 0 and start > line_count)


def _shape_labels(claim: dict, path_key: str, start: int,
                  path: Path | None) -> dict[str, bool]:
    """The labels that need no quote — the only ones computable on a stored row."""
    end = _int(claim.get("line_end")) or start
    return {
        "declarative_line_unset": _suffix(path_key) in _DECLARATIVE_SUFFIXES and start <= 1,
        "range_invalid": _range_invalid(start, end, len(_file_lines(path))),
    }


def _not_in_prompt(ctx: _Context, path_key: str, line: int) -> bool:
    """Whether the cited line was ever rendered for the model to read it off.

    A file the prioritiser dropped (tier-3 is off by default, feature 0059) is not in
    the prompt at any line. With numbering rolled back the rendered numbers cannot be
    recovered from a rendered file, so a rendered file is reported as in-prompt and
    ``notes`` says the label is vacuous — a silent False would read as a measurement.
    """
    rendered = ctx.feed["lines"].get(path_key)
    if rendered is None:
        return True
    return ctx.numbered and line not in rendered


# ── one claim ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Context:
    """Everything constant across claims, resolved once."""

    source_path: str
    feed: dict[str, Any]
    guard: re.Pattern[str]
    narrow: int
    wide: int
    numbered: bool
    stats: dict[str, Any] = field(default_factory=dict)


def _batch_paths(ctx: _Context, path_key: str) -> list[Path] | None:
    """The batch the cited file was rendered in, as resolved paths.

    This is what bounds ``found_elsewhere``: a real search over the files the model
    was shown in the SAME request, never a repository grep.
    """
    rels = ctx.feed["batch_of"].get(path_key)
    return None if rels is None else _resolved_batch(ctx, rels)


def _resolved_batch(ctx: _Context, rels: tuple[str, ...]) -> list[Path]:
    """The batch's members that resolve to a real file; unresolvable ones drop out
    because the verifier can only read what exists."""
    return [path for path in (ctx.feed["resolved"].get(rel) for rel in rels) if path]


def _label_claim(claim: dict, index: int, ctx: _Context) -> dict[str, Any]:
    """One claim's record: the verifier's outcome plus every label it supports."""
    raw_path = _text(claim, "file_path")
    path_key = _normalize_dedup_path(raw_path, ctx.source_path)
    path = _resolve_finding_path(raw_path, ctx.source_path)
    extras = _anchor_extras(claim)
    replay = _replay_finding(claim, extras)
    result = anchor.verify_anchor(replay, path, mode="observe",
                                  batch_paths=_batch_paths(ctx, path_key))
    line = result.new_line or replay["line_start"]
    return {
        "index": index,
        "file_path": raw_path,
        "path_key": path_key,
        "title": _text(claim, "title"),
        "category": _text(claim, "category"),
        "provenance": _text(claim, "provenance"),
        "line_start": replay["line_start"],
        "line_end": _int(claim.get("line_end")),
        "anchor_line": line,
        "resolved": path is not None,
        "dedup_key": list(_dedup_key(claim, ctx.source_path)),
        "anchor": _anchor_record(result),
        "labels": _claim_labels(claim, ctx, path, (path_key, replay, result, line)),
    }


def _anchor_record(result: anchor.AnchorResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "reason": result.reason,
        "new_line": result.new_line,
        "delta": result.delta,
        "candidates": result.candidates,
        "other_path": result.other_path,
        "quote_chars": result.quote_chars,
        "quote_tokens": result.quote_tokens,
    }


def _claim_labels(claim: dict, ctx: _Context, path: Path | None,
                  located: tuple[str, dict, anchor.AnchorResult, int]) -> dict[str, bool]:
    """Every label except ``intra_file_duplicate``, which is a property of the SET."""
    path_key, replay, result, line = located
    return {
        **_quote_labels(replay["evidence_quote"], result),
        **_context_labels(path, line),
        **_guard_labels(_guard_hits(path, ctx.guard), line, ctx.narrow, ctx.wide),
        **_shape_labels(claim, path_key, replay["line_start"], path),
        "line_not_in_prompt": _not_in_prompt(ctx, path_key, line),
        "intra_file_duplicate": False,
    }


def _mark_duplicates(records: list[dict[str, Any]]) -> None:
    """E5's residue: one line claimed by rows that do NOT collapse into each other.

    ``_deduplicate_findings`` keeps one row per ``_dedup_key``, so same-key repeats
    are already handled and are deliberately not counted. What survives — and what
    this measures — is two different TITLES for one defect at one line, which the
    feature refuses to close because closing it needs a deletion mechanism (§5.6).
    """
    keys: dict[tuple[str, int], set[tuple]] = defaultdict(set)
    for record in records:
        keys[(record["path_key"], record["anchor_line"])].add(tuple(record["dedup_key"]))
    for record in records:
        anchored = (record["path_key"], record["anchor_line"])
        record["labels"]["intra_file_duplicate"] = len(keys[anchored]) > 1


# ── the blob ─────────────────────────────────────────────────────────────────


def _fired_labels(records: list[dict[str, Any]]) -> Iterator[str]:
    for record in records:
        for name, hit in record["labels"].items():
            if hit:
                yield name


def _histogram(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_fired_labels(records))
    return {name: counts.get(name, 0) for name in LABELS}


def _status_histogram(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(record["anchor"]["status"] for record in records)
    return {status: counts.get(status, 0) for status in sorted(anchor.STATUSES)}


def _delta_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The ``anchor_delta`` distribution — the mislocated-class measurement itself.

    Only re-anchored rows carry a delta: ``exact`` is delta 0 by construction and
    ``ambiguous`` moved nothing, so folding either in would flatten the distribution
    the radius is meant to be tuned against (T3.12).
    """
    deltas = _with_status(records, "reanchored", "delta")
    radius, ceiling = _radius(), anchor.max_delta()
    return {
        "distribution": {str(delta): count for delta, count in sorted(Counter(deltas).items())},
        "n": len(deltas),
        "abs_max": max(map(abs, deltas), default=0),
        "within_radius": _at_most(deltas, radius),
        "within_max_delta": _at_most(deltas, ceiling),
        "rejected_strict_tiebreak": len(_with_status(records, "ambiguous", "status")),
        "radius": radius,
        "max_delta": ceiling,
    }


def _with_status(records: list[dict[str, Any]], status: str, key: str) -> list[Any]:
    """One anchor field from every record at ``status``."""
    return [record["anchor"][key] for record in records
            if record["anchor"]["status"] == status]


def _at_most(deltas: list[int], bound: int) -> int:
    return sum(abs(delta) <= bound for delta in deltas)


def _notes(ctx: _Context) -> list[str]:
    """Named limits, in the blob rather than in a reader's memory."""
    notes = [
        "labels measure LOCALISATION, not truth: an `exact` claim can still be false",
        "guard_* is a vocabulary proxy, not proof the named mitigation is the one missing",
    ]
    if not ctx.numbered:
        notes.append("VULTURE_LLM_LINE_NUMBERS is off: `line_not_in_prompt` is vacuous "
                     "for every RENDERED file (only unrendered files can be detected)")
    if ctx.feed["unmatched_batches"]:
        notes.append(f"{ctx.feed['unmatched_batches']} batch(es) could not be split into "
                     "blocks; their files are treated as unrendered")
    return notes


def _context(source_path: str, skill_findings: list[dict] | None,
             guard_pattern: str | None, wide_radius: int | None,
             max_files: int) -> _Context:
    feed = feed_probe.render_feed(source_path, skill_findings=skill_findings,
                                  max_files=max_files)
    narrow = _snippet_context_lines()
    return _Context(
        source_path=source_path,
        feed=_feed_index(feed, source_path),
        guard=re.compile(guard_pattern or _DEFAULT_GUARD_PATTERN, re.IGNORECASE),
        narrow=narrow,
        wide=wide_radius if wide_radius else narrow * _WIDE_RADIUS_MULTIPLIER,
        numbered=bool(feed["stats"]["env"]["VULTURE_LLM_LINE_NUMBERS"]),
        stats=feed["stats"],
    )


def _blob(records: list[dict[str, Any]], ctx: _Context) -> dict[str, Any]:
    return {
        "claims": records,
        "histogram": _histogram(records),
        "status_histogram": _status_histogram(records),
        "anchor_delta": _delta_stats(records),
        "totals": {
            "claims": len(records),
            "resolved": sum(record["resolved"] for record in records),
            "rendered_files": len(ctx.feed["lines"]),
            "unmatched_batches": ctx.feed["unmatched_batches"],
        },
        # A histogram taken under a different radius describes a run that never
        # happened, so the resolved knobs travel with the numbers they produced.
        "env": {
            "snippet_context": ctx.narrow,
            "wide_radius": ctx.wide,
            "guard_pattern": ctx.guard.pattern,
            "anchor_radius": _radius(),
            "anchor_max_delta": anchor.max_delta(),
            "line_numbers": ctx.numbered,
        },
        "feed": ctx.stats,
        "notes": _notes(ctx),
    }


def probe_claims(source_path: str, claims: list[dict], *,
                 skill_findings: list[dict] | None = None,
                 guard_pattern: str | None = None,
                 wide_radius: int | None = None,
                 max_files: int = 100_000) -> dict[str, Any]:
    """Label every claim against ``source_path`` and return the diffable blob.

    ``skill_findings`` reproduces the prompt the model actually saw: the prioritiser
    tiers on them and the batcher windows around them. Without them the feed is the
    no-findings feed, so ``line_not_in_prompt`` describes THAT feed and not the run's.
    """
    ctx = _context(source_path, skill_findings, guard_pattern, wide_radius, max_files)
    records = [_label_claim(claim, index, ctx) for index, claim in enumerate(claims)]
    _mark_duplicates(records)
    return _blob(records, ctx)


# ── CLI ──────────────────────────────────────────────────────────────────────


def _claim_rows(data: Any) -> Any:
    return data.get("findings") if isinstance(data, dict) else data


def _load_claims(path: str) -> list[dict]:
    """A bare list of findings, or the ``{"findings": [...]}`` envelope a stored run
    is saved as. Anything else is a usage error, not an empty measurement."""
    rows = _claim_rows(json.loads(Path(path).read_text()))
    if not isinstance(rows, list):
        raise SystemExit(f"{path}: expected a list of findings or {{'findings': [...]}}")
    return [row for row in rows if isinstance(row, dict)]


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Label stored LLM claims against the tree they accuse, offline.")
    ap.add_argument("source_path")
    ap.add_argument("--claims", required=True, help="findings JSON (list or envelope)")
    ap.add_argument("--skill-findings", default=None,
                    help="the run's SKILL findings, to reproduce the prompt it saw")
    ap.add_argument("--guard-pattern", default=None)
    ap.add_argument("--wide-radius", type=int, default=None)
    ap.add_argument("--max-files", type=int, default=100_000)
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    blob = probe_claims(
        args.source_path,
        _load_claims(args.claims),
        skill_findings=_load_claims(args.skill_findings) if args.skill_findings else None,
        guard_pattern=args.guard_pattern,
        wide_radius=args.wide_radius,
        max_files=args.max_files,
    )
    json.dump(blob, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
