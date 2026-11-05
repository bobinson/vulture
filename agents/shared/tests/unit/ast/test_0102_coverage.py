"""Feature 0102, plan task 2.4 (LLD §10.2, D14, D24, A8, §8.7 "coverage lists"): an audit's
``ast_coverage``, as ``coverage.snapshot(root)`` reports it.

``ast_coverage`` is how an audit tells its consumer which files the AST tier owned and which
fell back to the regex tier, and why; the lineage pass reads two of its keys to keep a
fallback file's AST-only rows from being closed as fixed (D24). Pinned here:

* **The wire shape (§10.2 "Wire contract").** A fresh audit reports every key with a real
  value: every fallback bucket at zero, ``fallback_keys == []`` and ``breaker_tripped is
  False`` (never null, never absent), the declines at zero, the §10.2 ``tallies`` (its
  counters, ``unmapped_kinds``, ``cache``) at zero, ``workers`` and ``grammars`` typed.
* **Determinism (D14).** The snapshot is serialized with ``sort_keys``: its keys are in
  sorted order at every level, and two audits fed the same events in different orders give
  the same JSON, byte for byte. Read literally, ``snapshot()`` itself returns the dict
  already key-sorted at every level (not only its serialized form).
* **Two path lists (D24, §10.3).** ``fallback_paths`` is for people: ``safe_path``-rendered,
  the ``MAX_FALLBACK_PATHS`` lexicographically smallest, ``fallback_paths_truncated`` past
  them. ``fallback_keys`` is for the lineage guard: every fallback path, uncapped, lossless
  (never ``safe_path``-rendered), canonical, ``/``-separated and relative to the root.
* **Counting unit (A8, A31 (3), (8)).** A path counts once per audit in its fallback bucket
  (and an owned file once in ``parsed``), however many ``get_model``/``owns`` calls the skills
  make, by its key (the posix normpath of the root-relative path); a model's own cap tallies
  aggregate once per unique path too.
* **Unsupported files (A31 (4)).** A file with no profile was never the AST tier's: it counts
  in ``fallback.unsupported`` only, and is in neither path list.
* **The breaker (D10, D24).** ``files.breaker_tripped`` is the one breaker signal the guard
  reads; ``workers.breaker_tripped`` mirrors it. A breaker trips per audit, never the
  process default.
* **Declines.** ``declines`` mirrors the audit's ledger: ``count``, ``by_rule``,
  ``capped_rules``.

Fallbacks are made through the public path: ``get_model``/``owns`` with the pool's answer
forced by ``_analysis.spy_pool`` (no worker runs), a real worker for a parse error, and a
crashing hook worker (``_audit.CRASH_HOOK``) for the breaker. Every audit is a fresh
``context.enter`` in isolation (``_analysis.in_audit``), so no test reads another's state.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, get_args

import pytest

from shared.ast import owns
from shared.ast.limits import CIRCUIT_BREAK_AFTER, MAX_ARGS, MAX_FALLBACK_PATHS
from shared.ast.pool import FallbackReason, WorkerPool
from tests.unit.ast._analysis import coverage_snapshot, in_audit, safe_path, spy_pool
from tests.unit.ast._audit import (
    CLEAN_JS,
    CRASH_HOOK,
    FORCED,
    GUARDED,
    OVER,
    SANITIZED,
    clean_files,
    decline_record,
    faults_until_open,
    names,
    path_lists,
    records,
    shuffled,
    snapshot_after,
)
from tests.unit.ast._support import hook_command, write

pytestmark = pytest.mark.usefixtures("real_pool")

# §10.2's eleven fallback buckets, written out: the pool's reasons and the three
# ``get_model``/``owns`` decide before it. The wire the D24 reader parses, not the pool's
# Literal (which must stay inside it).
_BUCKETS = frozenset({
    "unsupported", "parse_error", "too_large", "too_deep", "worker_crashed", "worker_error",
    "timeout", "ir_too_large", "bad_model", "spawn_failed", "circuit_open",
})
_TOP = {"grammars", "files", "declines", "tallies", "workers"}
# §10.2 ``tallies``: its counters, beside ``unmapped_kinds`` and ``cache``.
_TALLY_COUNTERS = ("unknown_only_sinks", "origin_overflow", "summary_cap")
_CACHE_COUNTERS = ("hits", "misses", "evictions")
_BROKEN = "f(a;)\n"  # one ERROR node: a model, and a parse_error fallback under owns


# ── the wire shape ───────────────────────────────────────────────────────────


def _tally_shape(tallies: dict[str, Any]) -> dict[str, Any]:
    """§10.2 ``tallies``: its counters, ``unmapped_kinds`` and ``cache``."""
    return {
        "counters": {k: tallies.get(k) for k in _TALLY_COUNTERS},
        "unmapped_kinds": tallies.get("unmapped_kinds"),
        "cache": tallies.get("cache"),
    }


def _wire_types(snapshot: dict[str, Any]) -> dict[str, object]:
    """The §10.2 members whose fresh value is not fixed, by type: ``workers.count`` and
    ``recycled`` are integers (never a bool), and ``grammars`` maps a language to a version;
    and the pool's reasons the wire has no bucket for (none: it can answer nothing else)."""
    workers, grammars = snapshot["workers"], snapshot["grammars"]
    return {
        "workers": sorted(workers),
        "worker counters": [type(workers.get(k)) for k in ("count", "recycled")],
        "grammars": isinstance(grammars, dict)
        and all(isinstance(v, str) for v in (*grammars, *grammars.values())),
        "pool reasons off the wire": sorted(set(get_args(FallbackReason)) - _BUCKETS),
    }


def test_a_fresh_audit_reports_every_wire_key_with_a_real_value(tmp_path: Path) -> None:
    snapshot = in_audit(tmp_path, coverage_snapshot, tmp_path)
    files = snapshot["files"]

    observed = {
        "top": set(snapshot),
        "fallback": files["fallback"],
        "parsed": files["parsed"],
        "lists": (files["fallback_paths"], files["fallback_keys"]),
        "false": [files["fallback_paths_truncated"], files["breaker_tripped"],
                  snapshot["workers"]["breaker_tripped"]],
        "declines": snapshot["declines"],
        "tallies": _tally_shape(snapshot["tallies"]),
    }

    assert observed == {
        "top": _TOP,
        "fallback": dict.fromkeys(_BUCKETS, 0),
        "parsed": 0,
        "lists": ([], []),
        "false": [False, False, False],
        "declines": {"count": 0, "by_rule": {}, "capped_rules": []},
        "tallies": {
            "counters": dict.fromkeys(_TALLY_COUNTERS, 0),
            "unmapped_kinds": {},
            "cache": dict.fromkeys(_CACHE_COUNTERS, 0),
        },
    }
    # ``False == 0``: the identity is the contract (never null, never a number).
    assert all(flag is False for flag in observed["false"]), observed["false"]
    assert _wire_types(snapshot) == {
        "workers": ["breaker_tripped", "count", "recycled"],
        "worker counters": [int, int],
        "grammars": True,
        "pool reasons off the wire": [],
    }


# ── determinism (D14) ────────────────────────────────────────────────────────


# Fallbacks in two directories, declines of two rules: events whose order can vary.
_EVENT_FILES = tuple(f"{d}/f{i}.js" for d, i in itertools.product("ba", range(15)))
_EVENT_DECLINES = tuple(itertools.product((GUARDED, SANITIZED), range(5)))


def _mixed_events(root: Path) -> tuple[list[Path], list[Any]]:
    events = [decline_record(root / f"r{i}.js", rule=rule) for rule, i in _EVENT_DECLINES]
    return clean_files(root, _EVENT_FILES), events


def test_snapshot_keys_are_sorted_at_every_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy_pool(monkeypatch, answer=FORCED)
    paths, events = _mixed_events(tmp_path)

    snapshot = in_audit(tmp_path, snapshot_after, tmp_path, paths, events)

    assert json.dumps(snapshot) == json.dumps(snapshot, sort_keys=True)


def test_the_snapshot_does_not_depend_on_the_order_of_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent skill threads record in any order; two audits fed the same events in two
    orders serialize to the same bytes."""
    spy_pool(monkeypatch, answer=FORCED)
    paths, events = _mixed_events(tmp_path)

    forward = in_audit(tmp_path, snapshot_after, tmp_path, paths, events)
    mixed = in_audit(tmp_path, snapshot_after, tmp_path, shuffled(paths, 1), shuffled(events, 2))

    assert json.dumps(mixed) == json.dumps(forward)


# ── the two path lists (D24, §10.3, §8.7) ────────────────────────────────────


def test_past_the_display_cap_paths_show_the_smallest_and_keys_keep_every_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 2.4: 250 fallbacks -> 200 display paths, the lexicographically smallest, and
    ``fallback_paths_truncated``; every one of the 250 in ``fallback_keys`` and the bucket."""
    spy_pool(monkeypatch, answer=FORCED)
    files_named = names(MAX_FALLBACK_PATHS + 50)
    paths = shuffled(clean_files(tmp_path, files_named), 102)

    files = in_audit(tmp_path, snapshot_after, tmp_path, paths)["files"]

    assert path_lists(files) == (
        files_named[:MAX_FALLBACK_PATHS], True, files_named, len(files_named)
    )


# A bell character, a non-ASCII letter, a name past safe_path's 200 characters.
_HOSTILE = ("sub/dir/a\x07b.js", "sub/naïve.js", "deep/" + "x" * 230 + ".js")


def test_fallback_keys_are_lossless_canonical_root_relative_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D24 wire contract, A31 (3): a key is the posix normpath of the file's path relative to
    the root — ``/``-separated, a ``..`` spelling folded — and otherwise verbatim; the display
    list shows the same files through ``safe_path``."""
    spy_pool(monkeypatch, answer=FORCED)
    clean_files(tmp_path, _HOSTILE)
    asked = [tmp_path / "sub" / "dir" / ".." / "naïve.js", tmp_path / _HOSTILE[0],
             tmp_path / _HOSTILE[2]]

    files = in_audit(tmp_path, snapshot_after, tmp_path, asked)["files"]

    shown = sorted(safe_path(tmp_path, tmp_path / rel) for rel in _HOSTILE)
    assert (files["fallback_keys"], files["fallback_paths"]) == (sorted(_HOSTILE), shown)


def _owned_three_times(root: Path, paths: Sequence[Path]) -> dict[str, Any]:
    for _ in range(3):
        for path in paths:
            owns(path)
    return coverage_snapshot(root)["files"]


def test_each_path_is_counted_once_per_audit(tmp_path: Path) -> None:
    """A8: three ``owns`` of a clean file and of a parse-error file — the latter also by a
    ``..`` spelling — count one parsed file and one ``parse_error`` fallback."""
    (tmp_path / "sub").mkdir()
    clean, broken = write(tmp_path / "ok.js", CLEAN_JS), write(tmp_path / "bad.js", _BROKEN)

    again = tmp_path / "sub" / ".." / "bad.js"

    files = in_audit(tmp_path, _owned_three_times, tmp_path, [clean, broken, again])

    observed = (files["parsed"], files["fallback"]["parse_error"], files["fallback_keys"],
                files["fallback_paths"])
    assert observed == (1, 1, ["bad.js"], ["bad.js"])


_RUBY = "def show\n  File.open(params[:file])\nend\n"


def test_an_unsupported_file_is_counted_and_never_listed(tmp_path: Path) -> None:
    """A31 (4): a file with no profile (Ruby, O1) counts in ``fallback.unsupported`` and is in
    neither ``fallback_keys`` nor ``fallback_paths``: the AST tier never owned it."""
    ruby = write(tmp_path / "show.rb", _RUBY)

    files = in_audit(tmp_path, _owned_three_times, tmp_path, [ruby])

    observed = (files["fallback"]["unsupported"], files["fallback_keys"], files["fallback_paths"])
    assert observed == (1, [], [])


# A call with one argument past MAX_ARGS: its model tallies ``args_capped`` once (§8.7).
_WIDE_CALL = "f(" + ", ".join(f"a{i}" for i in range(MAX_ARGS + 1)) + ");\n"


def _model_tallies_after_three_owns(root: Path, paths: Sequence[Path]) -> dict[str, Any]:
    _owned_three_times(root, paths)
    return coverage_snapshot(root)["tallies"]


def test_a_models_cap_tallies_aggregate_once_per_unique_path(tmp_path: Path) -> None:
    """A31 (8): a model's own cap tallies reach ``ast_coverage.tallies`` once per unique path
    per audit: three ``owns`` of a file with one over-wide call, the third by a ``..``
    spelling, tally ``args_capped`` once."""
    (tmp_path / "sub").mkdir()
    wide = write(tmp_path / "wide.js", _WIDE_CALL)
    again = tmp_path / "sub" / ".." / "wide.js"

    tallies = in_audit(tmp_path, _model_tallies_after_three_owns, tmp_path, [wide, again])

    assert tallies.get("args_capped") == 1


# ── the breaker (D10, D24) ───────────────────────────────────────────────────


def _trip_then_request(root: Path, pool: WorkerPool) -> tuple[list[Any], dict[str, Any]]:
    faults = faults_until_open(pool)
    owns(write(root / "after.js", CLEAN_JS))
    return faults, coverage_snapshot(root)


def test_a_tripped_breaker_is_reported_in_files_and_mirrored_in_workers(tmp_path: Path) -> None:
    """``CIRCUIT_BREAK_AFTER`` crashes open this audit's breaker; the next file is
    ``circuit_open``, ``files.breaker_tripped`` is True and ``workers.breaker_tripped``
    mirrors it. The process default's breaker stays closed (D10: one audit)."""
    crashing = WorkerPool(cmd=hook_command(*CRASH_HOOK))

    faults, snapshot = in_audit(tmp_path, _trip_then_request, tmp_path, crashing)

    files = snapshot["files"]
    observed = (faults, files["fallback"]["circuit_open"], files["fallback_keys"],
                files["breaker_tripped"], snapshot["workers"]["breaker_tripped"],
                coverage_snapshot(tmp_path)["files"]["breaker_tripped"])
    expected = (["worker_crashed"] * CIRCUIT_BREAK_AFTER, 1, ["after.js"], True, True, False)
    assert observed == expected


# ── declines ─────────────────────────────────────────────────────────────────


def test_the_declines_section_mirrors_the_ledger(tmp_path: Path) -> None:
    """§10.2 ``declines``: every decline counted (``count``, ``by_rule``), and the rule
    past ``MAX_SUPPRESSIONS_PER_RULE`` named in ``capped_rules``."""
    added = records(tmp_path, names(OVER, "s")) + records(tmp_path, names(2, "g"), rule=GUARDED)

    declines = in_audit(tmp_path, snapshot_after, tmp_path, [], added)["declines"]

    assert declines == {
        "count": OVER + 2,
        "by_rule": {SANITIZED: OVER, GUARDED: 2},
        "capped_rules": [SANITIZED],
    }
