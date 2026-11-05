"""Feature 0102, plan task 2.4 (LLD D20, D10, D12, A18, A20): the per-audit ``AuditContext``.

One ``AuditContext`` per audit, held in a ``ContextVar`` (D20): its coverage and tallies, its
bounded decline ledger, its circuit breaker, its source root and, since A18, the map of the
parses it declined. Pinned here:

* **Shape.** ``shared.ast.context`` offers ``AuditContext``, ``current``, ``enter`` and
  ``reset_default``, and no ``exit`` (set and forget: the next audit's ``clear_caches()``
  cleans up). A context carries ``root``, ``coverage``, ``ledger`` (a ``DeclineLedger``),
  ``breaker`` and ``declined``, and no ``engine`` field: there is no flag (D12).
* **``enter(root)``** returns the ``ContextVar`` token and makes a NEW audit current in the
  caller's context only; every audit owns its state.
* **The process default.** Outside any audit, ``current()`` is one default, the same object
  on every thread (D20: the corpus runner and unit tests are such callers).
  ``reset_default()`` starts it over: tallies, fallback counts, declines and the declined
  map. ``file_scanner.clear_caches()`` calls it (A20); neither touches an entered audit
  (A31 (6)), and a process that never loaded the layer is not made to load it.
* **Isolation.** Two audits never see each other's tallies: two context copies, two threads
  at once; a skill thread reaches its own audit through ``copy_context().run`` (D20's
  one-line wiring) and concurrent skill threads lose no tally.

Tallies are written with ``AuditContext.tally(name)``, the call §8.5's ``decide`` makes, and
read back through the §10.2 snapshot. Every Phase-2 name is reached through ``_analysis``'s
lazy accessors, so the module collects while ``shared.ast.context`` is missing.
"""

from __future__ import annotations

import contextvars
import functools
import json
import subprocess
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from shared.ast import get_model
from shared.testing.timing import budget
from shared.tools.file_scanner import clear_caches
from tests.unit.ast._analysis import (
    context_mod,
    coverage_snapshot,
    current_context,
    declines_mod,
    fresh_context,
    in_audit,
    spy_pool,
    tally_of,
)
from tests.unit.ast._audit import decline_record
from tests.unit.ast._support import SHARED_ROOT, isolated_python, write

pytestmark = pytest.mark.usefixtures("real_pool")

# A §10.2 tally ``decide`` writes (§8.5).
_UNKNOWN = "unknown_only_sinks"
# What an AuditContext carries (D20, A18).
_PARTS = ("root", "coverage", "ledger", "breaker", "declined")
_SURFACE = ("AuditContext", "current", "enter", "reset_default")
_JOIN_S = 30.0  # a thread still running after this is a hang


def _tallied(count: int) -> None:
    """``count`` tallies of ``_UNKNOWN`` on the current audit, one ``tally`` call each."""
    for _ in range(count):
        current_context().tally(_UNKNOWN)


def _skills[T](fn: Callable[[], T], count: int = 1) -> list[T]:
    """``fn`` on ``count`` pool threads at once, each submitted the way D20's runner submits
    a skill: ``pool.submit(contextvars.copy_context().run, fn)``."""
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(contextvars.copy_context().run, fn) for _ in range(count)]
        return [future.result(_JOIN_S) for future in futures]


def _on_bare_thread[T](fn: Callable[[], T]) -> T:
    """``fn()`` on a pool thread that was handed no context (a plain ``submit``)."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(fn).result(_JOIN_S)


def _entered(root: Path) -> tuple[Any, Any]:
    token = context_mod().enter(root)
    return token, current_context()


# ── shape ────────────────────────────────────────────────────────────────────


def test_the_module_offers_current_enter_and_reset_default_and_no_exit() -> None:
    module = context_mod()

    present = {name: hasattr(module, name) for name in (*_SURFACE, "exit")}

    assert present == {**dict.fromkeys(_SURFACE, True), "exit": False}


def test_an_audit_carries_root_coverage_ledger_breaker_and_declined_and_no_engine(
    tmp_path: Path,
) -> None:
    ctx = fresh_context(tmp_path)

    present = {name: hasattr(ctx, name) for name in (*_PARTS, "engine")}

    assert present == {**dict.fromkeys(_PARTS, True), "engine": False}
    ledger = isinstance(ctx.ledger, declines_mod().DeclineLedger)
    observed = (Path(ctx.root), ledger, dict(ctx.declined))
    assert observed == (tmp_path, True, {})


# ── enter ────────────────────────────────────────────────────────────────────


def test_enter_returns_a_token_and_makes_a_new_audit_current(tmp_path: Path) -> None:
    default = current_context()

    token, entered = contextvars.copy_context().run(_entered, tmp_path)

    observed = (isinstance(token, contextvars.Token), entered is default, Path(entered.root))
    assert observed == (True, False, tmp_path)


def test_enter_never_moves_the_callers_context(tmp_path: Path) -> None:
    default = current_context()

    first, second = fresh_context(tmp_path), fresh_context(tmp_path)

    assert (current_context() is default, first is second, first is default) == (True, False, False)


def test_every_audit_owns_its_state(tmp_path: Path) -> None:
    first, second = fresh_context(tmp_path), fresh_context(tmp_path)

    shared_parts = [name for name in _PARTS[1:] if getattr(first, name) is getattr(second, name)]

    assert shared_parts == []


# ── the process default ──────────────────────────────────────────────────────


def test_outside_an_audit_every_thread_reads_the_one_process_default() -> None:
    assert _on_bare_thread(current_context) is current_context()


def _reset_default() -> None:
    context_mod().reset_default()


# The two ways a default audit is started over: the call itself, and the per-audit reset
# every agent runs (A20).
_RESETS: dict[str, Callable[[], None]] = {
    "reset_default": _reset_default,
    "clear_caches": clear_caches,
}


def _dirty(root: Path) -> None:
    """Something in every part of the current audit a reset starts over: two tallies, one
    declined parse (and its fallback, A8, A18) and one decline."""
    _tallied(2)
    get_model(write(root / "deep.js", "f(a);\n"))
    current_context().ledger.add(decline_record(root / "a.js"))


def _state(root: Path) -> dict[str, Any]:
    snapshot = coverage_snapshot(root)
    files = snapshot["files"]
    return {
        "tally": snapshot["tallies"].get(_UNKNOWN, 0),
        "too_deep": files["fallback"]["too_deep"],
        "fallback_keys": files["fallback_keys"],
        "declines": snapshot["declines"]["count"],
        "declined": len(current_context().declined),
    }


@pytest.mark.parametrize("reset", _RESETS)
def test_a_reset_starts_the_default_audit_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reset: str
) -> None:
    """Plan 2.4 / A20: ``reset_default()`` clears the default audit's tallies, and with them
    its fallback counts, its declines and (A18) its declined map; ``clear_caches()`` is that
    reset."""
    spy_pool(monkeypatch, answer="too_deep")
    _reset_default()
    _dirty(tmp_path)
    dirty = _state(tmp_path)

    _RESETS[reset]()

    assert (dirty, _state(tmp_path)) == (
        {"tally": 2, "too_deep": 1, "fallback_keys": ["deep.js"], "declines": 1, "declined": 1},
        {"tally": 0, "too_deep": 0, "fallback_keys": [], "declines": 0, "declined": 0},
    )


def _tallied_then_reset(root: Path, reset: str) -> int:
    _tallied(4)
    _RESETS[reset]()
    return tally_of(root, _UNKNOWN)


@pytest.mark.parametrize("reset", _RESETS)
def test_a_reset_leaves_an_entered_audit_alone(tmp_path: Path, reset: str) -> None:
    """``reset_default()`` — and ``clear_caches()``, which calls it — resets only the process
    DEFAULT (A20, A31 (6)): an audit that entered its own context keeps its tallies, even when
    the reset runs on its own thread."""
    assert in_audit(tmp_path, _tallied_then_reset, tmp_path, reset) == 4


_NEVER_LOADED_PROBE = (
    "import json, sys\n"
    f"sys.path.insert(0, {str(SHARED_ROOT)!r})\n"
    "from shared.tools.file_scanner import clear_caches\n"
    "clear_caches()\n"
    "print(json.dumps(sorted(m for m in sys.modules if m.split('.')[:2] == ['shared', 'ast'])))\n"
)


def test_clear_caches_never_loads_the_layer(tmp_path: Path) -> None:
    """A20: the hook resets the layer only in a process that already loaded ``shared.ast``;
    a fresh interpreter that never imported it does not import it from ``clear_caches()``."""
    with isolated_python(_NEVER_LOADED_PROBE, tmp_path, stderr=subprocess.PIPE, text=True) as proc:
        out, err = proc.communicate(timeout=budget(30.0))

    assert proc.returncode == 0, err
    assert json.loads(out.strip().splitlines()[-1]) == []


# ── isolation ────────────────────────────────────────────────────────────────


def _with_a_skill(root: Path) -> tuple[Any, Any, int]:
    audit = current_context()
    (seen,) = _skills(current_context)
    _skills(functools.partial(_tallied, 3))
    return audit, seen, tally_of(root, _UNKNOWN)


def test_a_skill_thread_reaches_its_audit_through_copy_context(tmp_path: Path) -> None:
    """D20: the skill submit is wrapped in ``copy_context().run``, so a skill thread's
    ``current()`` is its audit's context, and what it tallies is the audit's."""
    before = tally_of(tmp_path, _UNKNOWN)

    audit, seen, tallied = in_audit(tmp_path, _with_a_skill, tmp_path)

    assert (seen is audit, tallied, tally_of(tmp_path, _UNKNOWN)) == (True, 3, before)


def _tally_with_a_peer(root: Path, count: int, barrier: threading.Barrier) -> int:
    _tallied(count)
    barrier.wait(_JOIN_S)  # both audits are open at once
    return tally_of(root, _UNKNOWN)


def test_two_audits_at_once_never_see_each_others_tallies(tmp_path: Path) -> None:
    before = tally_of(tmp_path, _UNKNOWN)
    barrier = threading.Barrier(2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(in_audit, root, _tally_with_a_peer, root, count, barrier)
            for root, count in ((tmp_path / "a", 3), (tmp_path / "b", 5))
        ]
        tallies = [future.result(_JOIN_S) for future in futures]

    assert (tallies, tally_of(tmp_path, _UNKNOWN)) == ([3, 5], before)


def _tallied_then_read(root: Path, count: int) -> int:
    _tallied(count)
    return tally_of(root, _UNKNOWN)


def test_two_audits_in_turn_never_see_each_others_tallies(tmp_path: Path) -> None:
    first = in_audit(tmp_path, _tallied_then_read, tmp_path, 3)
    second = in_audit(tmp_path, _tallied_then_read, tmp_path, 5)

    assert (first, second) == (3, 5)


def _many_skills(root: Path, threads: int, each: int) -> int:
    _skills(functools.partial(_tallied, each), threads)
    return tally_of(root, _UNKNOWN)


def test_concurrent_skill_threads_lose_no_tally(tmp_path: Path) -> None:
    """Up to eight skill threads share one audit (§4); every ``tally`` lands."""
    assert in_audit(tmp_path, _many_skills, tmp_path, 8, 2_000) == 16_000
