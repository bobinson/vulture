"""Feature 0102, A44 (2) (LLD §4.1 item 8, D20; plan task 3.9, test 32): the runner closes an
audit's ticket index when its skill phase ends.

Parse prefetch issues tickets on a skill's own thread and files them in the audit's
``TicketIndex``; a walk drains its own on exit, and ``context.leave`` closes the index on the
runner's normal path (``_ast_result``). The cancel and deadline paths never reach that
``leave``: a client disconnect closes the audit generator mid-skill, and a skill thread may
still be holding tickets. So the runner's skill-phase ``finally`` closes the index too, with one
straight-line statement (``_ast_close(ast_run)``, A43 (6): ``run_combined_audit``'s CC stays
55). Pinned here, through the real runner and real workers on a four-slot pool:

* a normal end: a stub skill files tickets outside any walk (``cache.issue_ahead``) and returns;
  after the run no ticket is outstanding and every slot is free;
* a cancel mid-skill: one stub skill files tickets and blocks; a second finishes, the consumer
  cancels the run's token and closes the generator at that skill's event; at once, with the
  blocked skill still running, no ticket is outstanding and every slot is free;
* ``run_combined_audit`` is still CC 55 and ``_ast_close`` is CC <= 4.

RED until task 3.9: ``WorkerPool.issue``, ``cache.issue_ahead`` and ``_ast_close`` do not exist.
"""

from __future__ import annotations

import contextvars
import threading
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from radon.complexity import cc_visit

from shared import audit_runner
from shared.ast import cache as ast_cache
from shared.ast import limits
from shared.ast.context import current
from shared.ast.pool import WorkerPool
from shared.audit_runner import run_combined_audit
from shared.cancellation import CancelToken, set_cancel_token
from shared.testing.timing import budget
from tests.support.agent_run import skill_failures, thinking_lines
from tests.unit.ast._prefetch import (
    PATH,
    Spy,
    cold_caches,
    drained,
    idle,
    js_files,
    pool_spies,
    process_pool,
)

type Skill = Callable[[str], dict[str, Any]]

_RUN_ID = "0102-runner-prefetch"
_WAIT_S = 30.0  # a stub skill's bounded wait for the other (a broken wait fails the skill)
_RUNNER_CC = 55  # A42 (5), A43 (6): run_combined_audit's CC at debf28a, straight lines only


@pytest.fixture(autouse=True)
def _cold() -> Iterator[None]:
    """An empty model cache (no answer key is ``known``) around every test."""
    with cold_caches():
        yield


def _ticketing(files: list[Path], issued: threading.Event, release: threading.Event) -> Skill:
    """A skill that files a ticket for each file but the first in its audit's index, outside any
    walk (so no walk drains them), then signals ``issued`` and returns once ``release`` is set."""

    def skill(_source_path: str) -> dict[str, Any]:
        audit = current()
        for path in files[1:]:
            ast_cache.issue_ahead(path, PATH, audit)
        issued.set()
        assert release.wait(budget(_WAIT_S)), "never released"
        return {"findings": []}

    return skill


def _after(event: threading.Event, done: threading.Event) -> Skill:
    """A skill that returns once ``event`` is set; ``done`` once it has."""

    def skill(_source_path: str) -> dict[str, Any]:
        try:
            assert event.wait(budget(_WAIT_S)), "the ticketing skill never issued"
            return {"findings": []}
        finally:
            done.set()

    return skill


def _audit(root: Path, skills: dict[str, Skill]) -> Iterator[str]:
    return run_combined_audit(
        run_id=_RUN_ID, source_path=str(root), categories=list(skills), skill_map=skills,
        use_llm=False,
    )


type Measure = Callable[[], dict[str, Any]]


def _measured(issue: Spy, pool: WorkerPool) -> dict[str, Any]:
    """The tickets the audit issued, then the pool read from outside (whose probe issues
    tickets of its own, so it comes second)."""
    return {"issued": issue.made(), "pool": drained(pool)}


def _ended_normally(root: Path, files: list[Path], measure: Measure) -> tuple[list[str], Any]:
    """One audit whose one skill files tickets and returns: every event, then ``measure()``."""
    released = threading.Event()
    released.set()
    events = list(_audit(root, {"ticketing": _ticketing(files, threading.Event(), released)}))
    return events, measure()


def _until(ctx: contextvars.Context, events: Iterator[str], marker: str) -> list[str]:
    """``events`` consumed in ``ctx`` up to and including the first that holds ``marker``."""
    seen: list[str] = []
    for event in iter(lambda: ctx.run(next, events), None):
        seen.append(event)
        if marker in event:
            return seen
    return seen


class _Cancelled:
    """An audit whose consumer cancels it mid-skill: ``ticketing`` files tickets and blocks,
    ``quick`` returns once they are filed; at ``quick``'s event the consumer cancels the token
    and closes the generator, while ``ticketing`` still runs. ``finish()`` lets it end."""

    def __init__(self, root: Path, files: list[Path]) -> None:
        self.issued, self.release, self.done = threading.Event(), threading.Event(), threading.Event()
        self.ctx = contextvars.Context()
        self.token = CancelToken()
        self.ctx.run(set_cancel_token, self.token)
        skills = {"ticketing": _ticketing(files, self.issued, self.release),
                  "quick": _after(self.issued, self.done)}
        self.events = self.ctx.run(_audit, root, skills)

    def close_at_quick(self) -> list[str]:
        seen = _until(self.ctx, self.events, "Analyzing quick patterns")
        self.token.cancel("client_disconnected")
        self.ctx.run(self.events.close)
        return seen

    def finish(self) -> None:
        self.release.set()
        assert self.done.wait(budget(_WAIT_S)), "the quick skill never ended"


def _cancelled_mid_skill(root: Path, files: list[Path], measure: Measure) -> tuple[list[str], Any]:
    """One audit closed mid-skill: the events it yielded, then ``measure()``, taken while the
    ticketing skill still runs."""
    run = _Cancelled(root, files)
    try:
        return run.close_at_quick(), measure()
    finally:
        run.finish()


_ENDINGS: dict[str, Callable[[Path, list[Path], Measure], tuple[list[str], Any]]] = {
    "normal end": _ended_normally,
    "cancelled mid-skill": _cancelled_mid_skill,
}


def _complexity() -> dict[str, int]:
    """CC (radon) of ``run_combined_audit`` and ``_ast_close`` in the runner's source."""
    source = Path(audit_runner.__file__).read_text(encoding="utf-8")
    blocks = {block.name: block.complexity for block in cc_visit(source)}
    return {name: blocks[name] for name in ("run_combined_audit", "_ast_close")}


@pytest.mark.parametrize("ending", sorted(_ENDINGS))
def test_the_skill_phase_finally_closes_the_audits_tickets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str
) -> None:
    """Test 32 (D20, A43 (6)): on a normal end, and on a generator close mid-skill (cancel),
    no ticket of the audit is outstanding and the free queue is full as soon as the generator
    is done; ``run_combined_audit`` stays CC 55 and its close is a straight-line helper."""
    files = js_files(tmp_path, 4)
    issue = pool_spies(monkeypatch)["issue"]
    with process_pool(4) as pool:
        events, measured = _ENDINGS[ending](tmp_path, files, partial(_measured, issue, pool))
        observed = {**measured, "failures": skill_failures(events),
                    "reached the skills": bool(thinking_lines(events))}
        expected = {"issued": pool.size - limits.PREFETCH_RESERVE, "pool": idle(pool),
                    "failures": [], "reached the skills": True}
    cc = _complexity()
    assert (observed, cc["run_combined_audit"], cc["_ast_close"] <= 4) == (expected, _RUNNER_CC, True)
