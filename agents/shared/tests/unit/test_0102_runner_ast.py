"""Feature 0102 (D13, D20; LLD §10.2, §10.3; plan task 3.4): the runner's AST wiring, the
parts ``test_0102_runner_wiring.py`` and the cwe ``test_0102_result_ast_coverage.py`` leave
open.

Plan task 3.4 wires the layer into ``run_combined_audit`` in four places: a new
``AuditContext`` entered per audit at the ``clear_caches()`` site, each skill submitted
through ``contextvars.copy_context().run``, the audit's declines streamed as ``ast_decline``
``thinking`` lines after the skill phase, and ``result.ast_coverage`` read from the audit's
own coverage. What those two modules do not pin, this one does:

* two audits running at once each report only their own declines: one ``AuditContext`` per
  audit, never the process default (an agent runs up to eight audits at once, §4);
* the decline lines are §10.3's, each file relative to the audited root, each line streamed
  once, in the ledger's order, before the ``result`` event; a rule past its cap streams only
  the lines the ledger keeps (§11 T6);
* every audit's ``result`` carries ``ast_coverage``, with real values in the members the D24
  guard reads, even when no skill asked the layer anything;
* the audit does not outlive its run (D20): the runner leaves no audit current in the
  context that consumed it, so a direct caller of that context (the corpus runner, a unit
  test) reads the process default, which ``clear_caches()`` starts over. ``clear_caches()``
  alone cannot detach an audit still current there: it resets only the default (A31 (6),
  ``test_0102_context.py``).

Each stub skill records its declines the way ``decide`` does (§8.5): through
``context.current().decline(path, flow, rule, label)`` (A30 (1)), with ``_analysis``'s
stand-in rule and flow (``stub_rule``, ``flow_with``). Every audit here runs in a
context of its own (a copied one, or a fresh thread's), so whatever it enters reaches no
other test.

RED until plan task 3.4: the ``result`` carries no ``ast_coverage`` and no ``ast_decline``
line is streamed.
"""

from __future__ import annotations

import contextvars
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from shared.ast.context import current
from shared.ast.limits import MAX_SUPPRESSIONS_PER_RULE
from shared.audit_runner import run_combined_audit
from shared.testing.timing import budget
from shared.tools.file_scanner import clear_caches
from tests.support.agent_run import (
    RESULT_HEAD,
    noop_skill,
    result_payload,
    skill_failures,
    thinking_lines,
)
from tests.unit.ast._analysis import VALIDATE, external, flow_with, stub_rule
from tests.unit.ast._audit import OVER

type Skill = Callable[[str], dict[str, Any]]
# One decline to record: (file under the audited root, sink line, family, decline label).
type Decline = tuple[str, int, str, str]

_CATEGORY = "stub_decline"
DECLINE = "ast_decline "
SANITIZED = "sanitized:shell_quote"
# How long one audit's stub skill waits for the other audit's (a broken wait fails the skill).
WAIT_S = budget(10.0)


def _decline(root: str, decline: Decline) -> None:
    """Record ``decline`` on the current audit, as ``decide`` does (A30 (1)): a request
    value's flow at the sink line, under the family's stand-in rule."""
    rel, line, family, label = decline
    flow = flow_with(family, external("request"), sink_line=line)
    current().decline(Path(root) / rel, flow, stub_rule(family), label)


def _guarded(count: int) -> list[Decline]:
    """``count`` ``guarded:validate`` declines of one path rule in ``a.js``, lines 1 on."""
    return [("a.js", line, "path", VALIDATE) for line in range(1, count + 1)]


def _declining(*declines: Decline) -> Skill:
    """A skill that records ``declines`` under the audited root and finds nothing."""

    def skill(source_path: str) -> dict[str, Any]:
        for decline in declines:
            _decline(source_path, decline)
        return {"findings": []}

    return skill


def _overlapping(count: int, meet: threading.Barrier, recorded: threading.Barrier) -> Skill:
    """A skill that records ``count`` declines while another audit's skill records its own:
    both wait at ``meet`` before recording and at ``recorded`` after it."""
    declining = _declining(*_guarded(count))

    def skill(source_path: str) -> dict[str, Any]:
        meet.wait()
        found = declining(source_path)
        recorded.wait()
        return found

    return skill


def _events(root: Path, skills: dict[str, Skill]) -> list[str]:
    """Every event of a skills-only audit of ``root`` by ``skills``, consumed in the caller's
    context."""
    return list(run_combined_audit(
        run_id="0102-runner-ast", source_path=str(root), categories=list(skills),
        skill_map=skills, use_llm=False,
    ))


def _isolated(root: Path, skills: dict[str, Skill]) -> list[str]:
    """``_events`` in a copy of the caller's context: whatever the audit enters stays there."""
    return contextvars.copy_context().run(_events, root, skills)


def _coverage(events: list[str]) -> dict[str, Any]:
    """The ``result`` event's ``ast_coverage``, ``{}`` when it carries none."""
    return result_payload(events).get("ast_coverage") or {}


def _declines_counted(events: list[str]) -> int | None:
    """``ast_coverage.declines.count`` of the ``result`` event, None when absent."""
    return _coverage(events).get("declines", {}).get("count")


def _declines_in(events: list[str]) -> list[str]:
    """The ``ast_decline`` ``thinking`` lines of ``events``, in stream order."""
    return [line for line in thinking_lines(events) if line.startswith(DECLINE)]


def _result_at(events: list[str]) -> int:
    """The stream index of the one ``result`` event (``len(events)`` when there is none)."""
    return next((i for i, e in enumerate(events) if e.startswith(RESULT_HEAD)), len(events))


def test_concurrent_audits_keep_their_own_declines(tmp_path: Path) -> None:
    """Two audits at once, their skill phases overlapping (the second audit's
    ``clear_caches()`` runs while the first is in its skills): each ``result`` counts only
    the declines its own skill recorded."""
    meet, recorded = threading.Barrier(2, timeout=WAIT_S), threading.Barrier(2, timeout=WAIT_S)

    def audit(name: str, count: int) -> list[str]:
        root = tmp_path / name
        root.mkdir()
        return _events(root, {_CATEGORY: _overlapping(count, meet, recorded)})

    with ThreadPoolExecutor(max_workers=2) as threads:  # a fresh context per thread
        runs = list(threads.map(audit, ("one", "two"), (1, 2)))

    observed = {
        "declines counted": list(map(_declines_counted, runs)),
        "skill failures": list(map(skill_failures, runs)),
    }
    assert observed == {"declines counted": [1, 2], "skill failures": [[], []]}


def test_declines_stream_as_root_relative_lines_once_before_the_result(tmp_path: Path) -> None:
    """Two skills, one decline each: §10.3's two lines, each file relative to the audited
    root, each line once, in the ledger's (sorted) order, before the ``result`` event."""
    events = _isolated(tmp_path, {
        "paths": _declining(("sub/a.js", 7, "path", VALIDATE)),
        "commands": _declining(("b.py", 3, "command", SANITIZED)),
    })

    at = _result_at(events)
    observed = {"before the result": _declines_in(events[:at]), "after it": _declines_in(events[at:])}
    assert observed == {
        "before the result": [
            f"{DECLINE}family=command file=b.py line=3 rule={SANITIZED} origins=external:request",
            f"{DECLINE}family=path file=sub/a.js line=7 rule={VALIDATE} origins=external:request",
        ],
        "after it": [],
    }


def test_a_rule_past_its_cap_streams_only_its_kept_lines(tmp_path: Path) -> None:
    """Ten declines of one rule past ``MAX_SUPPRESSIONS_PER_RULE``: the stream carries the
    ledger's capped lines, and ``ast_coverage.declines`` counts every one (§10.3, T6)."""
    events = _isolated(tmp_path, {_CATEGORY: _declining(*_guarded(OVER))})

    observed = {"lines": len(_declines_in(events)), "declines": _coverage(events).get("declines")}
    assert observed == {
        "lines": MAX_SUPPRESSIONS_PER_RULE,
        "declines": {"count": OVER, "by_rule": {VALIDATE: OVER}, "capped_rules": [VALIDATE]},
    }


def test_every_result_reports_ast_coverage(tmp_path: Path) -> None:
    """An audit whose skill never asks the layer anything still reports ``ast_coverage``,
    the members the D24 guard reads at real values (§10.2: never null, never absent)."""
    coverage = _coverage(_isolated(tmp_path, {"noop": noop_skill}))
    files = coverage.get("files", {})

    observed = {
        "parsed": files.get("parsed"),
        "fallback_keys": files.get("fallback_keys"),
        "breaker_tripped is False": files.get("breaker_tripped") is False,
        "declines": coverage.get("declines"),
    }
    assert observed == {
        "parsed": 0,
        "fallback_keys": [],
        "breaker_tripped is False": True,
        "declines": {"count": 0, "by_rule": {}, "capped_rules": []},
    }


def _audit_then_direct_caller(root: Path) -> dict[str, Any]:
    """In ONE context: an audit whose skill declines once, then what a direct caller of the
    same thread reads of its current audit after ``clear_caches()``."""
    events = _events(root, {_CATEGORY: _declining(*_guarded(1))})
    clear_caches()
    return {
        "the audit's declines": _declines_counted(events),
        "a direct caller's declines after clear_caches()": (
            current().coverage.snapshot(root)["declines"]["count"]
        ),
    }


def test_a_direct_caller_after_an_audit_starts_over(tmp_path: Path) -> None:
    """The context that consumed an audit is a direct caller's afterwards (the corpus runner,
    a test): the runner left no audit current there (D20), so after ``clear_caches()`` it
    reads the process default, started over, and never records into, or reads, the finished
    audit."""
    observed = contextvars.copy_context().run(_audit_then_direct_caller, tmp_path)

    assert observed == {
        "the audit's declines": 1,
        "a direct caller's declines after clear_caches()": 0,
    }
