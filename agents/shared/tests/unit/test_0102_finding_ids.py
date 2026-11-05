"""Feature 0102 (A43 (3)): a finding's id does not depend on which skill finished first.

``run_combined_audit`` runs its skills on a thread pool and streams each skill's rows as
the skill completes (``as_completed``). The 0046 id hashes ``audit_id:title:file_path:index``
and the index used to be the row's GLOBAL emission position, so the same tree audited twice
gave a row another id whenever two skills finished in the other order, and every rollup
parent named other members in ``rolled_up_member_ids``. The index is now derived from the
skill's SUBMISSION order and the row's position within that skill's own result.

The completion order is the runner's ``as_completed``, replaced here by one that waits for
every skill and then hands the futures back in a chosen order: the order the runner reads
completion from, made deterministic, so the two audits differ in nothing else. The stream
order still follows completion (asserted first, so the comparison is not of two identical
runs).

The validate stage and the line collapse run at their defaults, so the L2 rollup builds its
parents from the ids the runner assigned. Each rollup's members come from one skill: a
group that mixed two skills' rows would list its members in completion order, which is the
order the rows are kept in, not their ids.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future, wait
from itertools import product, starmap
from pathlib import Path
from typing import Any

import pytest

from shared import audit_runner
from shared.audit_runner import _FindingSlots, run_combined_audit
from tests.support.agent_run import event_data, result_findings

Order = Callable[[list[Future]], Iterable[Future]]
# Row = (category, title, line). Both skills report "Shared title" in app.py under their own
# category, so the two rows hash the same title and path and differ only in their index.
ROWS: dict[str, list[tuple[str, str, int]]] = {
    "first": [("alpha", "Repeated", 1), ("alpha", "Repeated", 2), ("alpha", "Shared title", 3)],
    "second": [("beta", "Shared title", 3), ("beta", "Twice", 7), ("beta", "Twice", 8)],
}


def _row(category: str, title: str, line: int) -> dict[str, Any]:
    """One skill row in ``app.py``."""
    return {
        "severity": "medium", "category": category, "title": title, "description": "d",
        "file_path": "app.py", "line_start": line, "line_end": line, "recommendation": "r",
    }


def _skill(name: str) -> Callable[[str], dict[str, Any]]:
    """A skill returning ``ROWS[name]``, fresh dicts on every call."""
    return lambda _source_path: {"findings": [_row(*spec) for spec in ROWS[name]]}


def _completing(order: Order) -> Callable[..., Iterator[Future]]:
    """An ``as_completed`` that yields every submitted future, all done, in ``order``."""

    def as_completed(futures: Iterable[Future], timeout: float | None = None) -> Iterator[Future]:
        submitted = list(futures)
        wait(submitted, timeout=timeout)
        return iter(order(submitted))

    return as_completed


def _audit(monkeypatch: pytest.MonkeyPatch, root: Path, order: Order) -> list[str]:
    """One skills-only audit of the two skills whose completion order is ``order``."""
    monkeypatch.setattr(audit_runner, "as_completed", _completing(order))
    return list(run_combined_audit(
        run_id="0102-ids", source_path=str(root), categories=list(ROWS),
        skill_map={name: _skill(name) for name in ROWS}, use_llm=False,
    ))


def _finding_events(events: list[str]) -> list[dict[str, Any]]:
    """Every live ``finding`` event's payload, in stream order."""
    return [event_data(e) for e in events if e.startswith("event: finding\n")]


def _streamed(events: list[str]) -> list[tuple[str, str]]:
    """The skills' live ``finding`` events as ``(category, id)``, in stream order (the rollup
    parents the validate stage streams after them left out)."""
    return [(row["category"], row["id"]) for row in _finding_events(events) if not row.get("is_rollup")]


def _streamed_categories(events: list[str]) -> list[str]:
    """The categories of the skills' live ``finding`` events, in stream order."""
    return [category for category, _id in _streamed(events)]


def _ids(events: list[str]) -> dict[tuple[str, str, int], str]:
    """Each result row's id, by the row it is (category, title, line)."""
    rows = result_findings(events)
    return {(r["category"], r["title"], r["line_start"]): r["id"] for r in rows if not r.get("is_rollup")}


def _members(events: list[str]) -> dict[str, list[str]]:
    """Each rollup parent's ``rolled_up_member_ids``, by the parent's id."""
    return {r["id"]: r["rolled_up_member_ids"] for r in result_findings(events) if r.get("is_rollup")}


@pytest.fixture
def audits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, list[str]]:
    """The same audit with the skills completing in submission order and in reverse."""
    (tmp_path / "app.py").write_text("".join(f"line {n}\n" for n in range(1, 10)), encoding="utf-8")
    return {"submitted": _audit(monkeypatch, tmp_path, list), "reversed": _audit(monkeypatch, tmp_path, reversed)}


def test_the_stream_follows_completion(audits: dict[str, list[str]]) -> None:
    """Precondition: the two audits really completed (and streamed) in different orders."""
    assert _streamed_categories(audits["submitted"]) == ["alpha"] * 3 + ["beta"] * 3
    assert _streamed_categories(audits["reversed"]) == ["beta"] * 3 + ["alpha"] * 3


def test_two_completion_orders_give_the_same_finding_ids(audits: dict[str, list[str]]) -> None:
    """Every row keeps its id however the skills finished; the ids are distinct."""
    ids = _ids(audits["submitted"])
    assert len(ids) == sum(map(len, ROWS.values()))
    assert len(set(ids.values())) == len(ids)
    assert _ids(audits["reversed"]) == ids


def test_two_completion_orders_give_the_same_rollup_member_ids(audits: dict[str, list[str]]) -> None:
    """Each rollup parent names the same members, in the same order, either way."""
    members = _members(audits["submitted"])
    assert sorted(map(len, members.values())) == [2, 2]
    assert _members(audits["reversed"]) == members


def test_the_live_event_carries_the_result_id(audits: dict[str, list[str]]) -> None:
    """The id is fixed at emission: the streamed rows carry the ids the result reports, which
    the L5 ``validation_update`` events refer to."""
    for events in audits.values():
        assert sorted(i for _c, i in _streamed(events)) == sorted(_ids(events).values())


def test_no_skill_row_shares_an_index_with_another_skill_or_the_llm_tier() -> None:
    """The index space: three skills and the LLM tier, five rows each, 20 distinct indices."""
    slots = _FindingSlots.of("abc")
    skill = list(starmap(slots.skill, product("abc", range(5))))
    llm = list(map(slots.llm, range(5)))
    assert len(set(skill + llm)) == 20
