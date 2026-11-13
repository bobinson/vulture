"""Feature 0104 WS-A2, decision D-S (2): A2's fold decides on DETERMINISTIC rows only.

Rule (LLD §4.1 A2, R1, R2, as D-S (2) amends them). ``consume.fold_hint_groups``, run by
``audit_runner._fold_hint_groups`` after the code window and before the validate stage, refuses
a stamped group only for what the deterministic tier does:

* (a) a row whose ``provenance`` is LLM-family (``shared.provenance.is_llm_provenance``:
  ``llm``, ``llm_l5_verified``, any case or whitespace variant) standing at a member's line
  never refuses, whatever its CWE: the rule's own, one of its dedup family, a ChildOf ancestor
  or descendant. The fold keeps that row, unchanged, as its own row beside the group row;
* (b) a member carrying ``merged_llm`` and/or ``merged_llm_dropped`` (0074 C3: the LLM rows
  the agent's dedup dropped against it) never refuses. The group row carries the members'
  ``merged_llm`` entries concatenated in member order, each once, and the sum of their
  ``merged_llm_dropped``; a key no member carries stays absent (C3: omitted when empty). The
  member rows the group keeps for the validate stage (``hint_rows``, R5) keep exactly their
  own;
* (c) the deterministic refusals stand: another row of no LLM-family provenance that one line
  reconciles with a member at its line, a member the line collapse kept (``collapsed_from``),
  a member's row missing or out of order;
* (d) the group row is the same row whether or not an LLM row stands at a member's line.

Why: the model's answer varies from run to run, so a fold an LLM row could refuse flipped a
file between one row and its members, and its rollup parent churned fixed <-> regression.

RED until D-S (2) lands, except the tests marked PIN, which hold on HEAD and must stay green.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from itertools import filterfalse
from pathlib import Path
from typing import Any

import pytest

from shared import audit_runner
from shared.ast.consume import hint_rows
from shared.provenance import is_llm_provenance
from tests.support.agent_run import DUMMY_TOOLS, result_findings
from tests.unit.ast._0104 import (
    _FILE_SINKS,
    _PATH,
    _SINKS,
    Extras,
    Rows,
    _carrying,
    _file_members,
    _finalized,
    _flow_sinks,
    _fold,
    _members,
    _other,
    _private,
    _row,
    _stamped,
    _written,
    cases,
    family_rule,
)
from tests.unit.ast._support import write
from tests.unit.test_0074_agent_dedup_counters import _llm_env

# A key the row does not carry (``None`` would also match a key set to ``None``).
ABSENT = "absent"
# ``merged_llm`` entries (0074 C3), each with its own description.
_A = {"provenance": "llm", "description": "the model read the path from a parameter"}
_B = {"provenance": "llm_l5_verified", "description": "the model found no allow-list"}
_C = {"provenance": "llm", "description": "the model traced the name to an export"}
_KEPT = ["CWE-706"]


def _tiered(
    line: int, category: str, provenance: str, path: Path | str = _PATH
) -> dict[str, Any]:
    """Another check's row of ``category`` at ``line``, of the tier ``provenance`` names."""
    return {**_other(line, category, path), "provenance": provenance}


def _merges(row: dict[str, Any]) -> tuple[Any, Any]:
    """The row's ``merged_llm`` and ``merged_llm_dropped``, ``ABSENT`` for a missing key."""
    return row.get("merged_llm", ABSENT), row.get("merged_llm_dropped", ABSENT)


def _carried(rows: Rows) -> list[tuple[Any, ...]]:
    """Each row's line, category, provenance, ``sinks`` and LLM merges, in order."""
    return [(row["line_start"], row["category"], row.get("provenance"), _flow_sinks(row),
             *_merges(row)) for row in rows]


def _group(
    family: str = "path", merged: Any = ABSENT, dropped: Any = ABSENT, provenance: Any = None
) -> tuple[Any, ...]:
    """``_carried``'s entry for the group row of ``_members(family)``."""
    return (_SINKS[0], family_rule(family).category, provenance, list(_SINKS), merged, dropped)


def _stamped_lines(rows: Rows) -> list[int]:
    """The line of each row still stamped a group member (a group row keeps its members' rows,
    privately, for the validate stage; no row keeps the stamp)."""
    return [row["line_start"] for row in rows if "_hint_group" in row]


def _assert_kept(findings: Rows) -> None:
    """Refused: every row as it was, in its place, its own merges kept, no stamp left."""
    want = _carried(findings)
    got = _fold(findings)
    assert (_carried(got), _private(got)) == (want, [])


# ── (a) an LLM row at a member's line stays its own row ──

LLM_BESIDE: list[tuple[str, str, int, str, str]] = [
    ("the rule's own CWE-22 at a member's line", "path", 7, "CWE-22", "llm"),
    ("CWE-23 at a member's line", "path", 7, "CWE-23", "llm"),
    ("CWE-36 at the anchor's line", "path", 3, "CWE-36", "llm"),
    ("CWE-073 at the last member's line", "path", 10, "CWE-073", "llm"),
    ("an L5-verified ChildOf ancestor (CWE-706)", "path", 7, "CWE-706", "llm_l5_verified"),
    ("an upper-case ChildOf descendant (CWE-24)", "path", 7, "CWE-24", "LLM"),
    ("CWE-77 at a command member's line", "command", 7, "CWE-77", "llm"),
    ("a padded CWE-88 at the command anchor's line", "command", 3, "CWE-88", " llm\t"),
    ("a ChildOf ancestor (CWE-74) of a command member", "command", 10, "CWE-74", "llm"),
]


@pytest.mark.parametrize(("family", "line", "category", "provenance"), cases(LLM_BESIDE))
def test_an_llm_row_at_a_member_line_stays_its_own_row(
    family: str, line: int, category: str, provenance: str
) -> None:
    """The group row in the anchor's place, the LLM row after it exactly as it came."""
    llm = _tiered(line, category, provenance)
    kept = copy.deepcopy(llm)
    got = _fold([*_members(family), llm])
    assert (_carried(got[:1]), got[1:]) == ([_group(family=family)], [kept])
    assert _stamped_lines(got) == []


def test_llm_rows_at_every_member_line_stay_their_own_rows() -> None:
    llm = [_tiered(line, "CWE-23", "llm") for line in _SINKS]
    kept = copy.deepcopy(llm)
    got = _fold([*_members(), *llm])
    assert (_carried(got[:1]), got[1:]) == ([_group()], kept)


def _relative_sinks(root: Path, provenance: str) -> list[Any]:
    """``sinks`` of each row ``audit_runner._fold_hint_groups`` gives back for the group's
    members on ``root``'s ``app/store.py``, named absolutely as a skill names them, and a
    CWE-73 row of ``provenance`` at a member's line naming its file relative to the root, as
    the LLM tier does."""
    beside = _tiered(7, "CWE-73", provenance, "app/store.py")
    members = _members(path=root / "app" / "store.py")
    got = audit_runner._fold_hint_groups([*members, beside], str(root), "r")
    return [_flow_sinks(row) for row in got]


@pytest.mark.parametrize("provenance", ["llm", "llm_l5_verified"])
def test_the_audits_fold_keeps_an_llm_row_named_relative_to_the_root(
    tmp_path: Path, provenance: str
) -> None:
    assert _relative_sinks(tmp_path, provenance) == [list(_SINKS), None]


# ── (b) a member's LLM merges ride on the group row ──

CARRIED: list[tuple[str, dict[int, dict[str, Any]], Any, Any]] = [
    ("PIN no member merged: neither key", {}, ABSENT, ABSENT),
    ("an LLM row merged into a member", {1: {"merged_llm": [_A]}}, [_A], ABSENT),
    ("the anchor's and the last member's, in member order",
     {0: {"merged_llm": [_B]}, 2: {"merged_llm": [_A]}}, [_B, _A], ABSENT),
    ("an entry two members share, once",
     {0: {"merged_llm": [_A, _B]}, 1: {"merged_llm": [_B]}, 2: {"merged_llm": [_C, _A]}},
     [_A, _B, _C], ABSENT),
    ("LLM rows dropped against a member", {1: {"merged_llm_dropped": 1}}, ABSENT, 1),
    ("the members' dropped counts summed",
     {0: {"merged_llm_dropped": 2}, 2: {"merged_llm_dropped": 3}}, ABSENT, 5),
    ("both keys, on different members",
     {0: {"merged_llm": [_C]}, 2: {"merged_llm": [_A], "merged_llm_dropped": 4}}, [_C, _A], 4),
]


@pytest.mark.parametrize(("extras", "merged", "dropped"), cases(CARRIED))
def test_the_group_row_carries_its_members_llm_merges(
    extras: Extras, merged: Any, dropped: Any
) -> None:
    got = _fold(_carrying(_members(), extras))
    assert (_carried(got), _stamped_lines(got)) == ([_group(merged=merged, dropped=dropped)], [])


def test_the_members_keep_only_their_own_merges() -> None:
    """PIN: the member rows a group row keeps for the validate stage (``hint_rows``), or the
    rows a refused group keeps, each hold its own merges and no other member's."""
    extras = {0: {"merged_llm": [_A]}, 2: {"merged_llm": [_B], "merged_llm_dropped": 2}}
    got = _fold(_carrying(_members(), extras))
    members = [row for out in got for row in hint_rows(out)]
    assert [_merges(row) for row in members] == [([_A], ABSENT), (ABSENT, ABSENT), ([_B], 2)]


_STAGE_MERGES = {0: {"merged_llm": [_A]}, 2: {"merged_llm": [_B], "merged_llm_dropped": 2}}


@pytest.mark.usefixtures("fresh_quotes")
def test_a_kept_group_row_carries_its_members_merges_through_the_stage(tmp_path: Path) -> None:
    """``finalize_skill_findings``: an L1-equal group stays one row, no rollup parent, and the
    row the stage hands on carries the members' merges."""
    rows = _carrying(_file_members(_written(tmp_path, "# keep")), _STAGE_MERGES)
    got = _finalized(rows, tmp_path)
    want = (_FILE_SINKS[0], "CWE-22", "skill", list(_FILE_SINKS), [_A, _B], 2)
    assert _carried(got) == [want]


@pytest.mark.usefixtures("fresh_quotes")
def test_an_ungrouped_member_keeps_only_its_own_merges(tmp_path: Path) -> None:
    """PIN: a group the stage cannot keep (a member validates apart, R5) gives back each
    member's own row with its own merges, as a never-grouped row has them."""
    rows = _carrying(_file_members(_written(tmp_path, "# nosec")), _STAGE_MERGES)
    got = sorted(_carried([r for r in _finalized(rows, tmp_path) if not r.get("is_rollup")]))
    assert got == [
        (4, "CWE-22", "skill", None, [_A], ABSENT),
        (8, "CWE-22", "skill", None, ABSENT, ABSENT),
        (11, "CWE-22", "skill", None, [_B], 2),
    ]


# ── (c) the deterministic refusals stand (PIN) ──

DETERMINISTIC_BESIDE: list[tuple[str, str, int, str, str]] = [
    ("a skill row (CWE-23) at a member's line", "path", 7, "CWE-23", "skill"),
    ("a catalog rollup (CWE-23) at the anchor's line", "path", 3, "CWE-23", "catalog_rollup"),
    ("a trusted signature (CWE-73) at the last member's line", "path", 10, "CWE-73",
     "signature_trusted"),
    ("a candidate signature (CWE-706) at a member's line", "path", 7, "CWE-706",
     "signature_candidate"),
    ("a plugin's row (CWE-36) at a member's line", "path", 7, "CWE-36", "semgrep"),
    ("llm inside the provenance, not leading it", "path", 7, "CWE-23", "skill_llm"),
    ("a skill row (CWE-77) at a command member's line", "command", 7, "CWE-77", "skill"),
]


@pytest.mark.parametrize(("family", "line", "category", "provenance"), cases(DETERMINISTIC_BESIDE))
def test_a_deterministic_row_at_a_member_line_still_refuses(
    family: str, line: int, category: str, provenance: str
) -> None:
    _assert_kept([*_members(family), _tiered(line, category, provenance)])


def _beside_both(rows: Rows) -> Rows:
    """``rows`` with an LLM row at one member's line and a skill row at another's."""
    return [*rows, _tiered(7, "CWE-23", "llm"), _tiered(10, "CWE-73", "skill")]


MEMBER_REFUSED: list[tuple[str, dict[int, dict[str, Any]], Callable[[Rows], Rows]]] = [
    ("collapsed_from on a member", {1: {"collapsed_from": _KEPT}}, list),
    ("collapsed_from beside merged_llm on one member",
     {1: {"collapsed_from": _KEPT, "merged_llm": [_A]}}, list),
    ("collapsed_from on one member, merged_llm on another",
     {0: {"merged_llm": [_A]}, 2: {"collapsed_from": _KEPT}}, list),
    ("a member's row missing, another carrying merged_llm",
     {0: {"merged_llm": [_A]}}, lambda rows: [rows[0], rows[2]]),
    ("the members out of order, one carrying merged_llm_dropped",
     {1: {"merged_llm_dropped": 2}}, lambda rows: rows[::-1]),
    ("a skill row decides, whatever LLM row stands beside it", {}, _beside_both),
]


@pytest.mark.parametrize(("extras", "arrange"), cases(MEMBER_REFUSED))
def test_a_deterministic_member_refusal_still_refuses(
    extras: Extras, arrange: Callable[[Rows], Rows]
) -> None:
    _assert_kept(arrange(_carrying(_members(), extras)))


@pytest.mark.parametrize("provenance", ["skill", "signature_trusted"])
def test_the_audits_fold_still_refuses_a_deterministic_row_named_relative_to_the_root(
    tmp_path: Path, provenance: str
) -> None:
    assert _relative_sinks(tmp_path, provenance) == [None] * 4


def test_the_cases_name_each_tier_by_the_shared_rule() -> None:
    """PIN: the tables' LLM provenances are LLM-family by ``is_llm_provenance``, their
    deterministic ones are not, so each case tests the tier it names."""
    llm = {case[4] for case in LLM_BESIDE} | {_A["provenance"], _B["provenance"]}
    deterministic = {case[4] for case in DETERMINISTIC_BESIDE}
    misnamed = (sorted(filterfalse(is_llm_provenance, llm)),
                sorted(filter(is_llm_provenance, deterministic)))
    assert misnamed == ([], [])


# ── (d) the group row does not depend on the LLM tier ──

STABLE: list[tuple[str, str, int, str]] = [
    ("CWE-23 at a member's line", "path", 7, "CWE-23"),
    ("the rule's own CWE-22 at the anchor's line", "path", 3, "CWE-22"),
    ("CWE-88 at a command member's line", "command", 10, "CWE-88"),
]


@pytest.mark.parametrize(("family", "line", "category"), cases(STABLE))
def test_an_llm_row_never_changes_the_group_row(family: str, line: int, category: str) -> None:
    alone = _fold(_members(family))
    beside = _fold([*_members(family), _tiered(line, category, "llm")])
    assert (len(alone), beside[:1]) == (1, alone)


# ── the audit: the model's rows on the production order of steps ──

# The audited file: every member line has a code window.
_SOURCE = "".join(f"value_{n} = {n}\n" for n in range(1, 25))
# The model's row at the second member's line, named relative to the root as the LLM tier
# names it; its ``check_id``-carrying twin, which the agent's dedup drops against a member
# (same check id, same file) as one ``merged_llm`` entry.
_ANSWER = {
    "severity": "high", "category": "CWE-23", "title": "Relative traversal reaches a file call",
    "description": "model reasoning", "file_path": "app/store.py", "line_start": 7,
    "line_end": 7, "recommendation": "fix",
}
_TWIN = {**_ANSWER, "category": "CWE-22", "title": "Path reaches a file call",
         "check_id": family_rule("path").check_id}
_TWIN_MERGE = [{"provenance": "llm", "description": "model reasoning"}]
_MODEL_ROW = (7, "CWE-23", "llm", None, ABSENT, ABSENT)

_MERGED_GROUP = _group(merged=_TWIN_MERGE, provenance="skill")

AUDITS: list[tuple[str, list[dict[str, Any]], list[tuple[Any, ...]]]] = [
    ("the model's CWE-23 row at a member's line", [_ANSWER],
     [_group(provenance="skill"), _MODEL_ROW]),
    ("the model's twin of a member, merged into it", [_TWIN], [_MERGED_GROUP]),
    ("both", [_TWIN, _ANSWER], [_MERGED_GROUP, _MODEL_ROW]),
]


def _audit(monkeypatch: pytest.MonkeyPatch, root: Path, answer: Rows) -> Rows:
    """The ``result`` snapshot's findings of one LLM-on ``run_combined_audit`` of ``root``
    (validate off): a skill emits the group's stamped member rows on ``app/store.py`` and the
    model answers ``answer`` in every batch."""
    path = write(root / "app" / "store.py", _SOURCE)
    rows = _stamped([_row(n, path=path, nl_lines=_SOURCE.split("\n")) for n in _SINKS], _SINKS)
    _llm_env(monkeypatch, root, lambda _batch: copy.deepcopy(answer))
    events = list(audit_runner.run_combined_audit(
        run_id="run-0104-ds2", source_path=str(root), categories=["injection"],
        skill_map={"injection": lambda _root: {"findings": rows}}, skill_tools=DUMMY_TOOLS,
        instructions="audit", use_llm=True,
    ))
    return result_findings(events)


@pytest.mark.parametrize(("answer", "want"), cases(AUDITS))
def test_an_llm_on_audit_folds_on_its_deterministic_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: Rows, want: list[tuple[Any, ...]]
) -> None:
    """The group row with the members' merges, and the model's own row beside it; no row of
    the snapshot keeps a private (``_``) key."""
    got = _audit(monkeypatch, tmp_path, answer)
    assert (_carried(got), _private(got, "_")) == (want, [])
