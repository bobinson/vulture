"""Feature 0104 WS-A2, decision D-S (5): an LLM row that would evict the group row refuses it.

Rule (LLD §4.1 A2, as D-S (2) and D-S (5) amend it). ``consume.fold_hint_groups`` decides on
the deterministic rows (D-S (2)), with ONE exception: it refuses a stamped group when an
LLM-family row (``shared.provenance.is_llm_provenance``) that the backend would merge with the
group's ANCHOR row — standing at the anchor's line of the anchor's file, of a CWE one line
reconciles with the anchor's (its dedup family or a ChildOf relation,
``shared.tools.finding_collapse.reconciled_on_line``) — is STRICTLY more severe than the anchor,
in the project's severity order (``finding_collapse.max_severity``: critical > high > medium >
low > info).

* (a) refused: every member stays its own row, in its place, no ``_hint_*`` key left, and the
  LLM row is unchanged — for the path family (CWE-22, 23, 36, 73, a ChildOf ancestor) and the
  command family (CWE-78, 77, 88, a ChildOf ancestor);
* (b) an equally or less severe LLM row at the anchor's line folds (D-S (2));
* (c) a more severe LLM row at another member's line (or at the anchor's line of another file)
  folds, and stays its own row;
* (d) a more severe LLM row of an unrelated CWE at the anchor's line folds;
* (e) the group row is the same row with and without a non-refusing LLM row.

Why: the Go backend's cross-agent dedup lets a strictly more severe LLM row win its (file, line,
family) key against a deterministic row, so that row would evict the group row, and every other
member — folded into it — would leave the persisted set with it.

RED until D-S (5) lands: the (a) tests. The others are PINS, green on the current tree.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from shared import audit_runner
from shared.provenance import is_llm_provenance
from shared.tools.finding_collapse import max_severity, reconciled_on_line
from tests.unit.ast._0104 import (
    _PATH,
    _SINKS,
    Rows,
    _carrying,
    _flow_sinks,
    _fold,
    _members,
    _private,
    cases,
    family_rule,
)
from tests.unit.ast.test_0104_fold_deterministic import _tiered

# The anchor's line: the group row stands there, at the anchor's severity.
ANCHOR = _SINKS[0]
# The members' stamp (a group row keeps its members' rows under ``_hint_rows``; no row keeps it).
_STAMP = "_hint_group"
# The same line number in another file of the audit.
_ELSEWHERE = _PATH.with_name("other.py")
# D-S (5)'s severity order, most severe first.
ORDER = ("critical", "high", "medium", "low", "info")


def _llm(
    line: int, category: str, severity: str, provenance: str = "llm", path: Path | str = _PATH
) -> dict[str, Any]:
    """An LLM-tier row of ``category`` and ``severity`` at ``line`` (``provenance`` names the
    tier, ``is_llm_provenance``)."""
    return {**_tiered(line, category, provenance, path), "severity": severity}


def _members_at(family: str, anchor: str) -> Rows:
    """The group's stamped member rows of ``family``, the anchor's of severity ``anchor`` (the
    other members keep the rule's, ``high``)."""
    return _carrying(_members(family), {0: {"severity": anchor}})


def _unstamped(row: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``row`` without its stamp."""
    return {key: copy.deepcopy(value) for key, value in row.items() if key != _STAMP}


def _assert_apart(family: str, anchor: str, beside: Rows) -> None:
    """Refused: every member and every LLM row exactly as it came, in its place; no ``_hint_*``
    key left on any row."""
    findings = [*_members_at(family, anchor), *copy.deepcopy(beside)]
    want = [_unstamped(row) for row in findings]
    got = _fold(findings)
    assert (got, _private(got)) == (want, [])


def _assert_folded(family: str, anchor: str, beside: Rows) -> None:
    """Folded: the group row in the anchor's place, at the anchor's line and severity, holding
    every member's sink line, then each LLM row exactly as it came; no row stamped."""
    got = _fold([*_members_at(family, anchor), *copy.deepcopy(beside)])
    head = (got[0]["line_start"], got[0]["severity"], _flow_sinks(got[0]))
    assert (head, got[1:]) == ((ANCHOR, anchor, list(_SINKS)), beside)
    assert _private(got, _STAMP) == []


# A case: (id, the rule's family, the anchor's severity, the LLM rows beside the members).
Case = tuple[str, str, str, Rows]

# ── (a) a more severe LLM row the backend merges with the anchor refuses (RED) ──

REFUSED: list[Case] = [
    ("the rule's own CWE-22", "path", "high", [_llm(ANCHOR, "CWE-22", "critical")]),
    ("CWE-23", "path", "high", [_llm(ANCHOR, "CWE-23", "critical")]),
    ("an L5-verified CWE-36", "path", "high",
     [_llm(ANCHOR, "CWE-36", "critical", "llm_l5_verified")]),
    ("CWE-73", "path", "high", [_llm(ANCHOR, "CWE-73", "critical")]),
    ("CWE-073, a leading zero", "path", "high", [_llm(ANCHOR, "CWE-073", "critical")]),
    ("a ChildOf ancestor (CWE-706)", "path", "high", [_llm(ANCHOR, "CWE-706", "critical")]),
    ("a high CWE-23 over a medium anchor, the other members high", "path", "medium",
     [_llm(ANCHOR, "CWE-23", "high")]),
    ("an upper-case LLM tier, low over an info anchor", "path", "info",
     [_llm(ANCHOR, "CWE-22", "low", "LLM")]),
    ("one of two rows at the anchor's line", "path", "high",
     [_llm(ANCHOR, "CWE-23", "high"), _llm(ANCHOR, "CWE-36", "critical")]),
    ("the command rule's own CWE-78", "command", "high", [_llm(ANCHOR, "CWE-78", "critical")]),
    ("CWE-77", "command", "high", [_llm(ANCHOR, "CWE-77", "critical")]),
    ("a padded CWE-88", "command", "high", [_llm(ANCHOR, "CWE-88", "critical", " llm\t")]),
    ("a ChildOf ancestor (CWE-74) of the command rule", "command", "high",
     [_llm(ANCHOR, "CWE-74", "critical")]),
    ("a medium CWE-77 over a low command anchor", "command", "low",
     [_llm(ANCHOR, "CWE-77", "medium", "llm_l5_verified")]),
]


@pytest.mark.parametrize(("family", "anchor", "beside"), cases(REFUSED))
def test_a_more_severe_llm_row_at_the_anchor_line_refuses(
    family: str, anchor: str, beside: Rows
) -> None:
    _assert_apart(family, anchor, beside)


@pytest.mark.parametrize("provenance", ["llm", "llm_l5_verified"])
def test_the_audits_fold_refuses_for_a_more_severe_row_named_relative_to_the_root(
    tmp_path: Path, provenance: str
) -> None:
    """``audit_runner._fold_hint_groups``: the LLM tier names its file relative to the root, a
    skill names it absolutely; the anchor's site is one site."""
    members = _members(path=tmp_path / "app" / "store.py")
    beside = _llm(ANCHOR, "CWE-73", "critical", provenance, "app/store.py")
    got = audit_runner._fold_hint_groups([*members, beside], str(tmp_path), "r")
    assert ([_flow_sinks(row) for row in got], _private(got)) == ([None] * 4, [])


# ── (b) an equally or less severe LLM row at the anchor's line folds (PIN, D-S (2)) ──

NOT_MORE_SEVERE: list[Case] = [
    ("an equally severe CWE-22", "path", "high", [_llm(ANCHOR, "CWE-22", "high")]),
    ("a less severe CWE-23", "path", "high", [_llm(ANCHOR, "CWE-23", "medium")]),
    ("an info CWE-36", "path", "high", [_llm(ANCHOR, "CWE-36", "info")]),
    ("a low L5-verified ChildOf ancestor (CWE-706)", "path", "high",
     [_llm(ANCHOR, "CWE-706", "low", "llm_l5_verified")]),
    ("a medium CWE-73 at a medium anchor", "path", "medium", [_llm(ANCHOR, "CWE-73", "medium")]),
    ("a critical CWE-22 at a critical anchor", "path", "critical",
     [_llm(ANCHOR, "CWE-22", "critical")]),
    ("an equally severe CWE-77", "command", "high", [_llm(ANCHOR, "CWE-77", "high")]),
    ("a low padded CWE-88", "command", "high", [_llm(ANCHOR, "CWE-88", "low", " llm\t")]),
    ("an info upper-case CWE-78 at a low anchor", "command", "low",
     [_llm(ANCHOR, "CWE-78", "info", "LLM")]),
]


@pytest.mark.parametrize(("family", "anchor", "beside"), cases(NOT_MORE_SEVERE))
def test_an_equally_or_less_severe_llm_row_at_the_anchor_line_folds(
    family: str, anchor: str, beside: Rows
) -> None:
    _assert_folded(family, anchor, beside)


# ── (c) a more severe LLM row away from the anchor's site folds, its own row (PIN) ──

AWAY: list[Case] = [
    ("a critical CWE-22 at the second member's line", "path", "high",
     [_llm(_SINKS[1], "CWE-22", "critical")]),
    ("a critical CWE-73 at the last member's line", "path", "high",
     [_llm(_SINKS[2], "CWE-73", "critical")]),
    ("a critical L5-verified CWE-706 at a member's line over a medium anchor", "path", "medium",
     [_llm(_SINKS[1], "CWE-706", "critical", "llm_l5_verified")]),
    ("critical rows at every other member's line", "path", "high",
     [_llm(_SINKS[1], "CWE-23", "critical"), _llm(_SINKS[2], "CWE-36", "critical")]),
    ("a critical CWE-22 on the line before the anchor's", "path", "high",
     [_llm(ANCHOR - 1, "CWE-22", "critical")]),
    ("a critical CWE-22 at the anchor's line of another file", "path", "high",
     [_llm(ANCHOR, "CWE-22", "critical", path=_ELSEWHERE)]),
    ("a critical CWE-77 at a command member's line", "command", "high",
     [_llm(_SINKS[1], "CWE-77", "critical")]),
    ("a critical CWE-78 at the last command member's line over a low anchor", "command", "low",
     [_llm(_SINKS[2], "CWE-78", "critical")]),
]


@pytest.mark.parametrize(("family", "anchor", "beside"), cases(AWAY))
def test_a_more_severe_llm_row_away_from_the_anchor_folds_and_stays_its_own_row(
    family: str, anchor: str, beside: Rows
) -> None:
    _assert_folded(family, anchor, beside)


# ── (d) a more severe LLM row of an unrelated CWE at the anchor's line folds (PIN) ──

UNRELATED: list[Case] = [
    ("a critical CWE-79", "path", "high", [_llm(ANCHOR, "CWE-79", "critical")]),
    ("the command family's CWE-78 at a path anchor", "path", "high",
     [_llm(ANCHOR, "CWE-78", "critical")]),
    ("CWE-74, a command ancestor, at a low path anchor", "path", "low",
     [_llm(ANCHOR, "CWE-74", "critical")]),
    ("CWE-918 at an info path anchor", "path", "info", [_llm(ANCHOR, "CWE-918", "critical")]),
    ("the path family's CWE-22 at a command anchor", "command", "high",
     [_llm(ANCHOR, "CWE-22", "critical")]),
    ("a high CWE-89 at a medium command anchor", "command", "medium",
     [_llm(ANCHOR, "CWE-89", "high", "llm_l5_verified")]),
]


@pytest.mark.parametrize(("family", "anchor", "beside"), cases(UNRELATED))
def test_a_more_severe_llm_row_of_an_unrelated_cwe_at_the_anchor_line_folds(
    family: str, anchor: str, beside: Rows
) -> None:
    _assert_folded(family, anchor, beside)


# ── (e) a non-refusing LLM row never changes the group row (PIN) ──

FOLDING: list[Case] = [*NOT_MORE_SEVERE, *AWAY, *UNRELATED]


@pytest.mark.parametrize(("family", "anchor", "beside"), cases(FOLDING))
def test_a_non_refusing_llm_row_never_changes_the_group_row(
    family: str, anchor: str, beside: Rows
) -> None:
    alone = _fold(_members_at(family, anchor))
    got = _fold([*_members_at(family, anchor), *copy.deepcopy(beside)])
    assert (len(alone), got[:1]) == (1, alone)


# ── the cases test what they name (PIN) ──


def _more_severe(severity: str, than: str) -> bool:
    """``severity`` ranks strictly above ``than`` in the project's order (``max_severity``)."""
    return severity != than and max_severity([than, severity]) == severity


def _merges_with_anchor(family: str, row: dict[str, Any]) -> bool:
    """``row`` stands at the anchor's site, of a CWE one line reconciles with the rule's."""
    at_anchor = (row["file_path"], row["line_start"]) == (str(_PATH), ANCHOR)
    return at_anchor and reconciled_on_line({"category": family_rule(family).category}, row)


def _evicts(family: str, anchor: str, row: dict[str, Any]) -> bool:
    """D-S (5)'s row: LLM-family, merged with the anchor, strictly more severe than it."""
    llm = is_llm_provenance(row["provenance"])
    return llm and _merges_with_anchor(family, row) and _more_severe(row["severity"], anchor)


def _evicting(table: list[Case]) -> list[str]:
    """The ids of ``table``'s cases holding a row D-S (5) names."""
    return [case_id for case_id, family, anchor, beside in table
            if any(_evicts(family, anchor, row) for row in beside)]


def test_each_case_holds_the_row_it_names() -> None:
    """Every refusing case holds a row D-S (5) names; no folding case holds one."""
    assert (_evicting(REFUSED), _evicting(FOLDING)) == ([case[0] for case in REFUSED], [])


def test_the_severity_order_is_the_projects() -> None:
    """``max_severity`` ranks the five labels in D-S (5)'s order, most severe first."""
    assert [max_severity(ORDER[n:]) for n in range(len(ORDER))] == list(ORDER)
