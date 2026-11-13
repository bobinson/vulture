"""Feature 0104, G19 (a) -- the validate stage sees the rows 0104 keeps exactly as before.

``finalize_skill_findings`` is what a full audit does to skill rows with the LLM off (the
pre-egress choke point, the skill-vs-skill line collapse, the code window, WS-A2's fold of a
file's hint-only rows of one rule into one row, the deterministic validate stage). Every 0104
rule only labels, removes or groups AST rows, so on every row it keeps the stage must answer as
it did before 0104 (LLD §4.1 "A1, result" and S2; §6.2 G19 (a); A66 (3)). A member is read
through its group: a row with ``validation.flow.sinks`` gives its status to each listed line.

* ``validation_status`` of the member row on every ``finding`` site of the ``a1/``, ``c/``,
  ``d/`` and ``h/`` trees equals the recorded pre-0104 status (A1's label is no voter input);
* the rollup parents (``is_rollup``) of every file of those trees with no ``clean`` site -- a
  file no rule removes a row from -- are the recorded pre-0104 parents, less those of a
  category the file is grouped in on the tree under test: a group is one row, so L2 makes it
  no parent (OD-2 (a)). A file with a ``clean`` site loses rows by design, so its parents may
  change and are not pinned here;
* ``a2/`` (``_0104_validate_stage_a2.json``, recorded from the pre-A2 tree): every member --
  each sink line an ``a2/`` marker's ``SINKS=`` lists, or the marker's own line under
  ``SINKS=none`` -- keeps its pre-A2 status; a file the markers group has no parent of the
  grouped category, and every ``a2/`` file keeps its other pre-A2 parents; and for every
  member, ``context_heuristics.line_signature`` (the S2 predicate the heads group by) equals
  the status and the L1 checks ``finalize_skill_findings`` gives that member's row ungrouped.

The expectations (``_0104_validate_stage.json``) were recorded from the pre-0104 tree; a site
whose row is new (the CWE-73 release sites) has none.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from shared import audit_runner
from shared.validate import context_heuristics
from tests._0104_sites import (
    A2,
    A2_SINKED,
    A2_SITES,
    SITES,
    WORKSTREAMS,
    category_of,
    finalized,
    rel_key,
    row_sinks,
    sinks_of,
    site_key,
    sub_of,
)
from tests._ast_heads import relative
from tests.e2e._0101_markers import Site


def _recorded(name: str) -> dict[str, Any]:
    return json.loads(Path(__file__).with_name(name).read_text(encoding="utf-8"))


EXPECT = _recorded("_0104_validate_stage.json")
EXPECT_A2 = _recorded("_0104_validate_stage_a2.json")
# The checks of the layers after L1 (L2's rollup, the window parity, L5's coverage).
NOT_L1 = frozenset({"rollup", "window", "coverage"})
STAGE_VIEW = ("file_path", "line_start", "category", "check_id")


class Staged(NamedTuple):
    members: dict[str, set[str]]  # statuses by path:line:category, a group read through sinks
    parents: dict[str, list[str]]  # rollup parents' line:category keys by path
    grouped: dict[str, set[str]]  # the categories a path is grouped in


def _key_row(staged: Staged, row: dict[str, Any], root: Path) -> None:
    if row.get("is_rollup"):
        rel, _, rest = rel_key(row, root).partition(":")
        staged.parents[rel].append(rest)
    else:
        _key_member(staged, row, root)


def _key_member(staged: Staged, row: dict[str, Any], root: Path) -> None:
    """A row's status at its line, or a group row's at each line it lists."""
    sinks = row_sinks(row)
    for line in sinks or [row["line_start"]]:
        key = rel_key({**row, "line_start": line}, root)
        staged.members[key].add(str(row.get("validation_status")))
    if sinks:
        staged.grouped[relative(root, row["file_path"])].add(row["category"])


def _keyed(rows: list[dict[str, Any]], root: Path) -> Staged:
    staged = Staged(defaultdict(set), defaultdict(list), defaultdict(set))
    for row in rows:
        _key_row(staged, row, root)
    return staged


@pytest.fixture(scope="module")
def staged(tmp_path_factory: pytest.TempPathFactory) -> Staged:
    """The five trees' rows through the stage."""
    root, rows = finalized(tmp_path_factory, (*WORKSTREAMS, A2))
    return _keyed(rows, root)


def _finding_site(site: Site) -> bool:
    return sub_of(site) in WORKSTREAMS and site.verdict == "finding"


def _members(site: Site) -> list[str]:
    """The ``path:line:category`` of each member an ``a2/`` marker names: each line its
    ``SINKS=`` lists, or its own line under ``SINKS=none``."""
    return [site_key(replace(site, line=line)) for line in sinks_of(site) or [site.line]]


A2_MEMBERS = sorted(key for site in A2_SINKED for key in _members(site))
A2_GROUPED = [site for site in A2_SINKED if sinks_of(site)]


def _parents_kept(staged: Staged, recorded: list[str], rel: str) -> None:
    """``rel``'s parents are the recorded ones, less those of a category it is grouped in."""
    grouped = staged.grouped.get(rel, set())
    want = [key for key in recorded if key.partition(":")[2] not in grouped]
    assert sorted(staged.parents.get(rel, [])) == want, (rel, grouped)


def test_expectations_name_only_finding_sites() -> None:
    """No stale expectation: each status key is a ``finding`` site of the four trees, with
    its category."""
    keys, sites = set(EXPECT["status"]), set(map(site_key, filter(_finding_site, SITES)))
    assert keys and keys <= sites, sorted(keys - sites)


@pytest.mark.parametrize("key", sorted(EXPECT["status"]))
def test_kept_row_keeps_its_validation_status(staged: Staged, key: str) -> None:
    assert staged.members.get(key) == {EXPECT["status"][key]}, (key, staged.members.get(key))


@pytest.mark.parametrize("rel", sorted(EXPECT["parents"]))
def test_untouched_file_keeps_its_rollup_parents(staged: Staged, rel: str) -> None:
    _parents_kept(staged, EXPECT["parents"][rel], rel)


# ── WS-A2 (``a2/``) ──


def test_a2_expectations_name_every_member() -> None:
    files = {site.rel for site in A2_SITES}
    assert sorted(EXPECT_A2["status"]) == A2_MEMBERS and set(EXPECT_A2["parents"]) == files


@pytest.mark.parametrize("key", A2_MEMBERS)
def test_a2_member_keeps_its_validation_status(staged: Staged, key: str) -> None:
    assert staged.members.get(key) == {EXPECT_A2["status"][key]}, (key, staged.members.get(key))


@pytest.mark.parametrize("rel", sorted(EXPECT_A2["parents"]))
def test_a2_file_keeps_its_other_rollup_parents(staged: Staged, rel: str) -> None:
    _parents_kept(staged, EXPECT_A2["parents"][rel], rel)


@pytest.mark.parametrize("site", A2_GROUPED, ids=site_key)
def test_grouped_file_has_no_rollup_parent(staged: Staged, site: Site) -> None:
    """OD-2 (a): the group is one row, so L2 makes no parent of its category."""
    category = category_of(site)
    parents = staged.parents.get(site.rel, [])
    assert [key for key in parents if key.endswith(f":{category}")] == [], parents


@pytest.fixture(scope="module")
def unfolded(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    """``a2/``'s rows through the stage with A2's fold folding nothing: each member's own row."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(audit_runner, "fold_hint_groups", _no_fold, raising=False)
        root, rows = finalized(tmp_path_factory, (A2,))
    assert not list(filter(row_sinks, rows)), "a group was folded"
    return {rel_key(row, root): row for row in rows if not row.get("is_rollup")}


def _no_fold(findings: list[dict[str, Any]], _path_key: Any) -> list[dict[str, Any]]:
    return findings


def _l1_checks(row: dict[str, Any]) -> tuple[tuple[str, str, float], ...]:
    checks = row["validation"]["checks"]
    return tuple((c["id"], c["result"], c["weight"]) for c in checks if c["id"] not in NOT_L1)


@pytest.mark.parametrize("key", A2_MEMBERS)
def test_line_signature_agrees_with_the_stage(
    unfolded: dict[str, dict[str, Any]], key: str
) -> None:
    """S2's predicate is the stage's own verdict: for the member's ungrouped row, the status
    and the (id, result, weight) of each L1 check."""
    signature = getattr(context_heuristics, "line_signature", None)
    assert signature is not None, "context_heuristics.line_signature does not exist"
    row = unfolded[key]
    view = {name: row[name] for name in STAGE_VIEW}
    assert signature(view) == (row["validation_status"], _l1_checks(row)), key
