"""Feature 0104, G19 (a) -- the validate stage sees the rows 0104 keeps exactly as before.

``finalize_skill_findings`` is what a full audit does to skill rows with the LLM off (the
pre-egress choke point, the skill-vs-skill line collapse, the code window, the deterministic
validate stage). Every 0104 rule only labels or removes AST rows, so on every row it keeps the
stage must answer as it did before 0104 (LLD §4.1 "A1, result"; §6.2 G19 (a)):

* ``validation_status`` of the member row on every ``finding`` site of the ``a1/``, ``c/``,
  ``d/`` and ``h/`` trees equals the recorded pre-0104 status (A1's label is no voter input);
* the rollup parents (``is_rollup``) of every file of those trees with no ``clean`` site --
  a file no rule removes a row from -- are the recorded pre-0104 parents. A file with a
  ``clean`` site loses rows by design, so its parents may change and are not pinned here.

The expectations (``_0104_validate_stage.json``) were recorded from the pre-0104 tree; a site
whose row is new (the CWE-73 release sites) has none. WS-A2 adds the ``a2/`` tree, the
grouped-file checks and the ``line_signature`` agreement at its own RED task (plan 0.12).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from shared.audit_runner import finalize_skill_findings
from shared.testing.isolation import isolate
from tests._0104_sites import FIXTURES, SITES, WORKSTREAMS, rel_key, scan, site_key, sub_of
from tests.e2e._0101_markers import Site, neutral_copy

EXPECT: dict[str, dict[str, Any]] = json.loads(
    Path(__file__).with_name("_0104_validate_stage.json").read_text(encoding="utf-8"))
Keyed = tuple[dict[str, set[str]], dict[str, list[str]]]


def _keyed(rows: list[dict[str, Any]], root: Path) -> Keyed:
    """Member statuses by ``path:line:category``; parent ``line:category`` keys by path."""
    members: defaultdict[str, set[str]] = defaultdict(set)
    parents: defaultdict[str, list[str]] = defaultdict(list)
    for row in rows:
        rel, _, rest = rel_key(row, root).partition(":")
        if row.get("is_rollup"):
            parents[rel].append(rest)
        else:
            members[f"{rel}:{rest}"].add(str(row.get("validation_status")))
    return members, parents


@pytest.fixture(scope="module")
def staged(tmp_path_factory: pytest.TempPathFactory) -> Keyed:
    """The four trees' rows through the stage, under the documented defaults and a private,
    empty L5 cache (the stage stores evidence quotes there)."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("vstage0104"))
    with pytest.MonkeyPatch.context() as patch:
        isolate(patch, tmp_path_factory.mktemp("vstage0104_home"))
        rows = scan(root, WORKSTREAMS)
        final = [r for sub in WORKSTREAMS
                 for r in finalize_skill_findings(rows[sub], str(root / sub), "run-0104")]
    return _keyed(final, root)


def _finding_site(site: Site) -> bool:
    return sub_of(site) in WORKSTREAMS and site.verdict == "finding"


def test_expectations_name_only_finding_sites() -> None:
    """No stale expectation: each status key is a ``finding`` site of the four trees, with
    its category."""
    keys, sites = set(EXPECT["status"]), set(map(site_key, filter(_finding_site, SITES)))
    assert keys and keys <= sites, sorted(keys - sites)


@pytest.mark.parametrize("key", sorted(EXPECT["status"]))
def test_kept_row_keeps_its_validation_status(staged: Keyed, key: str) -> None:
    members, _ = staged
    assert members.get(key) == {EXPECT["status"][key]}, (key, members.get(key))


@pytest.mark.parametrize("rel", sorted(EXPECT["parents"]))
def test_untouched_file_keeps_its_rollup_parents(staged: Keyed, rel: str) -> None:
    _, parents = staged
    assert sorted(parents.get(rel, [])) == EXPECT["parents"][rel]
