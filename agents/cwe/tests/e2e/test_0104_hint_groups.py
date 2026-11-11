"""Feature 0104 WS-A2 -- a file's hint-only rows of one rule, reported as ONE row (E2E).

Business contract (LLD §4.1, as ruled by A66; OD-1, OD-2, D-O (1))
------------------------------------------------------------------
A file whose every row of one AST rule (CWE-22 path traversal, CWE-78 command injection) is
hint-only -- reached by nothing but the parameter-name hint, A1's ``param_hint`` -- is reported
as ONE row: the row at the anchor, the lowest sink line no CWE-36 child replaced, whose
``validation.flow.sinks`` lists every member's sink line. No other member line keeps a row of
that check. The rows are grouped where the agent finalizes them (``finalize_skill_findings``:
the line collapse, the code window, the fold, the validate stage; LLM off), never in a skill,
so every site here asserts on the finalized rows. A file keeps every row of its own when:

* S1 -- another row of the rule is reached by a request, here or on the same sink line;
* S2 -- one member validates differently from the anchor: a suppression marker above it, or a
  name on its sink line the file validates with an anchored pattern (``guarded``). Each row
  then keeps its own ``validation_status``;
* R1, R2 -- another check's row of the path family stands at a member's line (a CWE-23 row,
  or a CWE-23 rollup parent at the anchor's line);
* it is one of A1's review probes (a request flow and a hint flow at one sink line).

Fixture layout: ``fixtures/0104_hint_tier/a2/``, scanned by the two AST skills and the CWE-23
skill (``_0104_sites.scan``), then finalized; ``a1/`` for the review probes. A site is a 0101
marker that names its check id. Every ``finding`` site of an AST check names ``SINKS=``: its
row's sink lines, ``_``-joined, or ``none`` for a row that carries no ``sinks``. ``STATUS=``
pins the row's ``validation_status``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests._0104_sites import (
    A2,
    A2_SINKED,
    A2_SITES,
    CATEGORY,
    CHECK,
    SITES,
    attrs,
    category_of,
    finalized,
    row_sinks,
    sinks_of,
    site_key,
)
from tests.e2e._0101_markers import Site, _hit, assert_population, verdicts

# (finding sites, clean sites, finalized rows of a site's category): a deleted fixture fails.
FLOOR = (25, 10, 25)
AST_CHECKS = (CHECK["CWE-22"], CHECK["CWE-78"])
STATUSED = [s for s in A2_SITES if "STATUS" in attrs(s)]
A1_PROBES = ("a1/two_args/shelve.ts", "a1/nested/reflect.ts", "a1/shared_helper/texts.js")
Final = tuple[Path, list[dict[str, Any]]]


@pytest.fixture(scope="module")
def final(tmp_path_factory: pytest.TempPathFactory) -> Final:
    return finalized(tmp_path_factory, (A2, "a1"))


def _only_row(final: Final, site: Site) -> dict[str, Any]:
    """The one finalized row of the site's check id on the site's file and line."""
    root, rows = final
    found = [r for r in rows if _hit(r, site, category_of(site), root)]
    assert len(found) == 1, found
    return found[0]


def _rows_of(final: Final, rel: str) -> list[dict[str, Any]]:
    """The finalized rows of the file ``rel`` names under the copy."""
    root, rows = final
    return [r for r in rows if r["file_path"] == str(root / rel)]


def _finding_sites(rel: str) -> list[Site]:
    """The ``finding`` sites of the 0104 tree in the file ``rel`` names."""
    return [s for s in SITES if s.rel == rel and s.verdict == "finding"]


def _counted(row: dict[str, Any]) -> bool:
    """A finding (no rollup parent) of a category a site may name."""
    return not row.get("is_rollup") and row["category"] in CATEGORY.values()


def _ast_finding(site: Site) -> bool:
    return site.verdict == "finding" and site.check in AST_CHECKS


def test_every_site_names_a_check_and_each_ast_row_its_sinks() -> None:
    assert A2_SITES, "no a2/ site"
    assert all(s.check in CATEGORY for s in A2_SITES)
    assert [s for s in A2_SITES if _ast_finding(s)] == A2_SINKED


def test_population_floor(final: Final) -> None:
    root, rows = final
    under = [r for r in rows if r["file_path"].startswith(f"{root / A2}/") and _counted(r)]
    assert_population(A2_SITES, under, *FLOOR)


def _verdict(final: Final, site: Site) -> str:
    root, rows = final
    return verdicts(rows, [site], category_of(site), root)[site]


@pytest.mark.parametrize("site", A2_SITES, ids=site_key)
def test_site_verdict(final: Final, site: Site) -> None:
    got = _verdict(final, site)
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("site", A2_SINKED, ids=site_key)
def test_row_lists_its_group_sinks(final: Final, site: Site) -> None:
    """S3: the anchor's row lists every unreplaced member's sink line; a kept row lists none."""
    assert row_sinks(_only_row(final, site)) == sinks_of(site)


@pytest.mark.parametrize("site", STATUSED, ids=site_key)
def test_kept_row_keeps_its_own_status(final: Final, site: Site) -> None:
    """S2: a file a member keeps ungrouped validates each row on its own line."""
    assert _only_row(final, site)["validation_status"] == attrs(site)["STATUS"]


@pytest.mark.parametrize("rel", A1_PROBES)
def test_a1_review_probe_is_never_grouped(final: Final, rel: str) -> None:
    """A1's review probes keep each finding row, and no row of theirs carries ``sinks``."""
    sites, rows = _finding_sites(rel), _rows_of(final, rel)
    assert sites and {_verdict(final, s) for s in sites} == {"finding"}
    assert rows and list(filter(row_sinks, rows)) == []
