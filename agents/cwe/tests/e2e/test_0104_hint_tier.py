"""Feature 0104 -- AST hint-tier precision: the line-level E2E sites (LLD §5.2, plan 0.6).

Business contract
-----------------
The AST tier reports CWE-22 / CWE-78 / CWE-918 rows whose only external origin can be the
parameter-name hint (``external(param_hint)``). 0104 makes those rows honest and removes the
classes measured as false positives, without losing a row any adjudicated true positive needs:

* A1 -- a row whose every reported flow at its sink line is hint-only names it:
  ``validation.flow.heuristic = "param_hint"``. A row that a request (or any other external)
  flow reaches at its sink line carries no such key, and shows that flow. Nothing is silenced.
* C  -- a bare existence probe (``exists`` / ``access`` / ``stat`` / ``lstat`` ...) of a
  JS/TS entry function's hinted parameter ITSELF declines, when the file shows no other use of
  the function than its declaration, an export listing or a resolved call. A composed argument,
  a destructured or rest parameter, an unresolved same-file use, another language, a content
  read: all still report.
* D  -- ``hash`` / ``hexdigest`` are exact numeric (digest) keys, unless the file binds that
  name itself (declaration, object key, assignment target, one wrapping call, class field).
* H  -- Go: the predeclared ``delete`` is no HTTP client call (H1); a reader drain
  (``io.ReadAll``) is no path sink without file-system evidence (H2); a bare call to a
  same-package helper is no language global (H3).
* A declined span is released to the line-level CWE-73 claim (D-M (6)): the ``x73`` sites.

Fixture layout (``fixtures/0104_hint_tier``): one subdirectory per workstream (``a1 c d h``)
plus ``regress/`` (probes whose verdict no workstream moves), so a reverted workstream removes
one subdirectory. A site is a marker of the 0101 grammar (``tests/e2e/_0101_markers.py``) that
always names its check id; ``HINT=<token>|none`` and ``SHOWS=request`` on the marker line add
the row's ``validation.flow`` expectations (A1 only). The skills skip test paths, so every
subdirectory is scanned from one neutral copy, and twice: the second replay must be byte-equal.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests._0104_sites import (
    CATEGORY,
    FIXTURES,
    SITES,
    SUBDIRS,
    Rows,
    attrs,
    scan,
    site_key,
    sub_of,
)
from tests.e2e._0101_markers import Site, _hit, assert_population, neutral_copy, verdicts
from tests.unit.test_0102_held_out import held_out_keys

# (finding sites, clean sites, emitted rows) per subdirectory: a deleted fixture fails here.
FLOORS = {
    "a1": (21, 0, 21),
    "c": (57, 12, 57),
    "d": (25, 4, 25),
    "h": (34, 8, 34),
    "regress": (30, 0, 30),
}
LABELLED = [s for s in SITES if "HINT" in attrs(s)]
SHOWING = [s for s in SITES if "SHOWS" in attrs(s)]


@pytest.fixture(scope="module")
def copy_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return neutral_copy(FIXTURES, tmp_path_factory.mktemp("hint0104"))


@pytest.fixture(scope="module")
def scanned(copy_root: Path) -> Rows:
    return scan(copy_root)


def _owned(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if r.get("category") in CATEGORY.values()]


def _category(site: Site) -> str:
    return CATEGORY[site.check or ""]


def _only_row(scanned: Rows, root: Path, site: Site) -> dict[str, Any]:
    """The one row of the site's check id on the site's file and line."""
    rows = [r for r in scanned[sub_of(site)] if _hit(r, site, _category(site), root)]
    assert len(rows) == 1, rows
    return rows[0]


def test_every_site_names_a_check() -> None:
    assert SITES, f"no site under {FIXTURES}"
    assert all(s.check in CATEGORY for s in SITES), [s for s in SITES if s.check not in CATEGORY]


def test_every_subdirectory_is_a_workstream() -> None:
    assert {sub_of(s) for s in SITES} == set(FLOORS) == set(SUBDIRS)


@pytest.mark.parametrize("sub", sorted(FLOORS))
def test_population_floor(scanned: Rows, sub: str) -> None:
    """Marker counts and emitted rows per subdirectory: a run that scans nothing fails."""
    finding, clean, emitted = FLOORS[sub]
    sites = [s for s in SITES if sub_of(s) == sub]
    assert_population(sites, _owned(scanned[sub]), finding, clean, emitted)


@pytest.mark.parametrize("site", SITES, ids=site_key)
def test_site_verdict(scanned: Rows, copy_root: Path, site: Site) -> None:
    got = verdicts(scanned[sub_of(site)], [site], _category(site), copy_root)[site]
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("site", LABELLED, ids=site_key)
def test_site_label(scanned: Rows, copy_root: Path, site: Site) -> None:
    """A1 (HT-9): ``validation.flow.heuristic`` of the site's row, or no key for ``none``."""
    want = attrs(site)["HINT"]
    got = _only_row(scanned, copy_root, site)["validation"]["flow"].get("heuristic")
    assert got == (None if want == "none" else want), (site.rel, site.line, got)


@pytest.mark.parametrize("site", SHOWING, ids=site_key)
def test_site_shows_the_reaching_flow(scanned: Rows, copy_root: Path, site: Site) -> None:
    """A1 tie-break (A48): a row a request flow reaches at its sink line shows that flow."""
    flow = _only_row(scanned, copy_root, site)["validation"]["flow"]
    assert f"external:{attrs(site)['SHOWS']}" in flow["origins"], flow


def test_no_fixture_holds_a_held_out_identifier() -> None:
    """The 0102 held-out token rule over this tree: no held-out identifier is a fixture's."""
    files = list(filter(Path.is_file, sorted(FIXTURES.rglob("*"))))
    hits = {path.relative_to(FIXTURES).as_posix(): sorted(found)
            for path in files if (found := held_out_keys(path))}
    assert files and not hits, hits


def _canonical(rows: Rows) -> str:
    return json.dumps(rows, sort_keys=True, default=str)


def test_second_replay_is_byte_identical(scanned: Rows, copy_root: Path) -> None:
    """R14: the same copy scanned again gives the same rows, byte for byte."""
    assert _canonical(scan(copy_root)) == _canonical(scanned)
