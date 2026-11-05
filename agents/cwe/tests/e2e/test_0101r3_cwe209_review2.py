"""Feature 0101 revision 3, implementation review round 2 -- CWE-209 arm corrections.

Business contract
-----------------
* F2 yields to a literal-only producer ONLY when nothing refills the field on
  the read's own root between the binding and the read. A fill there
  (`v.F = <error>`, `Object.assign(v, { F: <error> })`), in any language, keeps
  the file-wide verdict: the caught error text the routine writes back into
  the result is what reaches the peer. A literal refill, or a fill on another
  root, leaves the producer deciding.
* F3 reads a constructor whose parameter list declares members (TypeScript
  parameter properties, PHP promotion) across lines, as formatters wrap it;
  a named-argument construction reaches the member by name.
* H counts the writes a helper makes through the peer WRITER argument
  (`fmt.Fprint(w, err)`) whatever the parameter is named, and a parameter read
  through its error-text member (`e.Error()`, `e.message`). When the
  helper's own line is already the report (the base rule judges it), the call
  site is not reported a second time.
* A PascalCase `Results` root (a response-results factory) is the peer, so a
  value returned through `Results.Json(...)` is judged; a log type root is not.
* A producer that returns an error-role factory (`Result.fail(<error text>)`)
  fills the read's error field; a literal argument, or a factory whose name has
  no error role, does not.

Each unit is scanned on its own from a neutral copy (the rule skips test paths).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from tests.e2e._0101_markers import Site, neutral_copy, parse_tree, verdicts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "0101r3_cwe209"
CWE209 = "CWE-209"
PREFIXES = ("f2r2_", "f3r2_", "hr2_", "r5_")
SITES: list[Site] = [s for s in parse_tree(FIXTURES) if s.rel.split("/")[1].startswith(PREFIXES)]
# (pos floor, neg floor) per unit prefix
FLOORS = {"f2r2_": (5, 2), "f3r2_": (4, 2), "hr2_": (4, 5), "r5_": (3, 4)}
# neg units whose helper line is the base rule's report: exactly that one row, never the call too
ONE_ROW_UNITS = ("neg/hr2_go_helper_line_reported", "neg/hr2_ts_helper_line_reported",
                 "neg/hr2_go_http_error_err_member")


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, dict[str, list[dict]]]:
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe209r3review2"))
    per_unit = {u: check_information_exposure(str(root / u))["findings"] for u in sorted({_unit(s) for s in SITES})}
    return root, per_unit


def _rows(findings: list[dict], categories: tuple[str, ...] = (CWE209,)) -> list[dict]:
    return [f for f in findings if f.get("category") in categories]


@pytest.mark.parametrize("prefix", sorted(FLOORS))
def test_floors(prefix: str) -> None:
    pos = sum(1 for s in SITES if _unit(s).startswith(f"pos/{prefix}"))
    neg = sum(1 for s in SITES if _unit(s).startswith(f"neg/{prefix}"))
    assert pos >= FLOORS[prefix][0] and neg >= FLOORS[prefix][1], (prefix, pos, neg)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, per_unit = scanned
    got = verdicts(_rows(per_unit[_unit(site)]), [site], CWE209, root)[site]
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("unit", ONE_ROW_UNITS)
def test_a_reported_helper_line_is_not_reported_again_at_the_call(scanned, unit: str) -> None:
    _, per_unit = scanned
    rows = _rows(per_unit[unit], (CWE209, "CWE-550"))
    assert len(rows) == 1, [(r["category"], r["line_start"]) for r in rows]


@pytest.mark.parametrize("site", [s for s in SITES if s.rel.startswith("pos/")], ids=lambda s: _unit(s))
def test_genuine_site_reports_exactly_one_row(scanned, site: Site) -> None:
    root, per_unit = scanned
    same = [f for f in _rows(per_unit[_unit(site)])
            if int(f.get("line_start") or 0) == site.line and Path(f["file_path"]).relative_to(root) == Path(site.rel)]
    assert len(same) == 1, same
