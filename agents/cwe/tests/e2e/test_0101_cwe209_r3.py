"""Feature 0101 revision 3 -- CWE-209 reports every error disclosure its arms can prove (LLD 5.3.6, 5.3.7).

Business contract
-----------------
Revision 2 decided a field read (`res.json({ error: outcome.error })`) as
clean, and never treated a bare-call response helper (`writeError(w, 500,
err.Error())`) as a sink. Real leaks were missed on both counts. Revision 3
adds arms that each turn an unreported site into a reported one, and only
on evidence in the code:

* F  -- a result field is error text when the routine that produced it fills
  it from an error in the value it RETURNS (a keyed fill, a positional
  construction of a same-file type, a same-file factory or helper hop), or
  the file fills `.F = <error>`; a parameter-sourced fill counts only through
  a same-file caller that passes an error (P); `{ error: why }` reads `error`
  (R); detail-word fields (`message`) count through producer evidence (M).
  Persist-then-return-a-code, a side-effect hop, a throw and a cause passed
  to a foreign type are NOT evidence. Allman and K&R bodies decide alike.
* Y  -- a detail-role key over an error field, beside a literal code key.
* W  -- an object or collection filled from an error, then sent whole.
* C1/C2/H -- bare response helpers, responder callbacks, same-file helpers
  that write their parameter to a peer; a validator-sourced value (V) and a
  content-tested branch (T) are excused.
* S  -- the error event of an asynchronously iterated stream.
* X / X2 -- a projection-named helper, or a field's producer, followed to its
  ONLY definition in the scanned tree.

Fixture layout (`fixtures/0101_cwe209_r3`): one asserted site per unit; a
unit is a directory under ``pos/`` (a genuine disclosure: reported), ``neg/``
(nothing leaks: clean) or ``gap/`` (a known limit or known false positive,
pinned to the observed verdict so a change either way is seen). Each unit is
scanned ON ITS OWN, so a cross-file arm sees exactly the files of its unit.
Unit names start with the arm they exercise (`f_`, `rb_` return binding,
`al_` Allman/K&R, `y_`, `w_`, `ch_`, `s_`, `x_`, `x2_`, `shape_`, `k3_`).
The rule skips test paths, so units are scanned from a neutral copy.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree, verdicts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "0101_cwe209_r3"
CWE209 = "CWE-209"
KINDS = ("pos", "neg", "gap")
SITES: list[Site] = parse_tree(FIXTURES)

# (pos floor, neg floor) per arm prefix: LLD 14.6 "Fixtures" and the revision-3 plan table.
ARM_FLOORS = {
    "f_": (16, 8), "rb_": (0, 8), "al_": (6, 2), "y_": (1, 7), "w_": (7, 6), "ch_": (6, 6),
    "s_": (4, 3), "x_": (1, 4), "x2_": (1, 4),
}
GAP_SHAPES_FLOOR = 10
# Allman / K&R twins: the same producer in both brace styles decides alike.
TWINS = (
    ("al_allman_cs_record", "al_kr_cs_record"),
    ("al_allman_java_returned_var", "al_kr_java_returned_var"),
    ("al_allman_cs_hop", "al_kr_cs_hop"),
    ("al_allman_cs_persisted", "al_kr_cs_persisted"),
    ("al_psr_php", "al_kr_php"),
    ("al_allman_cs_attr_positional", "f_k_c02_cs_record"),
    ("al_allman_cs_initializer", "f_s13_cs_result"),
)


def _unit(site: Site) -> str:
    """`pos/f_s01.../site.ts` -> `pos/f_s01...`."""
    return "/".join(site.rel.split("/")[:2])


def _arm(unit: str) -> str:
    return unit.split("/")[1]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    """Every unit scanned on its own, from one neutral copy; all rows together."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe209r3"))
    findings: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            findings += check_information_exposure(str(unit))["findings"]
    return root, findings


def _rows(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("category") == CWE209]


def test_population_floor(scanned) -> None:
    """At least 42 genuine sites and 40 clean sites, and the rows are actually emitted."""
    _, findings = scanned
    pos = [s for s in SITES if s.rel.startswith("pos/")]
    assert len(pos) >= 42, len(pos)
    assert all(s.verdict == "finding" for s in pos)
    assert all(s.verdict == "clean" for s in SITES if s.rel.startswith("neg/"))
    assert_population(SITES, _rows(findings), min_finding=47, min_clean=40, min_emitted=47)


@pytest.mark.parametrize("prefix", sorted(ARM_FLOORS))
def test_arm_floors(prefix: str) -> None:
    """Every arm keeps its positive and negative fixtures (a deleted fixture fails here)."""
    pos = sum(1 for s in SITES if _unit(s).startswith(f"pos/{prefix}"))
    neg = sum(1 for s in SITES if _unit(s).startswith(f"neg/{prefix}"))
    want_pos, want_neg = ARM_FLOORS[prefix]
    assert pos >= want_pos and neg >= want_neg, (prefix, pos, neg)


def test_gap_shapes_floor() -> None:
    """The response shapes no arm covers stay pinned (R3-V.3 enumerates them)."""
    shapes = [s for s in SITES if _unit(s).startswith("gap/shape_")]
    assert len(shapes) >= GAP_SHAPES_FLOOR, len(shapes)


def test_one_asserted_site_per_unit() -> None:
    per_unit = Counter(_unit(s) for s in SITES)
    assert per_unit and max(per_unit.values()) == 1, [u for u, n in per_unit.items() if n > 1]
    units = {f"{k}/{p.name}" for k in KINDS for p in (FIXTURES / k).iterdir() if p.is_dir()}
    assert units == set(per_unit), sorted(units ^ set(per_unit))


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, findings = scanned
    got = verdicts(_rows(findings), [site], CWE209, root)[site]
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("site", [s for s in SITES if s.rel.startswith("pos/")], ids=lambda s: _unit(s))
def test_genuine_site_reports_exactly_one_row(scanned, site: Site) -> None:
    """One row on the site's line: an arm never duplicates the base rule or another arm."""
    root, findings = scanned
    rel = Path(site.rel)
    same = [f for f in _rows(findings)
            if int(f.get("line_start") or 0) == site.line and Path(f["file_path"]).relative_to(root) == rel]
    assert len(same) == 1, same


@pytest.mark.parametrize("pair", TWINS, ids=lambda p: f"{p[0]}~{p[1]}")
def test_allman_and_kr_twins_decide_alike(scanned, pair: tuple[str, str]) -> None:
    root, findings = scanned
    got = verdicts(_rows(findings), SITES, CWE209, root)
    by_unit = {_arm(_unit(s)): got[s] for s in SITES}
    assert by_unit[pair[0]] == by_unit[pair[1]], (pair, by_unit[pair[0]], by_unit[pair[1]])
