"""Feature 0101 revision 3, implementation review round 1 -- CWE-209 arm corrections.

Business contract
-----------------
* H (a same-file helper that writes its parameter to the peer) recognises the
  writes a helper actually makes: a Go helper's parameter list (`w
  http.ResponseWriter, msg string`, name before type), a write that takes the
  peer WRITER as its first argument (`http.Error(w, msg, ...)`,
  `fmt.Fprint(w, msg)`, `io.WriteString(w, msg)`), an encoder built over the
  peer writer (`json.NewEncoder(w).Encode(...)`), and a parameter converted
  on its way out (`[]byte(msg)`, `msg.encode()`). A helper that only logs the
  parameter, writes a literal, or encodes into a local buffer stays clean.
* F3 (positional construction) reads a constructor whose parameters are
  declared as members (TypeScript parameter properties, PHP promoted
  constructor parameters) as the type's ordered members.
* F2 (a file-wide `.F = <error>` fill) does not override the producer: when the
  read's root is bound from a same-file routine whose every fill of F, and
  every value it returns, is literal or a code constant, that routine decides
  and the read is clean. A producer that fills F from anything else keeps F2.
* C1 (a bare response helper judged by its name) counts `err` as a
  response-shape word (`writeErr(res, ...)`, `sendErr(res, ...)`); the peer
  first argument is still required.
* The leaks no arm reaches are pinned to their observed verdict under
  ``gap/``: K11, K12 and the review's new K15-K18 classes (stored then served,
  an outbound agent event stream, a proof evidence string, a collection
  returned to a streaming caller), and the NG builder / keyword / tuple
  response shapes that predate revision 3. A change either way is seen.

Each unit is scanned on its own from a neutral copy (the rule skips test paths).
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree, verdicts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "0101r3_cwe209"
CWE209 = "CWE-209"
KINDS = ("pos", "neg", "gap")
SITES: list[Site] = parse_tree(FIXTURES)

# (pos floor, neg floor) per unit prefix
FLOORS = {"h_go_": (5, 3), "h_py_": (2, 1), "f3_": (2, 2), "f2_": (1, 3), "c1_": (2, 2)}
# the known-limit classes that must stay pinned (a deleted pin fails here)
GAP_PREFIXES = ("k11_", "k12_", "k15_", "k16_", "k17_", "k18_", "ng_")


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe209r3review1"))
    findings: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            findings += check_information_exposure(str(unit))["findings"]
    return root, findings


def _rows(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("category") == CWE209]


def test_population(scanned) -> None:
    _, findings = scanned
    assert all(s.verdict == "finding" for s in SITES if s.rel.startswith("pos/"))
    assert all(s.verdict == "clean" for s in SITES if s.rel.startswith("neg/"))
    assert_population(SITES, _rows(findings), min_finding=12, min_clean=23, min_emitted=12)


@pytest.mark.parametrize("prefix", sorted(FLOORS))
def test_floors(prefix: str) -> None:
    pos = sum(1 for s in SITES if _unit(s).startswith(f"pos/{prefix}"))
    neg = sum(1 for s in SITES if _unit(s).startswith(f"neg/{prefix}"))
    assert pos >= FLOORS[prefix][0] and neg >= FLOORS[prefix][1], (prefix, pos, neg)


@pytest.mark.parametrize("prefix", GAP_PREFIXES)
def test_known_limit_classes_stay_pinned(prefix: str) -> None:
    assert any(_unit(s).startswith(f"gap/{prefix}") for s in SITES), prefix


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
    root, findings = scanned
    rel = Path(site.rel)
    same = [f for f in _rows(findings)
            if int(f.get("line_start") or 0) == site.line and Path(f["file_path"]).relative_to(root) == rel]
    assert len(same) == 1, same
