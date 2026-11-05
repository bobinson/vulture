"""CWE-209: a response helper is judged by its definition when the scanned tree holds exactly one.

Business contract
-----------------
A bare call whose NAME reads like a response helper (`writeInternalError(w, r, op,
err)`, `sendError(res, err)`) was reported whenever an error reached one of its
arguments, because a helper defined in another file was judged by its name alone.
A helper that logs the error and answers a fixed message -- the remediation CWE-209
asks for -- was therefore reported at every call, and a codebase that adopted it
saw no change.

* The helper's ONLY definition in the scanned tree decides, as a same-file
  definition already did: the call is reported when an argument that carries the
  error lands on a parameter the definition writes to the peer.
* Inside a helper, a call to another routine defined in the same file writes only
  the arguments that routine's own definition writes (`writeLoggedError(w, r, 500,
  "internal error", op, err)` writes the literal, not `err`).
* Where the definition cannot be matched to the call, the name still decides: no
  definition, several, keyword arguments, more arguments than parameters, or a
  member call (`http.Error(w, ...)`) inside the helper.

Fixture layout (`fixtures/cwe209_helper_definition`): one asserted site per unit,
under ``pos/`` (reported) or ``neg/`` (clean). Each unit is scanned on its own from
a neutral copy, so a cross-file definition is exactly the files of its unit.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree, verdicts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cwe209_helper_definition"
CWE209 = "CWE-209"
KINDS = ("pos", "neg")
SITES: list[Site] = parse_tree(FIXTURES)


def _unit(site: Site) -> str:
    """`neg/go_logged_internal_error_crossfile/handler.go` -> `neg/go_logged_internal_error_crossfile`."""
    return "/".join(site.rel.split("/")[:2])


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    """Every unit scanned on its own, from one neutral copy; the CWE-209 rows together."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe209helper"))
    findings: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            findings += check_information_exposure(str(unit))["findings"]
    return root, [f for f in findings if f.get("category") == CWE209]


def test_population() -> None:
    """One asserted site per unit; every pos unit expects a row, every neg unit none."""
    per_unit = Counter(_unit(s) for s in SITES)
    units = {f"{k}/{p.name}" for k in KINDS for p in (FIXTURES / k).iterdir() if p.is_dir()}
    assert units == set(per_unit) and max(per_unit.values()) == 1, per_unit
    assert all(s.verdict == "finding" for s in SITES if s.rel.startswith("pos/"))
    assert all(s.verdict == "clean" for s in SITES if s.rel.startswith("neg/"))


def test_rows_are_emitted(scanned) -> None:
    """The scan reports something, so a clean verdict cannot pass vacuously."""
    _, rows = scanned
    assert_population(SITES, rows, min_finding=10, min_clean=6, min_emitted=10)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, rows = scanned
    got = verdicts(rows, [site], CWE209, root)[site]
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("site", [s for s in SITES if s.rel.startswith("pos/")], ids=_unit)
def test_reported_site_has_exactly_one_row(scanned, site: Site) -> None:
    """A call judged after the walk (its definition was not yet indexed) is reported once."""
    root, rows = scanned
    same = [f for f in rows
            if int(f.get("line_start") or 0) == site.line and Path(f["file_path"]).relative_to(root) == Path(site.rel)]
    assert len(same) == 1, same
