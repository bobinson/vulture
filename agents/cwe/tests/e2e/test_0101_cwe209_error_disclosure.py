"""Feature 0101 -- CWE-209 decides on the VALUE that reaches a peer write (LLD 5.3).

Business contract
-----------------
CWE-209 is "an error's message, stack, string form or raw object reaches the
peer". The shipped rule decided on a NAME: any identifier starting
err/error/ex/exception inside a `.send/.json/.end/.write(` call. Measured on one
real target that was 8.3% precise (7 true of 84 adjudicated): a catalogue helper
whose own name starts with "error" returning a fixed entry was the dominant
false class, followed by code/enum fields (`{ error: err.code }`).

The fixtures under ``fixtures/0101_cwe209`` are synthetic (every identifier is
invented) and carry one asserted site each, as an ``EXPECT-NEXT:`` marker on its
own line above the site:

* ``pos/``    -- a genuine disclosure: exactly one CWE-209 row, no CWE-550 row.
* ``pos550/`` -- the CWE-550 shapes: CWE-550 replaces the 209 row on the line.
* ``neg/``    -- nothing leaks (non-peer sinks, projections, conditions, lookups,
  literals): no CWE-209 row. ``n15`` is a CWE-550 line and asserts that row.
* ``gap/``    -- non-goals and known gaps (LLD NG1/NG4/NG8, 8.3), pinned to the
  observed verdict with a ``known-gap`` note, so a change in either direction
  is seen instead of drifting silently.

Every RED probe site with a verdict is ported here. The rule skips test paths,
so the tree is scanned through ``neutral_copy`` and a population floor guards
against a run that scans nothing.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree, verdicts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "0101_cwe209"
CWE209 = "CWE-209"
CWE550 = "CWE-550"
CHECK_550 = "cwe.info_exposure.server_error_message"
MODULE_PATH = "agents/cwe/cwe_agent/skills/info_exposure_check.py"
REPO_ROOT = Path(__file__).resolve().parents[4]

SITES: list[Site] = parse_tree(FIXTURES)


def _category(site: Site) -> str:
    return CWE550 if site.check == CHECK_550 else CWE209


def _scan(module, tmp_path_factory, label: str, subdir: str = "") -> tuple[Path, list[dict]]:
    root = neutral_copy(FIXTURES / subdir if subdir else FIXTURES, tmp_path_factory.mktemp(label))
    return root, module.check_information_exposure(str(root))["findings"]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe209"))
    return root, check_information_exposure(str(root))["findings"]


def _rel(finding: dict, root: Path) -> str:
    path = Path(str(finding.get("file_path", "")))
    return path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()


def _rows(findings: list[dict], root: Path, rel: str, category: str) -> list[dict]:
    return [f for f in findings if f.get("category") == category and _rel(f, root) == rel]


def _genuine_sites() -> list[Site]:
    return [s for s in SITES if s.rel.startswith("pos/")]


def _clean_sites() -> list[Site]:
    return [s for s in SITES if s.rel.startswith("neg/") and s.verdict == "clean"]


def _category_rows(findings: list[dict], category: str) -> list[dict]:
    return [f for f in findings if f.get("category") == category]


def test_population_floor(scanned) -> None:
    """At least 50 genuine sites, 35 clean sites, and 50 rows actually emitted."""
    root, findings = scanned
    pos = _genuine_sites()
    neg = _clean_sites()
    assert len(pos) >= 50 and len(neg) >= 35, (len(pos), len(neg))
    rows = _category_rows(findings, CWE209)
    assert_population(SITES, rows, min_finding=50, min_clean=35, min_emitted=50)


def test_one_asserted_site_per_file() -> None:
    per_file = Counter(s.rel for s in SITES)
    assert per_file and max(per_file.values()) == 1, [r for r, n in per_file.items() if n > 1]


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{s.rel}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, findings = scanned
    got = verdicts(findings, [site], _category(site), root)[site]
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("site", [s for s in SITES if s.rel.startswith("pos/")],
                         ids=lambda s: s.rel)
def test_genuine_file_reports_exactly_one_209_row(scanned, site: Site) -> None:
    root, findings = scanned
    assert len(_rows(findings, root, site.rel, CWE209)) == 1
    assert not _rows(findings, root, site.rel, CWE550)


@pytest.mark.parametrize("site", [s for s in SITES if s.check == CHECK_550], ids=lambda s: s.rel)
def test_550_line_carries_no_209_row(scanned, site: Site) -> None:
    """CWE-550 runs first and REPLACES the 209 row on its line (P5)."""
    root, findings = scanned
    lines_209 = {f["line_start"] for f in _rows(findings, root, site.rel, CWE209)}
    assert site.line not in lines_209


# --------------------------------------------------------------------------
# The shipped-reported genuine gate (plan, every track): every genuine site the
# SHIPPED rule reports must still be reported. A precision change that silently
# drops a true positive the old rule caught is a regression, whatever it buys.
# --------------------------------------------------------------------------

# The pre-0101 commit, fixed: a revision computed from the branch (its merge base,
# or HEAD) loads the NEW rule once 0101 is merged, and the gate would then compare
# the rule with itself and pass vacuously. The 778 and 770 gates pin the same one.
SHIPPED_BASE = "071cde8096274841786947043a79d961852233b8"


def _shipped_source() -> str:
    out = subprocess.run(["git", "-C", str(REPO_ROOT), "show", f"{SHIPPED_BASE}:{MODULE_PATH}"],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout:
        pytest.skip(f"pre-0101 commit {SHIPPED_BASE[:8]} is not readable here: {out.stderr.strip()[:120]}")
    return out.stdout


def _shipped_module(tmp_path: Path):
    src = _shipped_source()
    path = tmp_path / "shipped_info_exposure_check.py"
    path.write_text(src)
    spec = importlib.util.spec_from_file_location("_0101_shipped_info_exposure_check", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _reported_sites(findings: list[dict], sites: list[Site], root: Path) -> list[Site]:
    """The ``sites`` a scan reports as a CWE-209 finding."""
    return [s for s, v in verdicts(findings, sites, CWE209, root).items() if v == "finding"]


def _unreported_sites(findings: list[dict], sites: list[Site], root: Path) -> list[str]:
    """`rel:line` of every one of ``sites`` the scan does NOT report as a CWE-209 finding."""
    now = verdicts(findings, sites, CWE209, root)
    return [f"{s.rel}:{s.line}" for s, v in now.items() if v != "finding"]


def test_every_genuine_site_the_shipped_rule_reports_is_still_reported(scanned, tmp_path, tmp_path_factory) -> None:
    root, findings = scanned
    genuine = _genuine_sites()
    shipped_root, shipped = _scan(_shipped_module(tmp_path), tmp_path_factory, "cwe209_shipped")
    shipped_hits = _reported_sites(shipped, genuine, shipped_root)
    lost = _unreported_sites(findings, shipped_hits, root)
    assert shipped_hits, "the shipped rule reported no genuine site: the gate is vacuous"
    assert not lost, f"genuine sites the shipped rule reported and the new rule drops: {lost}"
