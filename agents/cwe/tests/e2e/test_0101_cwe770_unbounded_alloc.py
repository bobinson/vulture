"""Feature 0101 -- CWE-770 business contract: input-driven, uncapped accumulation.

WHAT THE RULE MEANS
    CWE-770 is a collection or buffer that GROWS inside repetition the process
    does not control (a stream, socket, queue, request body, child-process
    output or an input-event callback) with NO CAP on that growth. The pre-0101
    rule reported any Python ``.append`` with a loop above it; measured on one
    real tree, 233 of 270 rows were appends inside ``for x in <finite in-memory
    collection>``, which cannot outgrow the collection.

THE FIXTURES (``fixtures/0101_cwe770``)
    Every RED probe site with a verdict is ported with synthetic names, one
    ``EXPECT-NEXT:`` marker on its own line above each site (a trailing marker
    would change the shipped rule's own verdict, R770-12). Sites that are
    non-goals (NG7) or known gaps (LLD 5.2.6) are pinned to the OBSERVED verdict
    with a ``known-gap:`` note, so a later change in either direction is seen.

    ``r0/alloc_make.go`` mirrors the protected Go ``make([]T, 0)`` arm (NG2).

WHY A NEUTRAL COPY
    The rule skips test paths, so scanning the fixtures in place yields nothing
    and every ``clean`` expectation would pass vacuously (RC-09).
"""
from __future__ import annotations

import importlib.util
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from cwe_agent.skills.resource_check import check_resource_management
from tests.e2e._0101_markers import (
    assert_population,
    mismatches,
    neutral_copy,
    parse_tree,
)

FIXTURES = Path(__file__).parent / "fixtures" / "0101_cwe770"
CATEGORY = "CWE-770"
CHECK_ID = "cwe.resource.unbounded_alloc"
# The pre-0101 rule, for the shipped-reported-genuine gate (RC-01, RC-02).
BASE_COMMIT = "071cde8096274841786947043a79d961852233b8"
SHIPPED_PATH = "agents/cwe/cwe_agent/skills/resource_check.py"

MIN_FINDING_SITES = 45
MIN_CLEAN_SITES = 35
MIN_EMITTED = 45
# LLD 13: genuine fixtures report in each of these languages.
GENUINE_LANGUAGES = (".py", ".go", ".ts", ".java", ".rs", ".cs", ".rb", ".php")


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, list, list[dict]]:
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe770"))
    sites = parse_tree(root)
    findings = [f for f in check_resource_management(str(root))["findings"]
                if f["category"] == CATEGORY]
    return root, sites, findings


def _rel(finding: dict, root: Path) -> str:
    return Path(finding["file_path"]).relative_to(root).as_posix()


def _finding_sites(sites: list) -> set[tuple[str, int]]:
    return {(s.rel, s.line) for s in sites if s.verdict == "finding"}


def test_population_floor(corpus) -> None:
    _, sites, findings = corpus
    assert_population(sites, findings, MIN_FINDING_SITES, MIN_CLEAN_SITES, MIN_EMITTED)


def test_every_site_holds_its_verdict(corpus) -> None:
    root, sites, findings = corpus
    bad = mismatches(findings, sites, CATEGORY, root)
    assert not bad, "\n".join(f"{s.rel}:{s.line} expected {want}, got {got}"
                              for s, want, got in bad)


def test_rows_equal_the_finding_sites_exactly(corpus) -> None:
    """No unmarked row: every emitted (file, line) is a declared finding site."""
    root, sites, findings = corpus
    emitted = {(_rel(f, root), f["line_start"]) for f in findings}
    assert emitted == _finding_sites(sites), {
        "unmarked rows": sorted(emitted - _finding_sites(sites)),
        "missing rows": sorted(_finding_sites(sites) - emitted),
    }


def _shape(finding: dict) -> tuple:
    return (finding["check_id"], finding["severity"], finding["line_start"] == finding["line_end"],
            finding.get("cwe_name"))


def test_row_shape_is_unchanged(corpus) -> None:
    """G5: check_id, category, severity and the enriched CWE name stay as shipped."""
    _, _, findings = corpus
    assert set(map(_shape, findings)) == {
        (CHECK_ID, "medium", True, "Allocation of Resources Without Limits or Throttling"),
    }


def _genuine_reported(root: Path, sites: list, findings: list[dict]) -> set[tuple[str, int]]:
    """Finding sites that are reported and are not known-gap pins."""
    reported = {(_rel(f, root), f["line_start"]) for f in findings} & _finding_sites(sites)
    return {key for key in reported if "known-gap" not in _marker_text(root, *key)}


def test_genuine_sites_report_in_every_tuning_language(corpus) -> None:
    root, sites, findings = corpus
    per_language = Counter(Path(rel).suffix for rel, _ in _genuine_reported(root, sites, findings))
    missing = sorted(set(GENUINE_LANGUAGES) - set(per_language))
    assert not missing, f"no genuine CWE-770 row in {missing}; per language: {dict(per_language)}"


def test_protected_go_make_arm_still_reports(corpus) -> None:
    root, _, findings = corpus
    assert any(_rel(f, root) == "r0/alloc_make.go" for f in findings)


def test_no_known_gap_is_silently_resolved(corpus) -> None:
    """Every known-gap pin exists and holds (a fix must update the pin AND SKILLS.md)."""
    root, sites, findings = corpus
    gaps = _known_gap_sites(root, sites)
    assert len(gaps) >= 20, f"expected the NG7 / LLD 5.2.6 pins, found {len(gaps)}"
    assert not mismatches(findings, gaps, CATEGORY, root)


def _known_gap_sites(root: Path, sites: list) -> list:
    return [s for s in sites if "known-gap" in _marker_text(root, s.rel, s.line)]


def _marker_text(root: Path, rel: str, line: int) -> str:
    return (root / rel).read_text(encoding="utf-8").split("\n")[line - 2]


def _shipped_check():
    """The pre-0101 module, loaded from git; skips where the history is absent."""
    try:
        src = subprocess.run(
            ["git", "-C", str(FIXTURES), "show", f"{BASE_COMMIT}:{SHIPPED_PATH}"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip(f"base commit {BASE_COMMIT[:8]} not available: {exc}")
    return src


def _rows(findings: list[dict], root: Path) -> set[tuple[str, int]]:
    return {(_rel(f, root), f["line_start"]) for f in findings if f["category"] == CATEGORY}


def _shipped_module(tmp_path: Path):
    module_path = tmp_path / "shipped_resource_check.py"
    module_path.write_text(_shipped_check(), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("shipped_resource_check_0101", module_path)
    shipped = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shipped)
    return shipped


def test_every_genuine_site_the_shipped_rule_reported_is_still_reported(corpus, tmp_path) -> None:
    root, sites, findings = corpus
    old = _rows(_shipped_module(tmp_path).check_resource_management(str(root))["findings"], root)
    new = _rows(findings, root)
    genuine_old = old & _finding_sites(sites)
    assert genuine_old, "the shipped rule reported no genuine site: the gate is vacuous"
    assert genuine_old <= new, sorted(genuine_old - new)
