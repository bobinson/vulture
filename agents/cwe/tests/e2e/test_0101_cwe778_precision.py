"""Feature 0101 -- CWE-778 precision: business-logic contract (LLD 5.1).

CWE-778 is "a security-relevant event is not recorded". Before 0101 the rule
reported every handler that did not log, every line naming an auth outcome, and
every `.catch(() => <nothing>)`. The fixtures under ``fixtures/0101_cwe778/`` pin
the three concepts that separate the security event from the ordinary one:

  A  a handler that HANDS THE FAILURE ON (returns, stores where it is read later,
     collects, reports, forwards to a callback parameter) is excused only when the
     guarded operation is NOT security-relevant (``handoff.ts``, ``py_handoff.py``,
     ``security_gate.ts``, the tuning languages);
  B  a keyword that NAMES an outcome (catalog key, enum member, constant, case
     label, pattern branch) is not an authorization decision (``auth_catalog.*``);
  C  a promise swallow after a teardown call, or whose fallback is null-checked,
     is best effort, unless the chain head is a security operation (``promise.ts``).

Every site carries an ``EXPECT`` marker. The rule skips test paths, so the tree
is scanned through ``neutral_copy`` and a population floor guards against a run
that scans nothing (RC-09).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _0101_markers import (
    assert_population,
    mismatches,
    neutral_copy,
    parse_tree,
    verdicts,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "0101_cwe778"
CATEGORY = "CWE-778"
# The pre-0101 commit: the shipped rule every "finding" site is compared against.
SHIPPED_BASE = "071cde8096274841786947043a79d961852233b8"
SHIPPED_PATH = "agents/cwe/cwe_agent/skills/insufficient_logging_check.py"


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe778_0101"))
    sites = parse_tree(root)
    findings = [
        f for f in check_insufficient_logging(str(root))["findings"]
        if f.get("category") == CATEGORY
    ]
    return root, sites, findings


def test_population_floor(corpus):
    """At least 60 finding sites, 40 clean sites and 60 emitted rows (plan T-1)."""
    _root, sites, findings = corpus
    assert_population(sites, findings, min_finding=60, min_clean=40, min_emitted=60)


def _files_with_markers() -> list[str]:
    return sorted({s.rel for s in parse_tree(FIXTURES)})


@pytest.mark.parametrize("rel", _files_with_markers())
def test_every_site_holds_its_verdict(corpus, rel):
    """Each marked site gets exactly its expected verdict, file by file."""
    root, sites, findings = corpus
    wrong = mismatches(findings, [s for s in sites if s.rel == rel], CATEGORY, root)
    assert not wrong, "\n".join(
        f"{s.rel}:{s.line} expected {want}, got {got}"
        f"{' (' + s.check + ')' if s.check else ''}" for s, want, got in wrong
    )


def _row(finding: dict, root: Path) -> tuple[str, int]:
    return Path(finding["file_path"]).relative_to(root).as_posix(), int(finding["line_start"])


def _stray_rows(findings: list[dict], sites, root: Path) -> list[tuple]:
    marked = {(s.rel, s.line) for s in sites}
    return sorted((*_row(f, root), f["check_id"]) for f in findings if _row(f, root) not in marked)


def test_no_unmarked_rows(corpus):
    """Every emitted row sits on a marked line: no silent new row in a fixture."""
    root, sites, findings = corpus
    stray = _stray_rows(findings, sites, root)
    assert not stray, f"rows on unmarked lines: {stray}"


def test_concepts_each_excuse_something(corpus):
    """Each concept removes rows: a clean site exists for every check the rule can excuse."""
    _root, sites, _findings = corpus
    clean_checks = {s.check for s in sites if s.verdict == "clean"}
    expected = {None, "cwe.insufficient_logging.auth_decision", "cwe.insufficient_logging.promise_swallow"}
    assert expected <= clean_checks, expected - clean_checks


def _shipped_module(tmp_path: Path):
    try:
        src = subprocess.run(
            ["git", "show", f"{SHIPPED_BASE}:{SHIPPED_PATH}"],
            cwd=FIXTURES, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # shallow clone / no git
        pytest.skip(f"shipped CWE-778 module not readable from git: {exc}")
    path = tmp_path / "shipped_insufficient_logging_check.py"
    path.write_text(src)
    spec = importlib.util.spec_from_file_location("_shipped_cwe778_0101", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _shipped_comparison(shipped, corpus) -> tuple[list, list]:
    """(MUST-REPORT sites the shipped rule reports, those of them the new rule drops)."""
    root, sites, findings = corpus
    must = list(filter(lambda s: s.verdict == "finding", sites))
    old = verdicts(shipped.check_insufficient_logging(str(root))["findings"], must, CATEGORY, root)
    shipped_reported = list(filter(lambda s: old[s] == "finding", must))
    new = verdicts(findings, shipped_reported, CATEGORY, root)
    return shipped_reported, list(filter(lambda s: new[s] != "finding", shipped_reported))


def test_shipped_reported_genuine_sites_are_kept(corpus, tmp_path):
    """RC-01/RC-02: every MUST-REPORT site the shipped rule reports is still reported."""
    root, sites, findings = corpus
    shipped_reported, lost = _shipped_comparison(_shipped_module(tmp_path), corpus)
    assert not lost, f"genuine sites the shipped rule reported are now dropped: {lost}"
    # And the shipped rule really did report the bulk of them (the check is not vacuous).
    assert len(shipped_reported) >= 60


def _kotlin_catalog_verdicts(root: Path) -> dict:
    sites = [s for s in parse_tree(root) if (s.rel, s.verdict) == ("auth_catalog.kt", "clean")]
    return verdicts(check_insufficient_logging(str(root))["findings"], sites, CATEGORY, root)


def test_concept_b_survives_auth_strip_off(tmp_path, monkeypatch):
    """C13: AUTH_STRIP=false restores raw-line matching only; Concept B still applies."""
    monkeypatch.setenv("VULTURE_CWE778_AUTH_STRIP", "false")
    got = _kotlin_catalog_verdicts(neutral_copy(FIXTURES, tmp_path))
    assert len(got) >= 4
    assert set(got.values()) == {"clean"}, got
