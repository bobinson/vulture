"""Cross-agent integration test: the OWASP mapper verified against real code.

The OWASP agent performs NO detection — it maps CWE findings onto OWASP Top 10
categories. So the faithful "does OWASP work against this code" test runs the
FULL pipeline: the CWE agent's deterministic skills detect on a committed
vulnerable fixture, and the real findings are fed to the OWASP mapper. The
fixture is engineered so the mapped categories span the ENTIRE Top 10 for BOTH
editions — this test asserts full 2021 AND 2025 coverage end to end (feature 0063).

Skips cleanly when cwe_agent isn't importable (a local owasp-only
PYTHONPATH=../shared run). CI installs every agent (`pip install -e cwe/`) and
runs `pytest owasp/tests/`, so it executes there.
"""

import json
import pathlib
import shutil

import pytest

# The CWE agent is this test's detection engine. Guard BEFORE importing it so a
# local owasp-only run SKIPS at collection instead of erroring.
cwe_skills = pytest.importorskip(
    "cwe_agent.skills",
    reason="cwe_agent not installed (local owasp-only run); present in CI via pip install -e cwe/",
)

from owasp_agent.agent import run_audit  # noqa: E402 -- must follow the importorskip guard

FIXTURE_DIR = (
    pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_flask_app"
)
FIXTURE_APP = FIXTURE_DIR / "app.py"

# CWEs the fixture deliberately plants (each a distinct class) — the precise,
# stable signal. The CWE agent also emits incidental Flask-shape CWEs (missing
# auth, CSRF, IDOR, ...); those are NOT asserted individually because they may
# drift as skills evolve.
PLANTED_CWES = {78, 89, 328, 502, 532, 611, 755, 798, 918, 937, 1104}

# The fixture is engineered so the planted + incidental CWEs together cover ALL
# ten OWASP categories in BOTH editions. A failure of the coverage assertion
# names the missing category — which is exactly the end-to-end signal we want:
# it means the pipeline no longer demonstrates full Top 10 coverage.
ALL_TEN = {f"A{n:02d}" for n in range(1, 11)}


def _events(gen):
    """Parse run_audit's SSE chunk generator into (event_type, data) tuples."""
    out = []
    for chunk in gen:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _detect_cwe_findings(scan_dir: str) -> list[dict]:
    """Run every CWE skill over scan_dir; return merged findings (real detection)."""
    findings: list[dict] = []
    for fn in cwe_skills.SKILL_MAP.values():
        findings.extend((fn(scan_dir) or {}).get("findings", []))
    return findings


def _detected_cwe_ids(findings: list[dict]) -> set[int]:
    return {
        int(f["category"].split("-")[1])
        for f in findings
        if str(f.get("category", "")).startswith("CWE-")
    }


@pytest.fixture
def scan_root(tmp_path):
    """Copy the whole committed fixture dir into a neutral temp dir before scanning.

    The committed path lives under tests/fixtures/, which the CWE scanner skips
    (SKIP_DIRS 'fixtures' + _TEST_DIRS 'tests'); scanning a temp copy avoids that.
    The whole directory (app.py + requirements.txt) is copied so the dependency
    skill sees the manifest (CWE-937/1104 -> A06 / A03).
    """
    d = tmp_path / "scanroot"
    shutil.copytree(FIXTURE_DIR, d)
    return str(d)


def test_fixture_present():
    assert FIXTURE_APP.is_file(), f"vulnerable fixture missing at {FIXTURE_APP}"
    assert (FIXTURE_DIR / "requirements.txt").is_file(), "fixture requirements.txt missing"


def test_cwe_detection_produces_pipeline_input(scan_root):
    """Pipeline sanity: the known-vulnerable fixture must yield its planted CWEs.

    A failure here means CWE DETECTION regressed (the mapper's input is missing)
    — distinct from an OWASP mapping failure asserted below.
    """
    detected = _detected_cwe_ids(_detect_cwe_findings(scan_root))
    assert detected, "CWE skills produced no findings on the vulnerable fixture"
    missing = PLANTED_CWES - detected
    assert not missing, f"CWE detection regressed; planted CWEs not detected: {sorted(missing)}"


@pytest.mark.parametrize("edition", ["2021", "2025"])
def test_owasp_maps_real_cwe_findings_to_full_top10(scan_root, edition):
    priors = _detect_cwe_findings(scan_root)
    events = _events(run_audit("e2e-pipeline", "/unused", {"edition": edition}, prior_findings=priors))

    findings = [d for t, d in events if t == "finding"]
    result = next(d for t, d in events if t == "result")
    end = next(d for t, d in events if t == "agent_end")

    # Every OWASP finding is category-labeled, sourced from a CWE, and snippet-free.
    assert findings, "OWASP mapper emitted no findings from real CWE input"
    assert all(f["category"].startswith("A") for f in findings)
    assert all(f["mapped_from"].startswith("CWE-") for f in findings)
    assert all(not f.get("code_snippet") for f in findings), "snippets must not leak into OWASP findings"

    # END-TO-END COVERAGE: the fixture lights up all ten categories this edition,
    # in the findings AND in the coverage manifest.
    found_ids = {f["owasp_category_id"] for f in findings}
    cov = result["owasp_coverage"]
    manifest_found = {c["id"] for c in cov["categories"] if c["found_count"] > 0}
    assert found_ids == ALL_TEN, f"{edition}: findings do not cover all 10; missing {sorted(ALL_TEN - found_ids)}"
    assert manifest_found == ALL_TEN, f"{edition}: manifest not fully covered; missing {sorted(ALL_TEN - manifest_found)}"

    # Coverage manifest complete + provenance correct.
    assert cov["edition"] == edition
    assert len(cov["categories"]) == 10
    assert cov["cwe_stage_status"] == "completed"  # non-empty priors -> completed
    assert end["status"] == "completed"
