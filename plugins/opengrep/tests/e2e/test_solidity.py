"""Feature 0058 — Solidity coverage via the opengrep plugin.

Vendored, pinned, HERMETIC Solidity rules (rules/vulture/solidity/), applied
to .sol through the bundled `vulture` rule set, no network. Feature 0102
removed the Semgrep Registry `r/solidity` tier: its rules may not be used.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from src import wrapper
from src.translate import summarize_scam_risk, translate_findings

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SOL_FIXTURE_DIR = PLUGIN_ROOT / "tests" / "fixtures" / "solidity"


def _pairs(argv):
    return list(zip(argv, argv[1:]))


# --- no Registry tier (0102) ---

def test_no_registry_solidity_config():
    argv = wrapper._engine_argv("/audit-inputs/x", {})
    configs = [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]
    assert "r/solidity" not in configs and not [c for c in configs if c.startswith(("p/", "r/"))]


# --- vendored Solidity rules ship + are pinned ---

def test_vendored_solidity_rules_shipped():
    d = wrapper.RULES_DIR / "vulture" / "solidity"
    assert d.is_dir() and any(d.glob("*.yaml")), (
        "vendored Solidity rules must ship under rules/vulture/solidity/ (P2d)"
    )


# --- hermetic detection: vendored rules fire on a .sol vuln, correct CWE ---

@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_vendored_solidity_rules_detect_on_fixture():
    # The vendored set only → hermetic, no network; the plugin's own argv.
    findings = _scan_vendored_findings(SOL_FIXTURE_DIR)
    cwes = {f.get("cwe") for f in findings}
    # tx.origin auth + selfdestruct (CWE-284) and delegatecall (CWE-829).
    assert "CWE-284" in cwes and "CWE-829" in cwes, (
        f"vendored Solidity rules must flag the .sol fixture; got cwes={sorted(cwes)} "
        f"checks={[f.get('check_id') for f in findings]}"
    )


# --- scam-contract rules (P2e): positives fire, the legit fixture stays clean ---

def _scan_vendored_findings(target_dir):
    """Run the hermetic vendored-only Solidity scan; return translated findings.
    The plugin excludes test paths, so it scans a copy outside tests/."""
    with tempfile.TemporaryDirectory() as tmp:
        target = shutil.copytree(target_dir, Path(tmp) / "src")
        argv = wrapper._engine_argv(str(target), {"rule_sets": ["vulture"]})
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=wrapper.RULES_DIR.parent)
        assert proc.returncode in (0, 1), f"opengrep rc={proc.returncode}: {proc.stderr[:1000]}"
        return translate_findings(json.loads(proc.stdout), agent_type="opengrep", root=str(target))


def _scan_vendored(target_dir):
    """Index the vendored scan by fixture basename -> (check_ids, cwes)."""
    findings = _scan_vendored_findings(target_dir)
    checks, cwes = {}, {}
    for f in findings:
        base = os.path.basename(f.get("file_path") or "")
        # the engine namespaces --config-dir rules as `rules.vulture.solidity.<id>`;
        # compare on the stable last segment (the bare rule id).
        checks.setdefault(base, set()).add((f.get("check_id") or "").split(".")[-1])
        cwes.setdefault(base, set()).add(f.get("cwe"))
    return checks, cwes


SCAM_RULE_IDS = frozenset({
    "vulture-solidity-unprotected-initializer",
    "vulture-solidity-arbitrary-from-nft-transfer",
    "vulture-solidity-set-approval-for-all-untrusted",
    "vulture-solidity-honeypot-transfer-gate",
    "vulture-solidity-uncapped-fee-setter",
    "vulture-solidity-owner-direct-balance-write",
})


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_scam_rules_fire_on_positive_fixtures():
    checks, cwes = _scan_vendored(SOL_FIXTURE_DIR)

    # Unprotected initializer -> CWE-665.
    assert "vulture-solidity-unprotected-initializer" in checks.get("Proxy.sol", set())
    assert "CWE-665" in cwes.get("Proxy.sol", set())

    # NFT arbitrary-from sweep + setApprovalForAll bait -> CWE-863.
    drainer = checks.get("DrainerNft.sol", set())
    assert "vulture-solidity-arbitrary-from-nft-transfer" in drainer
    assert "vulture-solidity-set-approval-for-all-untrusted" in drainer
    assert "CWE-863" in cwes.get("DrainerNft.sol", set())

    # Honeypot owner-gated transfer -> CWE-284.
    assert "vulture-solidity-honeypot-transfer-gate" in checks.get("Honeypot.sol", set())
    assert "CWE-284" in cwes.get("Honeypot.sol", set())


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_rug_marker_rules_fire_on_positive_fixtures():
    checks, cwes = _scan_vendored(SOL_FIXTURE_DIR)

    # Uncapped owner fee/tax setter + direct owner balance overwrite -> CWE-284.
    rug = checks.get("RugToken.sol", set())
    assert "vulture-solidity-uncapped-fee-setter" in rug
    assert "vulture-solidity-owner-direct-balance-write" in rug
    assert "CWE-284" in cwes.get("RugToken.sol", set())


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_scam_rules_silent_on_legit_fixture():
    checks, _ = _scan_vendored(SOL_FIXTURE_DIR)
    tripped = checks.get("Legit.sol", set()) & SCAM_RULE_IDS
    assert not tripped, f"legit fixture tripped scam rules (false positive): {sorted(tripped)}"


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="opengrep binary not installed")
def test_composite_scam_risk_on_stacked_fixture():
    """End-to-end: real scan -> translate -> post-process. The contract stacking
    >= 3 markers gets a composite; the 2-marker and 0-marker fixtures do not."""
    findings = _scan_vendored_findings(SOL_FIXTURE_DIR)
    composites = summarize_scam_risk(findings, agent_type="opengrep")
    by_file = {os.path.basename(c["file_path"]): c for c in composites}

    assert "ScamToken.sol" in by_file, "4-marker contract must raise a composite"
    c = by_file["ScamToken.sol"]
    assert c["check_id"] == "vulture-solidity-composite-scam-risk"
    assert c["severity"] == "high"

    # RugToken.sol has only 2 markers -> below threshold; Legit.sol has none.
    assert "RugToken.sol" not in by_file
    assert "Legit.sol" not in by_file
