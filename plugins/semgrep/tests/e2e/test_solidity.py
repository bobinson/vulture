"""Feature 0058 — Solidity coverage via the semgrep plugin.

Two tiers, both wired through the existing plugin (no new agent):
  * vendored, pinned, HERMETIC Solidity rules (rules/vulture/solidity/) —
    always applied to .sol via the vendored --config dir, no network.
  * r/solidity — the Semgrep REGISTRY Solidity namespace (~50 rules), an
    OPERATOR default (not client-injectable), best-effort breadth, egress
    required, disableable via VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import src.wrapper as wrapper
from src.translate import summarize_scam_risk, translate_findings

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SOL_FIXTURE_DIR = PLUGIN_ROOT / "tests" / "fixtures" / "solidity"


def _pairs(argv):
    return list(zip(argv, argv[1:]))


# --- r/solidity registry wiring (operator default, default set only) ---

def test_solidity_registry_in_default_argv(monkeypatch):
    monkeypatch.delenv("VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY", raising=False)
    argv = wrapper._semgrep_argv("/audit-inputs/x", {})
    assert ("--config", "r/solidity") in _pairs(argv)


def test_solidity_registry_absent_when_rule_packs_pinned(monkeypatch):
    monkeypatch.delenv("VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY", raising=False)
    argv = wrapper._semgrep_argv("/audit-inputs/x", {"rule_packs": ["p/security-audit"]})
    assert "r/solidity" not in argv


def test_solidity_registry_disable_escape_hatch(monkeypatch):
    monkeypatch.setenv("VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY", "true")
    argv = wrapper._semgrep_argv("/audit-inputs/x", {})
    assert "r/solidity" not in argv


# --- vendored Solidity rules ship + are pinned ---

def test_vendored_solidity_rules_shipped():
    d = Path(os.fspath(wrapper.VENDORED_RULES_DIR)) / "solidity"
    assert d.is_dir() and any(d.glob("*.yaml")), (
        "vendored Solidity rules must ship under rules/vulture/solidity/ (P2d)"
    )


# --- hermetic detection: vendored rules fire on a .sol vuln, correct CWE ---

@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_vendored_solidity_rules_detect_on_fixture():
    # Vendored dir only (no registry) → hermetic, no network. --project-root
    # so semgrep's built-in .semgrepignore (default `tests/`) doesn't skip the
    # tests/-nested fixture (matches the real argv on this semgrep version).
    argv = [
        "semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
        "--project-root", str(SOL_FIXTURE_DIR),
        "--config", os.fspath(wrapper.VENDORED_RULES_DIR),
        "--", str(SOL_FIXTURE_DIR),
    ]
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=300,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
    )
    assert proc.returncode in (0, 1), f"semgrep rc={proc.returncode}: {proc.stderr[:1000]}"
    findings = translate_findings(json.loads(proc.stdout), agent_type="semgrep", root=str(SOL_FIXTURE_DIR))
    cwes = {f.get("cwe") for f in findings}
    # tx.origin auth + selfdestruct (CWE-284) and delegatecall (CWE-829).
    assert "CWE-284" in cwes and "CWE-829" in cwes, (
        f"vendored Solidity rules must flag the .sol fixture; got cwes={sorted(cwes)} "
        f"checks={[f.get('check_id') for f in findings]}"
    )


# --- scam-contract rules (P2e): positives fire, the legit fixture stays clean ---

def _scan_vendored_findings(target_dir):
    """Run the hermetic vendored-only Solidity scan; return translated findings."""
    argv = [
        "semgrep", "scan", "--json", "--quiet", "--no-git-ignore",
        "--project-root", str(target_dir),
        "--config", os.fspath(wrapper.VENDORED_RULES_DIR),
        "--", str(target_dir),
    ]
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=300,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
    )
    assert proc.returncode in (0, 1), f"semgrep rc={proc.returncode}: {proc.stderr[:1000]}"
    return translate_findings(json.loads(proc.stdout), agent_type="semgrep", root=str(target_dir))


def _scan_vendored(target_dir):
    """Index the vendored scan by fixture basename -> (check_ids, cwes)."""
    findings = _scan_vendored_findings(target_dir)
    checks, cwes = {}, {}
    for f in findings:
        base = os.path.basename(f.get("file_path") or "")
        # semgrep namespaces --config-dir rules as `rules.vulture.solidity.<id>`;
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


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
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


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_rug_marker_rules_fire_on_positive_fixtures():
    checks, cwes = _scan_vendored(SOL_FIXTURE_DIR)

    # Uncapped owner fee/tax setter + direct owner balance overwrite -> CWE-284.
    rug = checks.get("RugToken.sol", set())
    assert "vulture-solidity-uncapped-fee-setter" in rug
    assert "vulture-solidity-owner-direct-balance-write" in rug
    assert "CWE-284" in cwes.get("RugToken.sol", set())


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_scam_rules_silent_on_legit_fixture():
    checks, _ = _scan_vendored(SOL_FIXTURE_DIR)
    tripped = checks.get("Legit.sol", set()) & SCAM_RULE_IDS
    assert not tripped, f"legit fixture tripped scam rules (false positive): {sorted(tripped)}"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep binary not installed")
def test_composite_scam_risk_on_stacked_fixture():
    """End-to-end: real scan -> translate -> post-process. The contract stacking
    >= 3 markers gets a composite; the 2-marker and 0-marker fixtures do not."""
    findings = _scan_vendored_findings(SOL_FIXTURE_DIR)
    composites = summarize_scam_risk(findings, agent_type="semgrep")
    by_file = {os.path.basename(c["file_path"]): c for c in composites}

    assert "ScamToken.sol" in by_file, "4-marker contract must raise a composite"
    c = by_file["ScamToken.sol"]
    assert c["check_id"] == "vulture-solidity-composite-scam-risk"
    assert c["severity"] == "high"

    # RugToken.sol has only 2 markers -> below threshold; Legit.sol has none.
    assert "RugToken.sol" not in by_file
    assert "Legit.sol" not in by_file
