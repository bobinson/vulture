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
from src.translate import translate_findings

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
