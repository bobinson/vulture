"""Feature 0058 P2g — composite scam-risk score (plugin post-process).

`summarize_scam_risk` groups translated findings by file, counts DISTINCT
owner-omnipotence / drainer markers, and emits one synthetic high-severity
finding per file that crosses the threshold. Pure Python — no semgrep needed,
so these are fast unit tests over hand-built finding dicts.
"""

from __future__ import annotations

from src.translate import SCAM_SCORE_MIN_MARKERS, summarize_scam_risk


def _f(check_id: str, file_path: str = "C.sol", line: int = 1) -> dict:
    return {"check_id": check_id, "file_path": file_path, "line_start": line}


def test_composite_fires_at_threshold():
    findings = [
        # namespaced check_id (as a --config-dir scan emits) must still match
        _f("rules.vulture.solidity.vulture-solidity-honeypot-transfer-gate", line=10),
        _f("vulture-solidity-uncapped-fee-setter", line=5),
        _f("vulture-solidity-owner-direct-balance-write", line=20),
    ]
    out = summarize_scam_risk(findings, agent_type="semgrep")
    assert len(out) == 1
    c = out[0]
    assert c["check_id"] == "vulture-solidity-composite-scam-risk"
    assert c["severity"] == "high"
    assert c["cwe"] == "CWE-284"
    assert c["provenance"] == "semgrep"
    assert c["agent_type"] == "semgrep"
    assert c["file_path"] == "C.sol"
    assert c["line_start"] == 5  # earliest marker line


def test_below_threshold_no_composite():
    findings = [
        _f("vulture-solidity-uncapped-fee-setter"),
        _f("vulture-solidity-owner-direct-balance-write"),
    ]
    assert SCAM_SCORE_MIN_MARKERS == 3
    assert summarize_scam_risk(findings, agent_type="semgrep") == []


def test_duplicate_marker_counts_once():
    findings = [
        _f("vulture-solidity-uncapped-fee-setter", line=1),
        _f("vulture-solidity-uncapped-fee-setter", line=2),
        _f("vulture-solidity-owner-direct-balance-write", line=3),
    ]  # only 2 DISTINCT markers -> below threshold
    assert summarize_scam_risk(findings, agent_type="semgrep") == []


def test_non_marker_findings_ignored():
    findings = [
        _f("vulture-solidity-tx-origin-auth"),
        _f("vulture-solidity-delegatecall-untrusted"),
        _f("vulture-solidity-uncapped-fee-setter"),
    ]  # only 1 scam marker -> no composite
    assert summarize_scam_risk(findings, agent_type="semgrep") == []


def test_composite_is_per_file():
    findings = [
        _f("vulture-solidity-honeypot-transfer-gate", file_path="A.sol"),
        _f("vulture-solidity-uncapped-fee-setter", file_path="A.sol"),
        _f("vulture-solidity-owner-direct-balance-write", file_path="A.sol"),
        _f("vulture-solidity-honeypot-transfer-gate", file_path="B.sol"),
    ]
    out = summarize_scam_risk(findings, agent_type="semgrep")
    assert len(out) == 1
    assert out[0]["file_path"] == "A.sol"
