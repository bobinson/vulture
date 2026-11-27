"""L5 claim refutation — business-logic contract.

The judge answers two separate questions per finding:

  * ``exploitable`` — how likely the finding is exploitable as written;
  * ``claim_holds`` — whether the weakness the finding CLAIMS exists at all.

Low exploitability alone never dismisses a finding: a true but low-impact
finding (an unlogged authentication failure, an error-detail disclosure) scores
low and must stay reported. Only a refuted claim may move a finding to
``likely_fp`` on its own — deterministic findings included — and only when the
refutation is admissible:

  * ``claim_holds`` is literally ``false`` and ``exploitable`` is below 0.5;
  * ``window_sufficient`` is literally ``true`` (the code shown decides it);
  * ``evidence_line`` cites a real line of the finding's own file;
  * the class is not a policy class (a hardcoded secret, weak crypto: the
    construct's presence is the finding);
  * the RC6 blast-radius cap did not freeze the layer.

All LLM behaviour goes through the network-free judge seam; no live model.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from shared.validate import ValidateConfig, llm_judge, validate
from tests._fake_llm import patch_l5_judge

_SRC = (
    "def load(raw):\n"            # 1
    "    try:\n"                  # 2
    "        return parse(raw)\n"  # 3
    "    except ValueError:\n"    # 4
    "        return None\n"       # 5
    "\n"                          # 6
    "def handler(req):\n"         # 7
    "    return load(req)\n"      # 8
)


def _refuting(**over) -> dict:
    v = {"exploitable": 0.05, "claim_holds": False, "window_sufficient": True,
         "evidence_line": 3, "reasoning": "parse fallback, not a security event"}
    v.update(over)
    return v


def _install_judge(monkeypatch, verdicts: dict[str, dict], calls: list | None = None) -> None:
    """Answer each finding id with its scripted verdict dict."""
    patch_l5_judge(monkeypatch)

    def _fake_call_llm(system_prompt: str, user_msg: str, model: str, timeout_s: float) -> str:
        if calls is not None:
            calls.append(user_msg)
        ids = re.findall(r"id=(\S+)", user_msg)
        return json.dumps({"verdicts": [{"id": fid, **verdicts[fid]} for fid in ids]})

    monkeypatch.setattr(llm_judge, "_call_llm", _fake_call_llm)


def _finding(path: Path, fid: str, *, category: str = "CWE-778",
             check_id: str = "cwe.insufficient_logging.cwe_778", line: int = 4) -> dict:
    return {
        "id": fid, "severity": "medium", "category": category,
        "title": "Insufficient Logging", "description": "handler does not log",
        "file_path": str(path), "line_start": line, "line_end": line,
        "recommendation": "log it", "check_id": check_id, "provenance": "skill",
        "code_snippet": "4:     except ValueError:\n5:         return None",
    }


def _source(tmp_path: Path, name: str = "loader.py") -> Path:
    p = tmp_path / "src" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_SRC)
    return p


def _run(tmp_path: Path, findings: list[dict]) -> dict[str, dict]:
    cfg = ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=True)
    result = validate(findings, source_path=str(tmp_path), config=cfg, audit_id="claim")
    return {f["id"]: f for f in result.findings}


def _judge_check(f: dict) -> dict:
    return next(c for c in f["validation"]["checks"] if c.get("id") == "llm_judge")


def test_a_cited_refutation_dismisses_a_deterministic_finding(tmp_path, monkeypatch):
    src = _source(tmp_path)
    _install_judge(monkeypatch, {"det": _refuting()})
    out = _run(tmp_path, [_finding(src, "det")])
    f = out["det"]
    assert f["validation_status"] == "likely_fp"
    assert _judge_check(f)["result"] == "claim_refuted"


@pytest.mark.parametrize("over, why", [
    ({"window_sufficient": None}, "closure not asserted"),
    ({"window_sufficient": False}, "verdict rests on unseen code"),
    ({"evidence_line": None}, "no line cited"),
    ({"evidence_line": 99}, "cited line past the end of the file"),
    ({"evidence_line": 0}, "line zero is not a line"),
    ({"evidence_file": "elsewhere.py"}, "cited another file"),
    ({"claim_holds": None}, "claim undecided"),
    ({"claim_holds": "false"}, "a string is not a literal false"),
    ({"exploitable": 0.7}, "a refuted claim that is also exploitable is incoherent"),
])
def test_an_inadmissible_refutation_does_not_dismiss(tmp_path, monkeypatch, over, why):
    src = _source(tmp_path)
    _install_judge(monkeypatch, {"det": _refuting(**over)})
    f = _run(tmp_path, [_finding(src, "det")])["det"]
    assert f["validation_status"] != "likely_fp", why
    assert _judge_check(f)["result"] != "claim_refuted", why


def test_a_true_low_impact_finding_stays_reported(tmp_path, monkeypatch):
    """Not exploitable is not the same as wrong: the claim holds, so it stays."""
    src = _source(tmp_path)
    _install_judge(monkeypatch, {"det": _refuting(claim_holds=True)})
    f = _run(tmp_path, [_finding(src, "det")])["det"]
    assert f["validation_status"] != "likely_fp"


def test_a_policy_class_is_never_dismissed_by_the_judge(tmp_path, monkeypatch):
    src = _source(tmp_path)
    _install_judge(monkeypatch, {"key": _refuting()})
    f = _run(tmp_path, [_finding(src, "key", category="CWE-798",
                                 check_id="cwe.secrets.hardcoded")])["key"]
    assert f["validation_status"] != "likely_fp"
    assert _judge_check(f)["result"] != "claim_refuted"


def test_rc6_freeze_also_freezes_claim_refutations(tmp_path, monkeypatch):
    """A non-Claude judge refuting every deterministic finding trips RC6."""
    findings = [_finding(_source(tmp_path, f"m{i}.py"), f"d{i}") for i in range(4)]
    _install_judge(monkeypatch, {f"d{i}": _refuting() for i in range(4)})
    out = _run(tmp_path, findings)
    for fid, f in out.items():
        assert f["validation_status"] != "likely_fp", fid
        assert _judge_check(f)["extras"].get("safeguard") == "rc6_blast_radius_cap", fid


def test_a_cached_refutation_replays(tmp_path, monkeypatch):
    """The second run is served from the verdict cache and still refutes."""
    src = _source(tmp_path)
    calls: list[str] = []
    _install_judge(monkeypatch, {"det": _refuting()}, calls)
    assert _run(tmp_path, [_finding(src, "det")])["det"]["validation_status"] == "likely_fp"
    n_calls = len(calls)
    again = _run(tmp_path, [_finding(src, "det")])["det"]
    assert len(calls) == n_calls, "second run must be a cache hit"
    assert again["validation_status"] == "likely_fp"
