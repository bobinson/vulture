"""RC6's blast-radius cap is set per judge-model family.

RC6 freezes the L5 layer when the judge's honoured demotions exceed a share of
the judged findings: the signature of a miscalibrated or manipulated judge
dismissing the result wholesale. At 0.5 for every model it froze a Claude
judge on every run of a noisy target. Measured on one TypeScript target with
claude-sonnet-5-5, two full runs (the second with every verdict fresh): 91.9%
and 86.7% of judged findings carried a demotion that would land, each one a
window-cited refutation. Claude's cap is 0.95, which still freezes a judge that
dismisses (nearly) everything; every other family keeps 0.5.
"""

from __future__ import annotations

import logging

from shared.validate.llm_judge import _apply_l5_safeguards
from shared.validate.types import ValidationCheck


def _finding(i: int) -> dict:
    # Deterministic, not a crypto/policy class: a demotion lands only on a
    # window-cited verdict, which every demoting check below asserts.
    return {
        "id": f"f{i}", "category": "CWE-400", "check_id": "c",
        "provenance": "skill", "severity": "medium",
        "file_path": "/x/a.ts", "line_start": i + 1,
        "validation": {"checks": []},
    }


def _demoting() -> ValidationCheck:
    return ValidationCheck(id="llm_judge", result="demoted", weight=-0.6,
                           extras={"window_sufficient": True})


def _neutral() -> ValidationCheck:
    return ValidationCheck(id="llm_judge", result="advisory", weight=0.0, extras={})


def _run(n_demoted: int, n_total: int, model: str) -> list[list[ValidationCheck]]:
    findings = [_finding(i) for i in range(n_total)]
    out = [[_demoting() if i < n_demoted else _neutral()] for i in range(n_total)]
    _apply_l5_safeguards(findings, list(range(n_total)), out, model=model)
    return out


def _frozen(out: list[list[ValidationCheck]]) -> bool:
    return any(o[0].extras.get("safeguard") == "rc6_blast_radius_cap" for o in out)


def test_a_claude_judge_demoting_90_percent_is_honoured() -> None:
    out = _run(18, 20, "claude-sonnet-5-5")
    assert not _frozen(out)
    assert sum(o[0].weight < 0 for o in out) == 18


def test_any_claude_spelling_gets_the_claude_cap() -> None:
    for model in ("litellm/anthropic/claude-sonnet-5-5", "claude-opus-5-5", "anthropic/claude-haiku-5-5"):
        assert not _frozen(_run(18, 20, model)), model


def test_other_judges_keep_the_half_cap() -> None:
    for model in ("qwen3.8-flash-next-iq3_s", "gpt-4o", "gemini-2.5-flash", ""):
        assert _frozen(_run(18, 20, model)), model


def test_a_claude_judge_dismissing_nearly_everything_still_freezes() -> None:
    assert _frozen(_run(20, 20, "claude-sonnet-5-5"))
    assert _frozen(_run(39, 40, "claude-sonnet-5-5"))  # 97.5% > 95%


def test_the_freeze_log_reports_the_honoured_count_and_the_cap(caplog) -> None:
    with caplog.at_level(logging.WARNING):
        _run(18, 20, "qwen3:8b")
    line = next(r.message for r in caplog.records if "RC6" in r.message)
    assert "18/20" in line and "50%" in line
