"""Feature 0072 §5.3 condition 1 / T4.3 — a promoting judge verdict may confirm
ALONE only if it asserted closure (window_sufficient is True).

Found by the togetherapp MCP dogfood: a lone judge verdict with
window_sufficient=None (the judge itself said "the window is insufficient")
was marked JUDGE_CITED purely because exploitable>0.5, and confirmed a QA-only
SQL-string-interpolation FP where both interpolated values are provably safe.
The gate must not confirm on an unverified-absence claim.
"""

from __future__ import annotations

import pytest

from shared.validate.llm_judge import _verdict_to_check
from shared.validate.types import ValidationCheck
from shared.validate.voter import (
    JUDGE_CITED,
    JUDGE_UNCITED,
    JUDGE_UNDECIDED,
    OBLIGATION_DISCHARGED,
    OBLIGATION_ID,
    vote,
)


def _verdict(prob, ws, ev=None):
    return {"id": "f0", "exploitable": prob, "reasoning": "r",
            "window_sufficient": ws, "evidence_line": ev}


@pytest.fixture(autouse=True)
def _closure_on(monkeypatch):
    # Exercise the mechanism directly: force the requirement on regardless of
    # obligation mode. (The mode-default is covered by its own test below.)
    monkeypatch.setenv("VULTURE_L5_PROMOTION_CLOSURE", "true")
    yield


def test_mode_default_off_in_observe_on_in_enforce(monkeypatch):
    from shared.validate.llm_judge import _promotion_closure_required
    monkeypatch.delenv("VULTURE_L5_PROMOTION_CLOSURE", raising=False)
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "observe")
    assert _promotion_closure_required() is False
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    assert _promotion_closure_required() is True
    # explicit override wins over mode
    monkeypatch.setenv("VULTURE_L5_PROMOTION_CLOSURE", "false")
    assert _promotion_closure_required() is False


# ── ingestion: the result label carries admissibility ─────────────────────


def test_promotion_with_closure_is_cited():
    c = _verdict_to_check(_verdict(0.8, True, 212), model="m", batch_id=0,
                          language="ts", finding={"id": "f0", "line_start": 40})
    assert c.result == JUDGE_CITED
    assert c.weight > 0


def test_promotion_without_closure_is_uncited():
    # window_sufficient=None → the judge did not assert the window decides it.
    c = _verdict_to_check(_verdict(0.8, None, 212), model="m", batch_id=0,
                          language="ts", finding={"id": "f0", "line_start": 212})
    assert c.result == JUDGE_UNCITED, "no closure ⇒ inadmissible for sole confirm"
    assert c.weight > 0, "weight is unchanged — only the admissibility label differs"


def test_promotion_with_false_closure_is_uncited():
    c = _verdict_to_check(_verdict(0.8, False, 212), model="m", batch_id=0,
                          language="ts", finding={"id": "f0", "line_start": 40})
    assert c.result == JUDGE_UNCITED


def test_undecided_boundary_unaffected():
    c = _verdict_to_check(_verdict(0.5, None), model="m", batch_id=0,
                          language="ts", finding={"id": "f0", "line_start": 1})
    assert c.result == JUDGE_UNDECIDED


def test_demotion_unaffected():
    c = _verdict_to_check(_verdict(0.1, None), model="m", batch_id=0,
                          language="ts", finding={"id": "f0", "line_start": 1})
    assert c.result == "demoted"
    assert c.weight < 0


def test_kill_switch_restores_prob_only(monkeypatch):
    monkeypatch.setenv("VULTURE_L5_PROMOTION_CLOSURE", "false")
    c = _verdict_to_check(_verdict(0.8, None, 212), model="m", batch_id=0,
                          language="ts", finding={"id": "f0", "line_start": 212})
    assert c.result == JUDGE_CITED, "kill switch ⇒ legacy prob-only labelling"


# ── end-to-end through the voter: the VLT-2888 shape ───────────────────────


def _obl():
    return ValidationCheck(id=OBLIGATION_ID, result=OBLIGATION_DISCHARGED,
                           weight=0.0, reason="searched, empty")


def test_lone_uncited_judge_does_not_confirm():
    """VLT-2888: sole promoter is a judge with no closure → withheld."""
    judge = _verdict_to_check(_verdict(0.8, None, 212), model="m", batch_id=0,
                              language="ts", finding={"id": "f0", "line_start": 212})
    status, conf = vote([judge, _obl()])
    assert status == "suspicious", "a lone no-closure judge must not confirm"
    assert conf > 0.55, "confidence preserved — only the label withheld"


def test_lone_cited_judge_confirms():
    judge = _verdict_to_check(_verdict(0.8, True, 40), model="m", batch_id=0,
                              language="ts", finding={"id": "f0", "line_start": 212})
    status, _ = vote([judge, _obl()])
    assert status == "high_confidence", "a closure-asserting judge may confirm"


def test_corroborated_judge_unaffected_by_closure():
    """When the judge is NOT the sole promoter, closure is irrelevant to the
    gate — a deterministic promotion carries it."""
    judge = _verdict_to_check(_verdict(0.8, None, 212), model="m", batch_id=0,
                              language="ts", finding={"id": "f0", "line_start": 212})
    path = ValidationCheck(id="path", result="promoted", weight=0.10,
                           reason="production entry point")
    status, _ = vote([judge, path, _obl()])
    assert status == "high_confidence", "corroborated confirmation stands"
