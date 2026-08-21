"""Feature 0072 P1 — obligations and the status gate.

The gate withholds the `high_confidence` LABEL when an obligation was never
discharged. It never rewrites confidence, never deletes a finding, and never
overrides a human's own positive label.
"""

from __future__ import annotations

import pytest

from shared.validate.types import ValidationCheck
from shared.validate.voter import (
    JUDGE_CITED,
    JUDGE_UNCITED,
    OBLIGATION_DISCHARGED,
    OBLIGATION_ID,
    OBLIGATION_REFUTED,
    OBLIGATION_UNKNOWN,
    vote,
)


def obligation(result: str) -> ValidationCheck:
    return ValidationCheck(id=OBLIGATION_ID, result=result, weight=0.0,
                           reason=f"ownership-predicate: {result}")


def judge(weight: float, result: str = JUDGE_CITED) -> ValidationCheck:
    return ValidationCheck(id="llm_judge", result=result, weight=weight,
                           reason="judge verdict")


def path_promoted() -> ValidationCheck:
    return ValidationCheck(id="path", result="promoted", weight=0.10,
                           reason="production entry point")


def operator(weight: float) -> ValidationCheck:
    return ValidationCheck(id="memory", result="user_label", weight=weight,
                           reason="operator label")


# ── the gate withholds the label ──────────────────────────────────────────

def test_unknown_obligation_withholds_the_label():
    checks = [path_promoted(), judge(0.60), obligation(OBLIGATION_UNKNOWN)]
    status, conf = vote(checks)
    assert status == "suspicious"
    assert conf > 0.55, "confidence must be PRESERVED, only the label withheld"


def test_discharged_obligation_permits_confirmation():
    checks = [path_promoted(), judge(0.60), obligation(OBLIGATION_DISCHARGED)]
    status, _ = vote(checks)
    assert status == "high_confidence"


def test_refuted_obligation_dismisses_the_finding():
    """`refuted` is the ONLY verdict that removes a finding.

    An earlier revision asserted the opposite — that a refutation merely fails to
    block confirmation, because the finding "should have been dropped upstream".
    Nothing upstream drops it: validate() is length-preserving by contract (V6)
    and the voter is the only place a status is assigned. Under that reading
    `refuted` was a no-op and the feature could not remove a single false
    positive, which is the entire point of it.

    Note the asymmetry that makes this safe: reaching `refuted` requires
    STRUCTURAL evidence (MAX_VERDICT), so a regex match on a comment can only
    ever discharge, never dismiss.
    """
    checks = [path_promoted(), obligation(OBLIGATION_REFUTED)]
    status, confidence = vote(checks)
    assert status == "likely_fp"
    assert confidence == pytest.approx(0.6), (
        "the obligation axis must not re-score the detection evidence")


def test_confidence_is_never_rewritten_by_the_gate():
    """The exact number must survive; only `status` moves."""
    open_checks = [judge(0.45), obligation(OBLIGATION_UNKNOWN)]
    closed_checks = [judge(0.45), obligation(OBLIGATION_DISCHARGED)]
    _, conf_open = vote(open_checks)
    _, conf_closed = vote(closed_checks)
    assert conf_open == conf_closed == pytest.approx(0.95)


def test_blocking_obligation_does_not_prevent_dismissal():
    """Independent refutation may still dismiss a finding whose obligation was
    never searched — the gate restrains confirmation only."""
    checks = [judge(-0.60), ValidationCheck(id="path", result="demoted", weight=-0.20,
                                            reason="test path"),
              obligation(OBLIGATION_UNKNOWN)]
    status, _ = vote(checks)
    assert status == "likely_fp"


# ── the authoritative-positive override ───────────────────────────────────

def test_operator_positive_label_overrides_the_gate():
    checks = [operator(0.40), obligation(OBLIGATION_UNKNOWN)]
    status, _ = vote(checks)
    assert status == "high_confidence", "a human's own label is ground truth"


def test_operator_NEGATIVE_label_never_grants_an_override():
    """The weight test is load-bearing: keying on the id alone would let a user
    calling something a false positive grant it a confirmation override."""
    checks = [operator(-0.40), judge(0.60), obligation(OBLIGATION_UNKNOWN)]
    status, _ = vote(checks)
    assert status != "high_confidence"


# ── the judge may not confirm alone unless it cited something ─────────────

def test_lone_uncited_judge_promotion_cannot_confirm():
    checks = [judge(0.60, JUDGE_UNCITED), obligation(OBLIGATION_DISCHARGED)]
    status, conf = vote(checks)
    assert status == "suspicious"
    assert conf > 0.55


def test_lone_CITED_judge_promotion_can_confirm():
    checks = [judge(0.60, JUDGE_CITED), obligation(OBLIGATION_DISCHARGED)]
    status, _ = vote(checks)
    assert status == "high_confidence"


def test_unknown_judge_result_fails_closed():
    """A verdict cached under an older schema carries neither marker."""
    checks = [judge(0.60, "real_bug_legacy"), obligation(OBLIGATION_DISCHARGED)]
    status, _ = vote(checks)
    assert status == "suspicious"


def test_lone_deterministic_promotion_is_untouched():
    """The rule restrains the judge, not solo checks generally. 81% of findings
    carry no evidence at all; a quorum rule would empty the confirmed tier."""
    checks = [path_promoted(), obligation(OBLIGATION_DISCHARGED)]
    status, conf = vote(checks)
    assert conf == pytest.approx(0.60)
    assert status == "high_confidence"


def test_uncited_judge_alongside_a_deterministic_promotion_confirms():
    """The judge is only barred when it is the SOLE promoter."""
    checks = [path_promoted(), judge(0.60, JUDGE_UNCITED),
              obligation(OBLIGATION_DISCHARGED)]
    status, _ = vote(checks)
    assert status == "high_confidence"


def test_a_demoting_check_is_never_counted_as_a_promoter():
    checks = [judge(0.60, JUDGE_UNCITED),
              ValidationCheck(id="path", result="demoted", weight=-0.20, reason="t"),
              obligation(OBLIGATION_DISCHARGED)]
    status, _ = vote(checks)
    assert status == "suspicious", "the demotion must not corroborate the judge"


# ── absence of an obligation check preserves pre-0072 behaviour ───────────

def test_no_obligation_check_behaves_exactly_as_before():
    """Every existing caller emits no obligation check; nothing may change."""
    checks = [path_promoted()]
    status, conf = vote(checks)
    assert (status, conf) == ("high_confidence", pytest.approx(0.60))
