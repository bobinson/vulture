"""Feature 0072 P4 (T4.2/AC5) — confidence 1.0 is reserved.

No pile of heuristic votes — and no single model vote (C2: any
`exploitable >= 0.834` used to reach exactly 1.000) — may present as total
certainty. Only ground truth (today: an operator's own positive label; a
future mechanical-verification check joins the same set) lifts the ceiling.

Implemented as a clamp BOUND, never an equality test: the two voters fold
weights in different orders (`0.5 + sum(w)` vs accumulate-from-0.5), so an
`if confidence >= 1.0` trigger can fire in one language and not the other
for the same checks. A bound only ever compares with `>`, which both
languages evaluate identically for the clamped result.
"""

from __future__ import annotations

from shared.validate.types import ValidationCheck
from shared.validate.voter import (
    CONFIDENCE_CEILING_UNVERIFIED,
    JUDGE_CITED,
    vote,
)


def check(id: str, weight: float, result: str = "x") -> ValidationCheck:
    return ValidationCheck(id=id, result=result, weight=weight, reason="t")


def test_a_lone_judge_vote_cannot_reach_certainty():
    status, conf = vote([check("llm_judge", 0.75, JUDGE_CITED)])
    assert status == "high_confidence"
    assert conf == CONFIDENCE_CEILING_UNVERIFIED
    assert conf < 1.0


def test_heuristic_pileup_cannot_reach_certainty():
    checks = [
        check("path", 0.10, "promoted"),
        check("llm_judge", 0.75, JUDGE_CITED),
        check("cross_agent", 0.30, "corroborated"),
    ]
    _, conf = vote(checks)
    assert conf == CONFIDENCE_CEILING_UNVERIFIED


def test_human_ground_truth_lifts_the_ceiling():
    checks = [
        check("llm_judge", 0.75, JUDGE_CITED),
        check("memory", 0.40, "user_label"),
    ]
    _, conf = vote(checks)
    assert conf == 1.0


def test_negative_operator_label_does_not_lift_the_ceiling():
    """`memory` is bidirectional; a user's FALSE-POSITIVE label must not
    grant the certainty reserved for confirmed-real findings."""
    checks = [
        check("llm_judge", 0.75, JUDGE_CITED),
        check("path", 0.30, "promoted"),
        check("memory", -0.40, "user_label"),
    ]
    _, conf = vote(checks)
    assert conf <= CONFIDENCE_CEILING_UNVERIFIED


def test_ceiling_changes_no_status():
    """0.99 is far above every status threshold; the ceiling is about the
    SENTINEL value, not about reclassifying anything."""
    status, _ = vote([check("llm_judge", 0.75, JUDGE_CITED)])
    assert status == "high_confidence"


def test_floor_is_untouched():
    _, conf = vote([check("llm_judge", -0.75, "demoted"),
                    check("path", -0.30, "demoted")])
    assert conf == 0.0
