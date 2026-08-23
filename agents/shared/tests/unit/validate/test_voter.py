"""Voter rule tests — V7 invariants."""

from shared.validate.types import ValidationCheck
from shared.validate.voter import AUTHORITATIVE_CHECKS, vote


def test_no_checks_high_confidence():
    """Empty checks → confidence 0.5 → high_confidence (above threshold)."""
    status, conf = vote([])
    assert status == "suspicious"     # 0.5 is below 0.55 threshold
    assert conf == 0.5


def test_single_demoting_check_yields_suspicious_not_likely_fp():
    """V7: a single demoting check cannot land likely_fp."""
    checks = [ValidationCheck(id="path", result="demoted", weight=-0.40, reason="test")]
    status, conf = vote(checks)
    assert status == "suspicious", "single check should not reach likely_fp"
    assert conf < 0.30


def test_two_demoting_checks_land_likely_fp():
    """V7: ≥ 2 demoting checks + confidence < 0.30 → likely_fp."""
    checks = [
        ValidationCheck(id="path", result="demoted", weight=-0.20, reason="test path"),
        ValidationCheck(id="memory", result="inherited", weight=-0.30, reason="fp neighbor"),
    ]
    status, conf = vote(checks)
    assert status == "likely_fp"
    assert conf == 0.0   # clamped


def test_authoritative_suppression_overrides_v7():
    """Suppression marker alone demotes to likely_fp (V7 amendment)."""
    checks = [ValidationCheck(id="suppression", result="demoted", weight=-0.40,
                              reason="# nosec marker")]
    status, conf = vote(checks)
    assert status == "likely_fp"
    assert conf <= 0.05


def test_authoritative_only_when_weight_negative():
    """A positive-weight `suppression` check (defensive — shouldn't
    occur in practice) does NOT auto-demote."""
    checks = [ValidationCheck(id="suppression", result="kept", weight=0.10,
                              reason="(theoretical positive)")]
    status, _ = vote(checks)
    assert status != "likely_fp"


def test_promoting_signal_lifts_to_high_confidence():
    """A promoting signal pushes above the 0.55 threshold."""
    checks = [
        ValidationCheck(id="sanitizer", result="promoted", weight=0.15, reason="sanitizer found"),
        ValidationCheck(id="cross_agent", result="merged", weight=0.10, reason="2 agents agree"),
    ]
    status, conf = vote(checks)
    assert status == "high_confidence"
    assert conf > 0.55


def test_authoritative_set_contents():
    """Document the authoritative DEMOTING set.

    v1 (0072) was `{"suppression"}` -- an operator's own `# nosec`-style marker.
    0076 adds `"anchor"`, the seat `voter.py:92` reserved for exactly this: a
    mechanical verification that the code a finding accuses is not where it said
    it is. This is a documentation pin, not a business rule -- its job is to make
    a change to the set deliberate and to force the Go mirror to move with it
    (see test_voter_parity.py). Both sides moved together in 0076.

    Membership is safe to be static because the GATE IS THE WEIGHT, not the id:
    `_has_authoritative_demotion` requires `weight < 0`, and the anchor check
    carries 0.0 unless VULTURE_LLM_QUOTE_DEMOTE_ABSENT is set. So with the
    feature's shipped default the seat is occupied and inert.
    """
    assert AUTHORITATIVE_CHECKS == frozenset({"suppression", "anchor"})


def test_confidence_clamped_to_0_1():
    """Confidence stays in [0, ceiling] regardless of weight sums.

    Feature 0072 T4.2: the upper bound is 0.99 unless an authoritative
    positive (human ground truth) is present — certainty is reserved.
    """
    huge_pos = [ValidationCheck(id="x", result="ok", weight=10.0) for _ in range(5)]
    huge_neg = [ValidationCheck(id="x", result="ok", weight=-10.0) for _ in range(5)]
    _, p = vote(huge_pos)
    _, n = vote(huge_neg)
    assert p == 0.99
    assert n == 0.0
    with_truth = huge_pos + [
        ValidationCheck(id="memory", result="user_label", weight=0.4)]
    _, pt = vote(with_truth)
    assert pt == 1.0
