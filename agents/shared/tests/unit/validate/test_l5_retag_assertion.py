"""Feature 0072 T4.8 — a verdict that asserted NOTHING may not re-tag provenance.

`llm_l5_verified` is persisted and user-visible, and its docstring reads
"independently confirmed by the judge". Two states reached it without any
assertion having been made:

  * the no-verdict stub emitted when the judge is unreachable — the same stub the
    L5 summary reports as "CONTRIBUTED NOTHING; treat this run as unjudged";
  * a verdict at exploitable == 0.5, the prompt's own "cannot judge" value, which
    is the branch that actually executes (10/10 live verdicts, 40/207 cached).

Every check here is built by CALLING THE PRODUCER rather than hand-constructing a
ValidationCheck, so the tests pin the real shapes and would notice if a producer
changed underneath them.
"""

from __future__ import annotations

import pytest

from shared.validate import (
    ValidateConfig,
    _apply_validation_to_finding,
    _revote_finding_in_place,
)
from shared.validate.llm_judge import _neutralize_l5_check, _verdict_to_check
from shared.validate.types import ValidationCheck
from shared.validate.voter import JUDGE_CITED, JUDGE_UNDECIDED, vote


def _verdict(prob: float) -> ValidationCheck:
    return _verdict_to_check(
        {"id": "f1", "exploitable": prob, "reasoning": "r"},
        model="m", batch_id=1, language="python",
    )


def _error_stub() -> ValidationCheck:
    """The exact shape llm_judge emits when a batch yields no verdict."""
    return ValidationCheck(
        id="llm_judge", result="error", weight=0.0, reason="no verdict",
    )


def _llm_finding() -> dict:
    return {"id": "f1", "provenance": "llm", "title": "t",
            "file_path": "/x/y.py", "line_start": 1, "category": "CWE-89"}


def _offline(checks: list[ValidationCheck]) -> dict:
    return _apply_validation_to_finding(_llm_finding(), checks, ValidateConfig())


def _streaming(checks: list[ValidationCheck]) -> dict:
    """The live path. It reads the finding's OWN serialised checks, so this
    also exercises ValidationCheck round-tripping through to_json/from_json —
    where a dropped field would silently disable the rule."""
    f = _llm_finding()
    f["validation"] = {"status": "suspicious", "confidence": 0.5,
                       "checks": [c.to_json() for c in checks]}
    _revote_finding_in_place(f, ValidateConfig())
    return f


# ── the producer's boundary ───────────────────────────────────────────────

def test_the_affirmative_label_requires_a_strict_majority():
    """exploitable == 0.5 is "I cannot judge", not "real bug"."""
    assert _verdict(0.5).result == JUDGE_UNDECIDED
    assert _verdict(0.5).weight == 0.0
    assert _verdict(0.51).result == JUDGE_CITED
    assert _verdict(0.49).result == "demoted"


def test_the_boundary_change_moved_no_confidence():
    """The gate withholds labels; it never re-scores. weight was already 0.0 at
    the boundary, so this must be a pure label change."""
    assert _verdict(0.5).weight == 0.0
    assert vote([_verdict(0.5)]) == ("suspicious", 0.5)


# ── the two no-assertion states must not re-tag ───────────────────────────

@pytest.mark.parametrize("path", [_offline, _streaming])
def test_an_undecided_verdict_does_not_retag(path):
    assert path([_verdict(0.5)])["provenance"] == "llm"


@pytest.mark.parametrize("path", [_offline, _streaming])
def test_an_error_stub_does_not_retag(path):
    """A dead judge must not mark findings as judge-verified. The run summary
    already calls this case unjudged; provenance said the opposite."""
    assert path([_error_stub()])["provenance"] == "llm"


# ── positive controls: without these the change is indistinguishable from
#    deleting the feature ────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [_offline, _streaming])
def test_a_real_promotion_still_retags(path):
    assert path([_verdict(0.9)])["provenance"] == "llm_l5_verified"


@pytest.mark.parametrize("path", [_offline, _streaming])
def test_a_neutralised_verdict_still_retags(path):
    """A verdict frozen by the RC6 cap or the policy exemption is rebuilt as
    `result="advisory"`, weight 0.0. It asserted something — the neutralisation
    is Vulture's decision, not the judge's — so it must still re-tag.

    This is why the predicate subtracts the two no-assertion states rather than
    requiring an affirmative one: `any(result == JUDGE_CITED)` would make the
    re-tag unreachable for every neutralised verdict and silently revert the
    documented streaming-path fix in test_provenance.py.
    """
    neutralised = _neutralize_l5_check(_verdict(0.1), "rc6_blast_radius_cap")
    assert neutralised.weight == 0.0
    assert path([neutralised])["provenance"] == "llm_l5_verified"


@pytest.mark.parametrize("path", [_offline, _streaming])
def test_a_demotion_still_blocks_the_retag(path):
    assert path([_verdict(0.1)])["provenance"] == "llm"


@pytest.mark.parametrize("path", [_offline, _streaming])
def test_one_real_verdict_among_stubs_retags(path):
    """`all(...)` not `any(...)`: a finding judged in two batches where only one
    returned is still judged."""
    assert path([_error_stub(), _verdict(0.9)])["provenance"] == "llm_l5_verified"


# ── the re-tag may never touch status or confidence ───────────────────────

@pytest.mark.parametrize("checks_fn", [
    lambda: [_verdict(0.5)], lambda: [_error_stub()], lambda: [_verdict(0.9)],
])
def test_retag_is_label_only(checks_fn):
    """Fails if anyone moves the re-tag ahead of the validation stamp."""
    checks = checks_fn()
    out = _offline(checks)
    want_status, want_conf = vote(checks)
    assert out["validation_status"] == want_status
    assert out["validation_confidence"] == want_conf


# ── T4.10: the L5 policy exemption is single-sourced ──────────────────────

def test_the_l5_exemption_set_is_the_declared_policy_set():
    """Two hand-maintained copies of the same judgement had diverged.

    `llm_judge._CRYPTO_POLICY_CWES` (which CWEs the L5 judge may never suppress
    alone) and `refutation.POLICY_CLASSES` (which classes declare Scope.NONE —
    "nothing can refute this") are the same statement: a class with no admissible
    refutation cannot have an L5 suppression resting on one. The L5 copy was
    missing CWE-321 and CWE-1395, so both were suppressible by a lone judge
    verdict despite being declared unrefutable.

    Keeping them equal is the point; this test fails if anyone re-forks them.
    """
    from shared.validate.llm_judge import _CRYPTO_POLICY_CWES
    from shared.validate.refutation import POLICY_CLASSES

    assert _CRYPTO_POLICY_CWES is POLICY_CLASSES


def test_the_previously_missing_classes_are_now_exempt():
    """The two that diverged, named explicitly so a silent re-narrowing fails."""
    from shared.validate.llm_judge import _CRYPTO_POLICY_CWES

    assert "CWE-321" in _CRYPTO_POLICY_CWES, "hardcoded crypto key"
    assert "CWE-1395" in _CRYPTO_POLICY_CWES, "known-vulnerable dependency"


@pytest.mark.parametrize("cwe", ["CWE-321", "CWE-1395"])
def test_the_newly_exempt_classes_resist_a_lone_judge_suppression(cwe):
    """Before single-sourcing, a lone judge verdict could suppress these."""
    from shared.validate.llm_judge import _exemption_reason

    finding = {"id": "f", "provenance": "skill", "category": cwe,
               "file_path": "/x.py", "line_start": 1}
    assert _exemption_reason(finding, _verdict(0.1)) == "crypto_policy_exempt"


def test_widening_the_exemption_set_changes_when_rc6_freezes():
    """A MEASURED and ACCEPTED side effect of single-sourcing — do not "fix".

    `_is_l5_exempt` feeds RC6's unanimity carve-out: a 100% demotion run is
    exempt from the blast-radius freeze only when EVERY judged finding is
    non-deterministic. Adding CWE-1395 to the exempt set means a run containing
    one now fails that test, so RC6 freezes and all four demotions are discarded.

    The direction is protective. Freezing DISCARDS demotions, so it keeps
    findings: it cannot introduce a false negative and cannot shrink the
    confirmed tier. It costs precision — three unrelated correct demotions are
    dropped on such a run — not recall.

    If that noise is ever judged unacceptable, the fix is to give the RC6
    carve-out its own narrower predicate, NOT to re-fork the policy set.
    """
    from shared.validate.llm_judge import _apply_l5_safeguards

    def run(fourth: str):
        findings = [{"id": c, "provenance": "llm", "category": c,
                     "file_path": "/x.py", "line_start": 1}
                    for c in ["CWE-89", "CWE-79", "CWE-22", fourth]]
        out = [[_verdict(0.1)] for _ in findings]
        _apply_l5_safeguards(findings, list(range(4)), out)
        return [(pytest.approx(c.weight), (c.extras or {}).get("safeguard"))
                for checks in out for c in checks]

    # An exempt class present -> unanimity carve-out lost -> RC6 freezes.
    assert run("CWE-1395") == [(0.0, "rc6_blast_radius_cap")] * 4
    # No exempt class -> unanimous all-nondeterministic -> demotions land.
    assert run("CWE-476") == [(-0.6, None)] * 4
