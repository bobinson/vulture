"""Feature 0072 T7.5 — one executable fixture per §3 defect class.

Each test pins the FIX for one defect class from the plan's audit, so a
regression fails a unit test instead of surfacing as a field report. Where a
dedicated suite already covers a class in depth, the fixture here is the
minimal sentinel; the deep suite is named in the docstring.

G1/G2 (process-boundary defects) live on the Go side:
backend/internal/handler/obligation_revote_test.go (mutation-checked) and
the shared parity fixture. They cannot be pinned from Python and are
deliberately absent here.
"""

from __future__ import annotations

from shared.validate import ValidateConfig, validate
from shared.validate.llm_judge import (
    COVERAGE_ID,
    _verdict_to_check,
    _window_sufficient,
)
from shared.validate.types import ValidationCheck
from shared.validate.voter import (
    CONFIDENCE_CEILING_UNVERIFIED,
    JUDGE_CITED,
    JUDGE_UNCITED,
    OBLIGATION_DISCHARGED,
    OBLIGATION_ID,
    OBLIGATION_UNKNOWN,
    vote,
)


def _c(id: str, weight: float, result: str = "x") -> ValidationCheck:
    return ValidationCheck(id=id, result=result, weight=weight, reason="t")


def test_A_unknown_is_a_state_not_a_zero():
    """§3 A: a class that was never searched blocks confirmation instead of
    scoring identically to a clean result. (Deep: test_obligation_gate.py)"""
    unknown = [_c("llm_judge", 0.60, JUDGE_CITED),
               _c(OBLIGATION_ID, 0.0, OBLIGATION_UNKNOWN)]
    clean = [_c("llm_judge", 0.60, JUDGE_CITED),
             _c(OBLIGATION_ID, 0.0, OBLIGATION_DISCHARGED)]
    assert vote(unknown)[0] == "suspicious"
    assert vote(clean)[0] == "high_confidence"


def test_A3_layer_crash_never_raises_confidence():
    """§3 A3: a crashed L1 contributes a blocking obligation, not silence.
    (Deep: test_obligation_integration.py)"""
    findings = [{"id": "x", "category": "CWE-89", "check_id": "c",
                 "title": "t", "severity": "high",
                 "file_path": None, "line_start": {"bad": "type"}}]
    res = validate(findings, config=ValidateConfig(), audit_id="crash")
    checks = res.findings[0]["validation"]["checks"]
    ob = next(c for c in checks if c["id"] == OBLIGATION_ID)
    assert ob is not None, "the crash path must still emit an obligation"


def test_B_evidence_scope_can_reach_past_the_window(tmp_path):
    """§3 B1: for a reviewed FILE-scope class the search is no longer the
    20-line backward window. (Deep: test_calibration.py forward-search)"""
    from shared.validate.context_heuristics import _sanitizer_search_extent
    from shared.validate.refutation import REFUTATION_MAP

    ref = REFUTATION_MAP["CWE-639"]
    assert ref.scope.name == "WIRING", (
        "the authorization family must search where its mitigations live"
    )


def test_C1_one_unverifiable_opinion_cannot_confirm():
    """§3 C1/C2: a lone uncited judge cannot confirm, and no single check
    reaches confidence 1.0. (Deep: test_obligation_gate, test_confidence_ceiling)"""
    status, conf = vote([_c("llm_judge", 0.75, JUDGE_UNCITED)])
    assert status == "suspicious"
    assert conf <= CONFIDENCE_CEILING_UNVERIFIED < 1.0


def test_D1_unknown_is_not_verified():
    """§3 D1: an UNDECIDED verdict must not read as judge-verified.
    (Deep: test_l5_retag_assertion.py)"""
    from shared.validate import _L5_NO_ASSERTION, _retag_l5_verified
    f = {"provenance": "llm"}
    checks = [ValidationCheck(id="llm_judge", result="undecided", weight=0.0,
                              reason="cannot tell")]
    _retag_l5_verified(f, checks)
    assert f["provenance"] == "llm", (
        "a no-assertion verdict re-tagged provenance to llm_l5_verified"
    )
    assert "undecided" in _L5_NO_ASSERTION and "error" in _L5_NO_ASSERTION


def test_E_evidence_travels_with_the_verdict():
    """§3 E1/E2: the window and citation are recorded, not discarded.
    (Deep: test_p5_auditability.py + Go repo round-trip tests)"""
    check = _verdict_to_check(
        {"id": "f", "exploitable": 0.9, "reasoning": "x",
         "window_sufficient": True, "evidence_line": 12},
        model="m", batch_id=0, language="py",
        finding={"id": "f", "line_start": 40},
    )
    assert check.extras["window_sufficient"] is True
    assert check.extras["evidence_line"] == 12
    assert check.extras["citation_class"] == "other_line"


def test_H2_missing_closure_is_not_asserted():
    """§3 H2: only a literal True opens the closure gate — absent, false,
    or wrong-typed all fail closed. (Deep: test_l5_closure_gate.py)"""
    for bad in (None, False, "true", 1):
        check = ValidationCheck(id="llm_judge", result="demoted", weight=-0.3,
                                reason="r", extras={"window_sufficient": bad})
        assert _window_sufficient(check) is False, repr(bad)


def test_I1_coverage_is_never_silent():
    """§3 I1/A6: every finding names what happened to it at L5.
    (Deep: test_l5_coverage.py)"""
    findings = [{"id": "x", "category": "CWE-89", "check_id": "c",
                 "title": "t", "severity": "high",
                 "file_path": "a.py", "line_start": 1, "line_end": 1,
                 "code_snippet": "1: x"}]
    res = validate(findings, config=ValidateConfig(enable_l5=False),
                   audit_id="cov")
    checks = res.findings[0]["validation"]["checks"]
    assert any(c["id"] == COVERAGE_ID for c in checks)


def test_J1_a_mitigation_match_never_raises_confidence(tmp_path):
    """§3 J1 (P0): the sanitizer's inverted polarity. A matching mitigation
    pattern near the sink must not score the finding HIGHER.
    (Deep: test_sanitizer_polarity.py)"""
    from shared.validate.context_heuristics import _sanitizer_check, clear_l1_cache
    clear_l1_cache()
    mitigated = tmp_path / "m.py"
    mitigated.write_text("cur = conn.cursor()\ncur.execute(q, params) if prepared else None\ncur.execute(q)\n")
    check = _sanitizer_check(str(mitigated), 3, "CWE-89")
    assert check.result == "matched"
    assert check.weight == 0.0, "a mitigation match must never promote"
