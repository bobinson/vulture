"""Feature 0072 P6 — L5 coverage becomes visible (T6.1/T6.2, AC7, AC32).

Which findings the judge actually saw is a stated, per-finding fact, not an
emergent property of snippet attachment. Every finding leaving validate()
carries a `coverage` check whose result names what happened at L5 — and a
missing L5 verdict NEVER blocks confirmation (coverage is informational).

The result vocabulary is enumerated (AC32). Two values extend the plan's
five, both forced by the dogfood run that motivated P6: `skipped_l5_disabled`
(the most common "why not judged" of all — the layer was off) and
`judge_error` (a finding the judge attempted and returned no verdict for;
counting it "judged" is the exact dishonesty the L5 summary fix removed).
"""

from __future__ import annotations

from shared.validate import ValidateConfig, validate
from shared.validate.llm_judge import (
    COVERAGE_ID,
    COVERAGE_JUDGE_ERROR,
    COVERAGE_JUDGED,
    COVERAGE_RESULTS,
    COVERAGE_SKIPPED_ALREADY_LIKELY_FP,
    COVERAGE_SKIPPED_L5_DISABLED,
    COVERAGE_SKIPPED_NO_WINDOW,
    COVERAGE_SKIPPED_NOT_SELECTED,
    run_l5,
)
from shared.validate.types import ValidationCheck
from shared.validate.voter import OBLIGATION_DISCHARGED, OBLIGATION_ID, vote


def _f(idx: int, sev: str = "medium", **overrides) -> dict:
    f = {
        "id": f"f{idx}",
        "severity": sev,
        "title": f"finding-{idx}",
        "file_path": f"src/x{idx}.py",
        "line_start": 10, "line_end": 10,
        "description": "x",
        "code_snippet": "x = 1\n",
        "check_id": f"chk-{idx}",
    }
    f.update(overrides)
    return f


def _coverage_of(finding: dict) -> dict:
    checks = finding.get("validation", {}).get("checks", [])
    cov = [c for c in checks if c.get("id") == COVERAGE_ID]
    assert len(cov) == 1, (
        f"finding {finding.get('id')} must carry exactly one coverage check, "
        f"got {len(cov)}"
    )
    return cov[0]


def _fake_verdicts(system, user_msg, model, timeout):
    import re
    ids = re.findall(r"id=(f\d+)", user_msg)
    verdicts = ",".join(
        f'{{"id":"{i}","exploitable":0.8,"reasoning":"x"}}' for i in ids
    )
    return f'{{"verdicts":[{verdicts}]}}'


# ── AC7: every finding carries a coverage check ────────────────────────────


def test_l5_disabled_still_stamps_coverage_on_every_finding():
    """The commonest "why was this never judged" is: the layer was off.

    That must be a stated fact on the finding, not an absence the reader
    has to infer from a missing check.
    """
    findings = [_f(0), _f(1)]
    result = validate(findings, config=ValidateConfig(enable_l5=False))
    for f in result.findings:
        cov = _coverage_of(f)
        assert cov["result"] == COVERAGE_SKIPPED_L5_DISABLED
        assert cov["weight"] == 0.0


def test_judged_finding_is_marked_judged(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [_f(0, "high")]
    cfg = ValidateConfig(enable_l5=True, l5_model_override="test-model")
    result = validate(findings, config=cfg)
    assert _coverage_of(result.findings[0])["result"] == COVERAGE_JUDGED


def test_no_window_finding_is_marked_skipped_no_window(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [_f(0, "high"), _f(1, "high", code_snippet="")]
    cfg = ValidateConfig(enable_l5=True, l5_model_override="test-model")
    result = validate(findings, config=cfg)
    assert _coverage_of(result.findings[1])["result"] == COVERAGE_SKIPPED_NO_WINDOW


def test_top_n_cut_is_marked_skipped_not_selected(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [_f(i, "high") for i in range(3)]
    l1 = [[] for _ in findings]
    out_states = run_l5(
        findings, l1,
        ValidateConfig(enable_l5=True, l5_model_override="test-model",
                       top_n_for_llm=1),
    )
    assert out_states is not None
    results = [_coverage_of(f)["result"] for f in findings]
    assert results.count(COVERAGE_JUDGED) == 1
    assert results.count(COVERAGE_SKIPPED_NOT_SELECTED) == 2


def test_suppressed_finding_is_marked_skipped_already_likely_fp(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [_f(0, "high")]
    l1 = [[ValidationCheck(id="suppression", result="nosec", weight=-0.2,
                           reason="operator suppression")]]
    run_l5(findings, l1,
           ValidateConfig(enable_l5=True, l5_model_override="test-model"))
    assert _coverage_of(findings[0])["result"] == COVERAGE_SKIPPED_ALREADY_LIKELY_FP


def test_error_stub_is_never_counted_judged(monkeypatch):
    """A judge that returned no verdict did NOT judge the finding. The L5
    summary already refuses to count error stubs as judged; the per-finding
    coverage check must tell the same truth."""
    def _broken(*a, **k):
        raise RuntimeError("judge unreachable")
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _broken)
    findings = [_f(0, "high")]
    run_l5(findings, [[]],
           ValidateConfig(enable_l5=True, l5_model_override="test-model"))
    assert _coverage_of(findings[0])["result"] == COVERAGE_JUDGE_ERROR


# ── AC32: the vocabulary is closed ────────────────────────────────────────


def test_every_coverage_result_is_enumerated(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [_f(0, "high"), _f(1, "high", code_snippet="  ")]
    cfg = ValidateConfig(enable_l5=True, l5_model_override="test-model")
    result = validate(findings, config=cfg)
    for f in result.findings:
        assert _coverage_of(f)["result"] in COVERAGE_RESULTS


def test_enumeration_is_exactly_the_stated_vocabulary():
    """The plan's five values plus the two dogfood-forced extensions.
    Anything new must be added HERE deliberately, with its rationale."""
    assert COVERAGE_RESULTS == frozenset({
        "judged",
        "skipped_no_window",
        "skipped_already_likely_fp",
        "skipped_budget_exhausted",
        "skipped_not_selected",
        "skipped_l5_disabled",
        "judge_error",
    })


# ── AC7 second half: coverage never blocks, never moves confidence ────────


def test_coverage_check_is_inert_in_the_voter():
    base = [
        ValidationCheck(id="path", result="promoted", weight=0.10,
                        reason="entry point"),
        ValidationCheck(id=OBLIGATION_ID, result=OBLIGATION_DISCHARGED,
                        weight=0.0, reason="searched, empty"),
    ]
    status_without, conf_without = vote(base)
    for cov_result in COVERAGE_RESULTS:
        cov = ValidationCheck(id=COVERAGE_ID, result=cov_result, weight=0.0,
                              reason="coverage")
        status_with, conf_with = vote(base + [cov])
        assert (status_with, conf_with) == (status_without, conf_without), (
            f"coverage result {cov_result!r} must never change a vote"
        )


def test_missing_l5_verdict_never_blocks_confirmation():
    """A finding the judge never saw can still confirm on other evidence."""
    checks = [
        ValidationCheck(id="path", result="promoted", weight=0.10,
                        reason="entry point"),
        ValidationCheck(id=COVERAGE_ID, result=COVERAGE_SKIPPED_L5_DISABLED,
                        weight=0.0, reason="L5 off"),
        ValidationCheck(id=OBLIGATION_ID, result=OBLIGATION_DISCHARGED,
                        weight=0.0, reason="searched, empty"),
    ]
    status, _ = vote(checks)
    assert status == "high_confidence"


# ── T6.2: the per-run summary names coverage by skip reason ────────────────


def test_run_summary_reports_coverage_breakdown(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [_f(0, "high"), _f(1, "high", code_snippet="")]
    cfg = ValidateConfig(enable_l5=True, l5_model_override="test-model")
    result = validate(findings, config=cfg)
    cov_lines = [t for t in result.event_texts if "L5 coverage" in t]
    assert len(cov_lines) == 1
    line = cov_lines[0]
    assert "judged=1" in line
    assert "skipped_no_window=1" in line


def test_run_summary_reports_coverage_when_l5_disabled():
    findings = [_f(0), _f(1)]
    result = validate(findings, config=ValidateConfig(enable_l5=False))
    cov_lines = [t for t in result.event_texts if "L5 coverage" in t]
    assert len(cov_lines) == 1
    assert "skipped_l5_disabled=2" in cov_lines[0]


def test_summary_breaks_down_by_provenance(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)
    findings = [
        _f(0, "high"),
        _f(1, "high", provenance="llm", check_id=None),
    ]
    cfg = ValidateConfig(enable_l5=True, l5_model_override="test-model")
    result = validate(findings, config=cfg)
    line = next(t for t in result.event_texts if "L5 coverage" in t)
    assert "llm" in line, "the summary must break coverage down by provenance"


# ── AC7 includes rollup PARENTS ────────────────────────────────────────────


def test_rollup_parents_carry_coverage_too():
    """Found by scanning Vulture with Vulture: 306 of 2095 result rows had no
    coverage check — every one an L2 rollup parent, which is synthesised
    after L1 and never passes through run_l5. Same gap class _ensure_obligation
    closed for obligations."""
    def member(line: int) -> dict:
        return {
            "id": f"m{line}", "category": "CWE-321",
            "title": "Hardcoded cryptographic key",
            "description": "d", "file_path": "/x/keys.ts",
            "line_start": line, "line_end": line, "severity": "critical",
            "code_snippet": f"{line}: key = 'x'", "check_id": "chk",
        }

    result = validate([member(21), member(42)],
                      config=ValidateConfig(enable_l5=False))
    assert result.rollups, "two same-shape members must produce a parent"
    for parent in result.rollups:
        cov = [c for c in parent.get("validation", {}).get("checks", [])
               if c.get("id") == COVERAGE_ID]
        assert len(cov) == 1, "rollup parents must carry coverage (AC7)"
        assert cov[0]["result"] == COVERAGE_SKIPPED_L5_DISABLED


def test_rollup_parents_coverage_when_l5_enabled(monkeypatch):
    monkeypatch.setattr("shared.validate.llm_judge._call_llm", _fake_verdicts)

    def member(line: int) -> dict:
        return {
            "id": f"m{line}", "category": "CWE-321",
            "title": "Hardcoded cryptographic key",
            "description": "d", "file_path": "/x/keys.ts",
            "line_start": line, "line_end": line, "severity": "critical",
            "code_snippet": f"{line}: key = 'x'", "check_id": "chk",
        }

    cfg = ValidateConfig(enable_l5=True, l5_model_override="test-model")
    result = validate([member(21), member(42)], config=cfg)
    for parent in result.rollups:
        cov = [c for c in parent.get("validation", {}).get("checks", [])
               if c.get("id") == COVERAGE_ID]
        assert len(cov) == 1
        assert cov[0]["result"] == COVERAGE_SKIPPED_NO_WINDOW


# ── coverage stamping must not disturb existing behaviour ─────────────────


def test_coverage_does_not_change_statuses(monkeypatch):
    """Byte-identical statuses with and without the coverage layer would be
    ideal; short of a flag to disable it, assert the L5-off validate() still
    produces the same statuses as before the feature (path seed only)."""
    findings = [_f(0, "high")]
    result = validate(findings, config=ValidateConfig(enable_l5=False))
    f = result.findings[0]
    assert f["validation_status"] in ("high_confidence", "suspicious")
    non_coverage = [c for c in f["validation"]["checks"]
                    if c["id"] != COVERAGE_ID]
    re_status, re_conf = vote([ValidationCheck.from_json(c)
                               for c in non_coverage])
    assert f["validation_status"] == re_status
    assert abs(f["validation_confidence"] - re_conf) < 1e-9
