"""Feature 0072 P7 — calibration gate (T7.1–T7.4) and P2 completion
(T2.1 migration, T2.4 forward search + memo keying, T2.6 stripping).
"""

from __future__ import annotations

import json

import pytest

from shared.validate import ValidateConfig, validate
from shared.validate.calibration import (
    RuleStats,
    evaluate_rules,
    reset_demoted_rules_cache,
    rule_is_demoted,
    rules_below_precision,
    scope_divergence,
)
from shared.validate.context_heuristics import (
    _sanitizer_check,
    _strip_comments_and_strings,
    clear_l1_cache,
)
from shared.validate.refutation import (
    REFUTATION_MAP,
    Evidence,
    Scope,
    obligation_check,
)
from shared.validate.voter import OBLIGATION_DISCHARGED, OBLIGATION_UNKNOWN


@pytest.fixture(autouse=True)
def _fresh_calibration(monkeypatch):
    monkeypatch.delenv("VULTURE_CALIBRATION_FILE", raising=False)
    reset_demoted_rules_cache()
    clear_l1_cache()
    yield
    reset_demoted_rules_cache()
    clear_l1_cache()


# ── T2.1: the legacy sanitizer classes are declared, unreviewed ────────────


def test_legacy_sanitizer_classes_are_migrated():
    for cwe in ("CWE-89", "CWE-79", "CWE-22", "CWE-20"):
        ref = REFUTATION_MAP.get(cwe)
        assert ref is not None, f"{cwe} must be declared (T2.1)"
        assert ref.evidence is Evidence.TEXTUAL
        assert ref.scope_reviewed is False, (
            "the legacy window was never chosen for the class; it must not "
            "enforce until reviewed (T2.1a / AC21)"
        )


def test_policy_declaration_wins_over_legacy_migration():
    """CWE-330 is in the legacy sanitizer map AND a policy class; the policy
    declaration (Scope.NONE, reviewed) must win."""
    ref = REFUTATION_MAP["CWE-330"]
    assert ref.scope is Scope.NONE
    assert ref.scope_reviewed is True


def test_migrated_class_discharges_after_search(tmp_path):
    src = tmp_path / "db.py"
    src.write_text("q = build()\ncur.execute(q)\n")
    c = obligation_check("CWE-89", "absent", file_path=str(src), line_start=2)
    assert c.extras["obligation_state"] == OBLIGATION_DISCHARGED
    assert c.extras["scope_declared"] == "file"
    assert c.extras["scope_actual"] == "window20_backward", (
        "the legacy window is what was actually searched; recording the "
        "declared scope here would hide exactly the divergence T7.4 alerts on"
    )


# ── T2.6 / AC17: comments and strings never match ──────────────────────────


def test_strip_removes_comments_and_string_contents():
    assert "sanitize" not in _strip_comments_and_strings("x = 1  # TODO sanitize")
    assert "sanitize" not in _strip_comments_and_strings('log("please sanitize")')
    assert "escape" not in _strip_comments_and_strings("// escape later")
    assert "execute" in _strip_comments_and_strings('cur.execute("SELECT 1")')


def test_sanitizer_ignores_mitigation_shaped_comment(tmp_path):
    """AC11/AC17's L1 half: `sanitize` in a comment near a finding must not
    read as a mitigation search hit."""
    src = tmp_path / "a.py"
    src.write_text("\n".join([
        "# we should really sanitize this input",   # comment only
        "q = 'SELECT * FROM t WHERE id=' + uid",
        "cur.execute(q)",
    ]))
    c = _sanitizer_check(str(src), 3, "CWE-20")
    assert c.result == "absent", (
        f"a comment token must not discharge the search (got {c.result})"
    )


def test_sanitizer_still_matches_real_code(tmp_path):
    src = tmp_path / "a.py"
    src.write_text("\n".join([
        "data = validate(payload)",
        "q = build(data)",
        "cur.execute(q)",
    ]))
    c = _sanitizer_check(str(src), 3, "CWE-20")
    assert c.result == "matched"
    assert c.extras["scope_searched"] == "window20_backward"


# ── T2.4 / AC25: extent-keyed memo, forward search for reviewed FILE scope ─


def test_memo_distinguishes_extents(tmp_path):
    from shared.validate.context_heuristics import _scan_for_sanitizer
    src = tmp_path / "two_funcs.py"
    src.write_text("\n".join([
        "def a(x):",
        "    return validate(x)",     # hit at line 2
        "",
        "def b(y):",
        "    return y + 1",           # no hit in 4..5
    ]))
    hit_a = _scan_for_sanitizer(str(src), "CWE-20", 0, 2)
    hit_b = _scan_for_sanitizer(str(src), "CWE-20", 3, 5)
    assert hit_a == 2
    assert hit_b == 0, "two extents of one file must get their own answers"


def test_reviewed_file_scope_searches_forward(tmp_path, monkeypatch):
    """A guard AFTER the sink is invisible to the backward window; once a
    FILE-scope class is reviewed, the search must see it (B1)."""
    monkeypatch.setitem(
        REFUTATION_MAP, "CWE-20",
        REFUTATION_MAP["CWE-20"].__class__(
            scope=Scope.FILE, evidence=Evidence.TEXTUAL,
            scope_reviewed=True, degradable=True),
    )
    clear_l1_cache()
    src = tmp_path / "fwd.py"
    src.write_text("\n".join([
        "q = build(payload)",
        "cur.execute(q)",              # finding here, line 2
        "def helper(p):",
        "    return validate(p)",      # mitigation AFTER the sink
    ]))
    c = _sanitizer_check(str(src), 2, "CWE-20")
    assert c.result == "matched"
    assert c.extras["scope_searched"] == "file"


# ── T7.1 / T7.3: per-rule measurement ──────────────────────────────────────


def _labelled(rule: str, status: str, is_real: bool) -> tuple[dict, bool]:
    return ({"check_id": rule, "validation_status": status}, is_real)


def test_evaluate_rules_precision_and_recall_guard():
    stats = evaluate_rules([
        _labelled("r1", "high_confidence", True),
        _labelled("r1", "high_confidence", False),
        _labelled("r1", "suspicious", True),
        _labelled("r1", "likely_fp", True),      # dismissed true positive!
        _labelled("r2", "suspicious", False),
    ])
    r1 = stats["r1"]
    assert r1.confirmed == 2
    assert r1.confirmed_precision == 0.5
    assert r1.dismissed_true_positives == 1
    assert r1.surviving_recall == pytest.approx(1 - 1 / 3)
    assert stats["r2"].confirmed_precision is None


def test_rules_below_precision_respects_min_findings():
    stats = {
        "small": RuleStats(rule="small", confirmed=1, confirmed_true=0),
        "bad": RuleStats(rule="bad", confirmed=10, confirmed_true=3),
        "good": RuleStats(rule="good", confirmed=10, confirmed_true=9),
    }
    demoted = rules_below_precision(stats, threshold=0.8)
    assert demoted == {"bad"}, "one bad sample must not demote a rule"


# ── T7.2: a demoted rule is candidate-only, via the existing gate ──────────


def test_demoted_rule_obligation_is_unknown(tmp_path, monkeypatch):
    calib = tmp_path / "calibration.json"
    calib.write_text(json.dumps({"demoted_rules": ["noisy-rule"]}))
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    reset_demoted_rules_cache()
    assert rule_is_demoted("noisy-rule")

    c = obligation_check("CWE-798", "skipped", check_id="noisy-rule")
    assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN
    assert "calibration" in c.reason

    ok = obligation_check("CWE-798", "skipped", check_id="fine-rule")
    assert ok.extras["obligation_state"] == OBLIGATION_DISCHARGED


def test_demoted_rule_cannot_confirm_under_enforcement(tmp_path, monkeypatch):
    calib = tmp_path / "calibration.json"
    calib.write_text(json.dumps({"demoted_rules": ["noisy-rule"]}))
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    reset_demoted_rules_cache()

    src = tmp_path / "main.py"
    src.write_text("password = 'hunter2'\n")
    finding = {
        "id": "f1", "category": "CWE-798", "check_id": "noisy-rule",
        "title": "hardcoded secret", "severity": "high",
        "file_path": str(src), "line_start": 1, "line_end": 1,
        "code_snippet": "1: password = 'hunter2'",
    }
    res = validate([finding], config=ValidateConfig(), audit_id="cal-1")
    assert res.findings[0]["validation_status"] != "high_confidence"


def test_broken_calibration_file_fails_open(tmp_path, monkeypatch):
    calib = tmp_path / "calibration.json"
    calib.write_text("{not json")
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    reset_demoted_rules_cache()
    assert rule_is_demoted("any-rule") is False, (
        "a typo in the calibration file must not demote every rule"
    )


def test_transient_read_failure_self_heals(tmp_path, monkeypatch):
    """A momentarily-unreadable file (NFS blip / mid-write) must not disable
    demotion for the whole process — the empty result must not be cached."""
    calib = tmp_path / "calibration.json"
    calib.write_text("{not json yet")           # malformed on first read
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    reset_demoted_rules_cache()
    assert rule_is_demoted("r1") is False        # failed load, NOT cached
    calib.write_text(json.dumps({"demoted_rules": ["r1"]}))  # file becomes good
    assert rule_is_demoted("r1") is True, "demotion must self-heal after the fix"


def test_demotion_keyed_by_category_when_no_check_id(tmp_path, monkeypatch):
    """The measurement side keys a rule as check_id OR category; a finding with
    no check_id is written under its category, so enforcement must match on
    category too (else the two halves of the loop disagree)."""
    calib = tmp_path / "calibration.json"
    calib.write_text(json.dumps({"demoted_rules": ["CWE-777"]}))
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    reset_demoted_rules_cache()
    c = obligation_check("CWE-777", "skipped", check_id="")   # no check_id
    assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN
    assert c.extras["enforced"] is True


def test_demoted_rule_enforces_even_when_scope_unreviewed(tmp_path, monkeypatch):
    """A demoted LEGACY class (scope_reviewed=False) must still gate under
    enforce: imprecision is orthogonal to scope review, so the demotion must
    not wait on the per-class review flip."""
    calib = tmp_path / "calibration.json"
    calib.write_text(json.dumps({"demoted_rules": ["cwe.injection.sqli"]}))
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    reset_demoted_rules_cache()
    # CWE-89 is a migrated legacy class: scope_reviewed=False, so absent the
    # demotion it would discharge on a search. Demoted, it must gate.
    assert REFUTATION_MAP["CWE-89"].scope_reviewed is False
    c = obligation_check("CWE-89", "absent", check_id="cwe.injection.sqli")
    assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN
    assert c.extras["enforced"] is True
    assert c.result == OBLIGATION_UNKNOWN


def test_demotion_is_inert_in_observe_mode(tmp_path, monkeypatch):
    """AC22: observe changes no status, demotion included."""
    calib = tmp_path / "calibration.json"
    calib.write_text(json.dumps({"demoted_rules": ["noisy"]}))
    monkeypatch.setenv("VULTURE_CALIBRATION_FILE", str(calib))
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "observe")
    reset_demoted_rules_cache()
    c = obligation_check("CWE-89", "absent", check_id="noisy")
    assert c.result == OBLIGATION_DISCHARGED           # neutralised
    assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN  # truth recorded
    assert c.extras["enforced"] is False


# ── T7.4: scope divergence alert ───────────────────────────────────────────


def _f_with_scopes(rule: str, declared, actual) -> dict:
    return {
        "check_id": rule,
        "validation": {"checks": [{
            "id": "obligation", "result": "discharged", "weight": 0.0,
            "extras": {"scope_declared": declared, "scope_actual": actual},
        }]},
    }


def test_scope_divergence_flags_material_rules():
    findings = (
        [_f_with_scopes("r1", "file", "window20_backward")] * 3
        + [_f_with_scopes("r1", "file", "file")]
        + [_f_with_scopes("r2", "wiring", "wiring")] * 4
    )
    alerts = scope_divergence(findings, material_share=0.25)
    assert "r1" in alerts and alerts["r1"] == 0.75
    assert "r2" not in alerts


def test_scope_divergence_ignores_unsearched():
    findings = [_f_with_scopes("r3", None, None)] * 5
    assert scope_divergence(findings) == {}
