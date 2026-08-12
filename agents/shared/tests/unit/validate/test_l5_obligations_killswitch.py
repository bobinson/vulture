"""Feature 0072 T1.10 — the VULTURE_L5_OBLIGATIONS=false kill switch.

The rollback plan promises a runtime valve that restores the pre-0072 vote —
no label withheld, no finding dismissed on an obligation — even under
enforce mode, without reverting to observe or shipping a new build. It was
never implemented; an operator reaching for it got a silent no-op. These
tests pin the contract.
"""

from __future__ import annotations

import pytest

from shared.validate import ValidateConfig, validate
from shared.validate.refutation import obligation_check, obligations_enabled
from shared.validate.voter import (
    OBLIGATION_DISCHARGED,
    OBLIGATION_REFUTED,
    OBLIGATION_UNKNOWN,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("VULTURE_L5_OBLIGATIONS", "VULTURE_OBLIGATION_MODE",
              "VULTURE_OBLIGATION_STRICT_SCOPE"):
        monkeypatch.delenv(k, raising=False)
    yield


def _finding(category: str, tmp_path) -> dict:
    src = tmp_path / "m.py"
    src.write_text("q = build(req.body.id)\ncur.execute(q)\n")
    return {
        "id": "f1", "category": category, "check_id": f"chk.{category}",
        "title": "t", "severity": "high",
        "file_path": str(src), "line_start": 2, "line_end": 2,
        "code_snippet": "2: cur.execute(q)",
    }


def _obligation(f: dict) -> dict:
    return next(c for c in f["validation"]["checks"] if c["id"] == "obligation")


# ── default: the switch is on, behaviour unchanged ─────────────────────────


def test_default_is_enabled():
    assert obligations_enabled() is True


def test_enforce_still_withholds_when_switch_on(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    # An undeclared class → obligation unknown → gate withholds under enforce.
    res = validate([_finding("CWE-99999", tmp_path)], config=ValidateConfig())
    ob = _obligation(res.findings[0])
    assert ob["result"] == OBLIGATION_UNKNOWN
    assert res.findings[0]["validation_status"] != "high_confidence"


# ── switch off: obligations never gate, even under enforce ─────────────────


def test_killswitch_forces_discharged_under_enforce(monkeypatch):
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    monkeypatch.setenv("VULTURE_L5_OBLIGATIONS", "false")
    assert obligations_enabled() is False
    # An undeclared class would be `unknown`; the kill switch emits discharged.
    c = obligation_check("CWE-99999", "no_map")
    assert c.result == OBLIGATION_DISCHARGED
    assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN  # truth recorded
    assert c.extras["enforced"] is False
    assert "VULTURE_L5_OBLIGATIONS=false" in c.reason


def test_killswitch_neutralises_a_refutation_under_enforce(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    monkeypatch.setenv("VULTURE_L5_OBLIGATIONS", "false")
    # A WIRING class that would refute stays discharged: no dismissal on an
    # obligation, the switch's second half of the promise.
    c = obligation_check("CWE-639", "absent")
    assert c.result == OBLIGATION_DISCHARGED
    assert c.extras["obligation_state"] in (
        OBLIGATION_UNKNOWN, OBLIGATION_DISCHARGED, OBLIGATION_REFUTED)


def test_killswitch_end_to_end_restores_confirmation(monkeypatch, tmp_path):
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    monkeypatch.setenv("VULTURE_L5_OBLIGATIONS", "false")
    # A finding that enforce would withhold (undeclared class → unknown) is
    # confirmable again with the switch off, if its other evidence supports it.
    f = _finding("CWE-99999", tmp_path)
    f["file_path"] = str(tmp_path / "backend" / "internal" / "handler" / "h.go")
    (tmp_path / "backend" / "internal" / "handler").mkdir(parents=True)
    (tmp_path / "backend" / "internal" / "handler" / "h.go").write_text(
        "q := build(id)\ndb.Query(q)\n")
    f["line_start"] = 2
    res = validate([f], config=ValidateConfig())
    ob = _obligation(res.findings[0])
    assert ob["result"] == OBLIGATION_DISCHARGED
    assert ob["extras"]["obligation_state"] == OBLIGATION_UNKNOWN


def test_switch_value_parsing(monkeypatch):
    for val, want in [("false", False), ("FALSE", False), ("False", False),
                      ("true", True), ("", True), ("0", True), ("no", True)]:
        monkeypatch.setenv("VULTURE_L5_OBLIGATIONS", val)
        assert obligations_enabled() is want, val
