"""Feature 0072 P2 — the refutation contract and the obligation emitter."""

from __future__ import annotations

import pytest

from shared.validate.refutation import (
    MAX_VERDICT,
    POLICY_CLASSES,
    REFUTATION_MAP,
    Evidence,
    Scope,
    obligation_check,
    obligation_mode,
)
from shared.validate.voter import (
    OBLIGATION_DISCHARGED,
    OBLIGATION_ID,
    OBLIGATION_UNKNOWN,
)


@pytest.fixture(autouse=True)
def _enforce(monkeypatch):
    """Most cases assert the ENFORCING behaviour; observe mode is tested apart."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")


# ── the default is observe, and observe changes nothing ───────────────────

def test_default_mode_is_observe(monkeypatch):
    monkeypatch.delenv("VULTURE_OBLIGATION_MODE", raising=False)
    assert obligation_mode() == "observe"


def test_observe_mode_never_blocks(monkeypatch):
    """The gate ships off: an unmapped class records unknown but discharges."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "observe")
    c = obligation_check("CWE-99999", "no_map")
    assert c.result == OBLIGATION_DISCHARGED
    assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN, "the truth is recorded"
    assert c.extras["enforced"] is False


def test_unknown_mode_value_falls_back_to_observe(monkeypatch):
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "banana")
    assert obligation_mode() == "observe"


# ── the highest-value rule: no declaration means never checked ────────────

def test_class_with_no_refutation_set_is_unknown():
    c = obligation_check("CWE-99999", "absent")
    assert c.id == OBLIGATION_ID
    assert c.result == OBLIGATION_UNKNOWN
    assert "no refutation set" in c.reason


# ── the five-to-three mapping ─────────────────────────────────────────────

@pytest.mark.parametrize("sanitizer_result,expected", [
    ("matched", OBLIGATION_DISCHARGED),
    ("absent", OBLIGATION_DISCHARGED),
    ("no_map", OBLIGATION_UNKNOWN),
    ("no_file", OBLIGATION_UNKNOWN),
    ("skipped", OBLIGATION_UNKNOWN),
    (None, OBLIGATION_UNKNOWN),
])
def test_sanitizer_state_maps_onto_the_three_states(sanitizer_result, expected):
    # CWE-639 is declared and reviewed, so the mapping is what decides.
    c = obligation_check("CWE-639", sanitizer_result)
    assert c.result == expected


def test_a_textual_match_discharges_but_never_refutes():
    """The safety property: a regex match may support an obligation, never
    remove a finding. A word-level pattern hitting a comment must not delete a
    real vulnerability."""
    assert MAX_VERDICT[Evidence.TEXTUAL] == OBLIGATION_DISCHARGED
    c = obligation_check("CWE-639", "matched")
    assert c.result == OBLIGATION_DISCHARGED
    assert c.result != "refuted"


# ── policy classes ────────────────────────────────────────────────────────

def test_policy_class_discharges_without_a_search():
    """A hardcoded secret has nothing to refute; the no-declaration rule must
    not demote an entire deterministic tier."""
    c = obligation_check("CWE-798", "skipped")
    assert c.result == OBLIGATION_DISCHARGED


def test_every_policy_class_is_declared_scope_none():
    for cwe in POLICY_CLASSES:
        assert REFUTATION_MAP[cwe].scope is Scope.NONE


def test_scope_none_is_bounded_to_the_allowlist():
    """Unbounded, Scope.NONE is a one-line bypass of the whole gate."""
    declared_none = {k for k, v in REFUTATION_MAP.items() if v.scope is Scope.NONE}
    assert declared_none <= POLICY_CLASSES, (
        f"classes declaring Scope.NONE outside the allowlist: "
        f"{sorted(declared_none - POLICY_CLASSES)}"
    )


# ── degradation is per class ──────────────────────────────────────────────

def test_authorization_classes_may_not_degrade():
    """Discharging an authz obligation at a narrower scope because no route
    resolver exists would re-open the exact class this feature closes."""
    for cwe in ("CWE-639", "CWE-566", "CWE-862", "CWE-863"):
        assert REFUTATION_MAP[cwe].degradable is False
        assert REFUTATION_MAP[cwe].scope is Scope.WIRING


def test_non_degradable_class_is_unknown_when_its_scope_is_unavailable():
    c = obligation_check("CWE-639", "absent", scope_available=False)
    assert c.result == OBLIGATION_UNKNOWN
    assert "may not degrade" in c.reason


def test_strict_scope_makes_even_degradable_classes_block(monkeypatch):
    monkeypatch.setenv("VULTURE_OBLIGATION_STRICT_SCOPE", "true")
    REFUTATION_MAP["CWE-TEST-DEGRADABLE"] = REFUTATION_MAP["CWE-639"].__class__(
        scope=Scope.FILE, evidence=Evidence.TEXTUAL,
        scope_reviewed=True, degradable=True)
    try:
        c = obligation_check("CWE-TEST-DEGRADABLE", "absent", scope_available=False)
        assert c.result == OBLIGATION_UNKNOWN
    finally:
        del REFUTATION_MAP["CWE-TEST-DEGRADABLE"]


# ── enforcement is per class, gated on a reviewed scope ───────────────────

def test_unreviewed_scope_is_not_enforced():
    """Legacy entries migrate unreviewed, so they behave exactly as before."""
    REFUTATION_MAP["CWE-TEST-UNREVIEWED"] = REFUTATION_MAP["CWE-639"].__class__(
        scope=Scope.FILE, evidence=Evidence.TEXTUAL, scope_reviewed=False)
    try:
        c = obligation_check("CWE-TEST-UNREVIEWED", "no_map")
        assert c.result == OBLIGATION_DISCHARGED, "unreviewed classes must not block"
        assert c.extras["obligation_state"] == OBLIGATION_UNKNOWN
    finally:
        del REFUTATION_MAP["CWE-TEST-UNREVIEWED"]


def test_obligation_check_carries_its_provenance():
    c = obligation_check("CWE-639", "no_map")
    assert c.extras["scope_declared"] == "wiring"
    assert c.extras["evidence"] == "structural"
    assert c.extras["category"] == "CWE-639"
    assert c.weight == 0.0, "an obligation never moves confidence"


def test_rollup_parents_carry_an_obligation():
    """A rollup parent is appended to the result AFTER validate() returns, so it
    never reaches the voter. Without an obligation stamped at construction it is
    indistinguishable — to the gate — from a finding whose obligation was
    discharged, and would confirm freely under enforcement.

    Found by scanning Vulture with Vulture: exactly the 300 `catalog_rollup`
    findings of a 1775-finding self-scan carried no obligation.
    """
    from shared.validate.rollup import _build_rollup_parent

    parent = _build_rollup_parent(
        audit_id="a-1", category="CWE-99999", file_path="/x/y.ts",
        members=[{"id": "m1", "severity": "high", "title": "t", "line_start": 1}],
        instance_count=3,
    )
    checks = parent["validation"]["checks"]
    assert any(c["id"] == OBLIGATION_ID for c in checks), (
        "a rollup parent must carry an obligation like any other finding"
    )


# ── predicate semantics: which field decides, and when the argument holds ──

@pytest.mark.parametrize("line,fields,disjunctive", [
    # Only the field inside the predicate counts. Refuting on `body.balance`
    # would discharge an obligation the middleware never satisfied.
    ("Wallet.increment({ balance: req.body.balance }, "
     "{ where: { UserId: req.body.UserId } })", ["body.UserId"], False),
    # A conjunction of two request fields: BOTH are collected, and one
    # server-derived term is enough to scope the query.
    ("Address.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })",
     ["params.id", "body.UserId"], False),
    # No predicate keyword at all — the whole line is used, because a rule may
    # flag the assignment rather than the query.
    ("const owner = req.body.UserId", ["body.UserId"], False),
    # A predicate keyword with no request field after it falls back to the line.
    ("Model.findAll({ where: { id } }) // keyed on req.params.id",
     ["params.id"], False),
    # Disjunctions, in the three shapes they take.
    ("Model.findOne({ where: { [Op.or]: [{ id: req.params.id }, "
     "{ UserId: req.body.UserId }] } })", ["params.id", "body.UserId"], True),
    ("db.find({ where: { $or: [{ id: req.params.id }] } })", ["params.id"], True),
    ("Model.findOne({ where: { id: req.params.id || req.body.UserId } })",
     ["params.id", "body.UserId"], True),
])
def test_predicate_fields_and_disjunctivity(line, fields, disjunctive):
    from shared.validate.refutation import _predicate_fields

    got_fields, got_disjunctive = _predicate_fields(line)
    assert got_fields == fields
    assert got_disjunctive is disjunctive


def test_a_disjunctive_predicate_is_never_refuted(tmp_path):
    """A conjunctive predicate is scoped as tightly as its tightest term, which
    is what licenses refuting on one server-derived field. `[Op.or]` matches a
    row satisfying EITHER term, so the argument collapses and the query really is
    exploitable. Refuting here would delete a real vulnerability — the one
    direction this feature must never introduce.
    """
    from shared.validate.refutation import clear_route_model_cache

    (tmp_path / "middleware").mkdir()
    (tmp_path / "middleware" / "auth.ts").write_text(
        "export const authContext = () => (req, res, next) => {\n"
        "  req.body.ownerId = subjectOf(tokenFrom(req))\n"
        "  next()\n"
        "}\n"
    )
    (tmp_path / "handler.ts").write_text(
        "export function get() {\n"
        "  return async (req, res) => {\n"
        "    await Model.findOne({ where: { [Op.or]: [{ id: req.params.id }, "
        "{ ownerId: req.body.ownerId }] } })\n"
        "  }\n"
        "}\n"
    )
    (tmp_path / "routes.ts").write_text(
        "import { authContext } from './middleware/auth'\n"
        "import { get } from './handler'\n"
        "export function build(app) {\n"
        "  app.get('/thing/:id', authContext(), get())\n"
        "}\n"
    )
    clear_route_model_cache()
    try:
        c = obligation_check(
            "CWE-639", "absent", file_path=str(tmp_path / "handler.ts"),
            line_start=3, source_root=str(tmp_path), scope_available=True)
        assert c.result != "refuted", (
            f"a disjunctive predicate was refuted: {c.reason}")
    finally:
        clear_route_model_cache()
