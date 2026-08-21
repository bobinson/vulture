"""Feature 0072 — the gate end to end through the real validate() entry point.

Unit tests cover the voter and the emitter in isolation. These drive the whole
pipeline the way an agent does, because the defect this feature fixes lived in
the seam between layers, not inside any one of them.
"""

from __future__ import annotations

import pytest

from shared.validate import ValidateConfig, validate


def _finding(path: str, category: str, line: int = 4) -> dict:
    return {
        "id": f"f-{category}-{line}",
        "title": f"{category} finding",
        "file_path": path,
        "line_start": line,
        "category": category,
        "severity": "high",
        "provenance": "skill",
        "check_id": "cwe.test.rule",
        "code_snippet": "1: x\n2: y\n3: z",
    }


@pytest.fixture
def source(tmp_path):
    f = tmp_path / "handler.ts"
    f.write_text(
        "function update(req) {\n"
        "  const id = req.body.ownerId\n"
        "  // no mitigation in this window\n"
        "  db.update({ where: { ownerId: id } })\n"
        "}\n"
    )
    return str(f)


def _cfg() -> ValidateConfig:
    # L1 + L2 only: L5 needs a model, and the gate is decided before it.
    return ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=False)


def _obligation(finding: dict) -> dict | None:
    return next(
        (c for c in finding["validation"]["checks"] if c["id"] == "obligation"),
        None,
    )


def test_observe_mode_records_the_obligation_without_changing_status(
    source, monkeypatch
):
    """The gate ships OFF. An unmapped class is recorded as unknown but the
    status is whatever it would have been before 0072."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "observe")
    res = validate([_finding(source, "CWE-99999")], config=_cfg(), audit_id="a1")
    f = res.findings[0]

    ob = _obligation(f)
    assert ob is not None, "an obligation must be recorded even in observe mode"
    assert ob["extras"]["obligation_state"] == "unknown"
    assert ob["result"] == "discharged", "observe mode must not block"
    assert ob["extras"]["enforced"] is False


def test_enforce_mode_withholds_the_label_for_an_undeclared_class(
    source, monkeypatch
):
    """The feature's highest-value rule: a class with no declared refutation set
    may never be confirmed."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    res = validate([_finding(source, "CWE-99999")], config=_cfg(), audit_id="a2")
    f = res.findings[0]

    assert _obligation(f)["result"] == "unknown"
    assert f["validation_status"] != "high_confidence"


def test_enforce_mode_blocks_an_authorization_finding_with_no_route_model(
    source, monkeypatch
):
    """The motivating class. CWE-639's mitigation lives at WIRING scope and no
    resolver exists yet, and the class is non-degradable — so it must stay
    unknown rather than discharge at a narrower scope. An earlier design
    discharged here, which re-opened the very false positives this closes."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    res = validate([_finding(source, "CWE-639")], config=_cfg(), audit_id="a3")
    f = res.findings[0]

    ob = _obligation(f)
    assert ob["result"] == "unknown"
    assert "may not degrade" in ob["reason"]
    assert f["validation_status"] != "high_confidence"


def test_policy_class_still_confirms_under_enforcement(source, monkeypatch):
    """A hardcoded secret has nothing to refute. The no-declaration rule must
    not demote an entire deterministic tier."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    res = validate([_finding(source, "CWE-798")], config=_cfg(), audit_id="a4")
    f = res.findings[0]

    assert _obligation(f)["result"] == "discharged"


def test_confidence_is_preserved_when_the_label_is_withheld(source, monkeypatch):
    """The gate withholds a label; it never re-scores. Triage keeps the signal."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "observe")
    observed = validate([_finding(source, "CWE-639")], config=_cfg(), audit_id="a5")
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    enforced = validate([_finding(source, "CWE-639")], config=_cfg(), audit_id="a6")

    assert (
        observed.findings[0]["validation_confidence"]
        == enforced.findings[0]["validation_confidence"]
    )


def test_validate_remains_length_preserving(source, monkeypatch):
    """V6: the validate stage annotates, it never adds or removes findings."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    findings = [
        _finding(source, "CWE-639"),
        _finding(source, "CWE-798", line=2),
        _finding(source, "CWE-99999", line=3),
    ]
    res = validate(findings, config=_cfg(), audit_id="a7")
    assert len(res.findings) == len(findings)


def test_every_finding_carries_an_obligation(source, monkeypatch):
    """Coverage is not optional: a finding with no obligation check would be
    indistinguishable from one whose obligation was discharged."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    findings = [_finding(source, c) for c in ("CWE-639", "CWE-798", "CWE-89")]
    res = validate(findings, config=_cfg(), audit_id="a8")
    for f in res.findings:
        assert _obligation(f) is not None, f"{f['category']} carries no obligation"


def test_a_finding_that_bypasses_L1_still_carries_an_obligation(source, monkeypatch):
    """Regression: L2 rollup PARENTS are synthesised after L1, so they never
    pass through run_l1 and arrived with an empty check list. A finding with no
    obligation check is indistinguishable — to the gate — from one whose
    obligation was discharged, so under enforcement they confirmed freely.

    Found by scanning Vulture with Vulture on the live install: 2 of 7 persisted
    findings carried no obligation, both `provenance=catalog_rollup`. Every unit
    test had reached the voter through run_l1 and so could not see it.
    """
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")

    # A finding L1 cannot process: no resolvable line, as a rollup parent has.
    orphan = _finding(source, "CWE-99999")
    orphan["line_start"] = 0
    orphan["provenance"] = "catalog_rollup"

    res = validate([orphan], config=_cfg(), audit_id="a9")
    f = res.findings[0]

    ob = _obligation(f)
    assert ob is not None, "every finding must carry an obligation check"
    assert ob["result"] == "unknown"
    assert f["validation_status"] != "high_confidence"


# ── P3a: WIRING refutation end to end through validate() ──────────────────

_MW = (
    "export const authContext = () => (req, res, next) => {\n"
    "  req.body.ownerId = subjectOf(tokenFrom(req))\n"
    "  next()\n"
    "}\n"
)
_HANDLER = (
    "export function update() {\n"
    "  return async (req, res) => {\n"
    "    await Model.update({ v: req.body.v }, "
    "{ where: { ownerId: req.body.ownerId } })\n"
    "  }\n"
    "}\n"
)


def _wired_tree(tmp_path, mount: str):
    (tmp_path / "middleware").mkdir()
    (tmp_path / "middleware" / "auth.ts").write_text(_MW)
    (tmp_path / "handler.ts").write_text(_HANDLER)
    (tmp_path / "routes.ts").write_text(
        "import { authContext } from './middleware/auth'\n"
        "import { update } from './handler'\n"
        f"export function build(app) {{\n{mount}\n}}\n"
    )
    return str(tmp_path / "handler.ts")


@pytest.fixture(autouse=True)
def _fresh_route_model():
    """The model is cached per source root; tmp_path differs per test, but a
    stale entry would still mask a regression."""
    from shared.validate.refutation import clear_route_model_cache
    clear_route_model_cache()
    yield
    clear_route_model_cache()


def test_a_guarded_mount_dismisses_the_finding(tmp_path, monkeypatch):
    """The false positive. Every route mounting this handler writes the keyed
    field from the token, so the query is correctly scoped and the finding is
    refuted — the only verdict that removes a finding rather than withholding a
    label."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    handler = _wired_tree(
        tmp_path, "  app.put('/thing/:id', authContext(), update())")

    res = validate([_finding(handler, "CWE-639", line=3)], config=_cfg(),
                   source_path=str(tmp_path), audit_id="p3a-1")
    f = res.findings[0]

    assert _obligation(f)["result"] == "refuted"
    assert f["validation_status"] == "likely_fp"


def test_an_unguarded_mount_keeps_the_finding(tmp_path, monkeypatch):
    """The true positive. Identical handler body, different wiring, opposite
    correct verdict — a rule that cannot tell these apart is worthless."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    handler = _wired_tree(tmp_path, "  app.put('/thing/:id', update())")

    res = validate([_finding(handler, "CWE-639", line=3)], config=_cfg(),
                   source_path=str(tmp_path), audit_id="p3a-2")
    f = res.findings[0]

    assert _obligation(f)["result"] != "refuted"
    assert f["validation_status"] != "likely_fp"


def test_one_unguarded_mount_among_many_keeps_the_finding(tmp_path, monkeypatch):
    """EVERY mounting route must carry the mitigation. Reachable through one
    unguarded route means exploitable, and refuting here would delete a real
    vulnerability."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    handler = _wired_tree(
        tmp_path,
        "  app.put('/thing/:id', authContext(), update())\n"
        "  app.patch('/legacy/thing/:id', update())")

    res = validate([_finding(handler, "CWE-639", line=3)], config=_cfg(),
                   source_path=str(tmp_path), audit_id="p3a-3")

    assert res.findings[0]["validation_status"] != "likely_fp"


def test_without_a_source_root_nothing_is_refuted(tmp_path, monkeypatch):
    """No source root means no route model, so an authorization obligation can
    only be `unknown`. It must never silently discharge — and never refute."""
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "enforce")
    handler = _wired_tree(
        tmp_path, "  app.put('/thing/:id', authContext(), update())")

    res = validate([_finding(handler, "CWE-639", line=3)], config=_cfg(),
                   audit_id="p3a-4")
    f = res.findings[0]

    assert _obligation(f)["result"] == "unknown"
    assert f["validation_status"] != "high_confidence"


def test_observe_mode_does_not_dismiss_a_refutable_finding(tmp_path, monkeypatch):
    """AC22: the shipping default must change no status — in EITHER direction.

    The observe-mode neutraliser originally handled only `unknown`, the state
    that withholds a label. `refuted` DISMISSES a finding, so letting it through
    unenforced would mean the default configuration silently moved findings to
    `likely_fp`. "Off by default" has to mean off in the finding-removing
    direction above all.
    """
    monkeypatch.setenv("VULTURE_OBLIGATION_MODE", "observe")
    handler = _wired_tree(
        tmp_path, "  app.put('/thing/:id', authContext(), update())")

    res = validate([_finding(handler, "CWE-639", line=3)], config=_cfg(),
                   source_path=str(tmp_path), audit_id="p3a-observe")
    f = res.findings[0]
    ob = _obligation(f)

    assert ob["result"] == "discharged", "observe mode must not dismiss"
    assert ob["extras"]["obligation_state"] == "refuted", "the truth is recorded"
    assert f["validation_status"] != "likely_fp"


# ── L5 coverage must be reported honestly ─────────────────────────────────

def _l5_summary(texts: list[str]) -> str:
    return next(t for t in texts if t.startswith("[validate] L5 done"))


def test_error_stubs_are_not_counted_as_judged(monkeypatch, source):
    """A dead judge must not read as a working one.

    Live-observed: an LM Studio model that failed to load 400'd every call, so
    every finding got an `llm_judge` check with `result="error"` and the summary
    still said "680 finding(s) judged". An operator reading that believes the
    layer filtered false positives when it examined nothing.

    This is 0072's own thesis applied to the layer itself: "we never checked"
    must not be presentable as "we checked and it was clean".
    """
    from shared.validate import _run_l5_phase

    findings = [
        {"id": "a", "validation": {"checks": [
            {"id": "llm_judge", "result": "error", "reason": "no verdict"}]}},
        {"id": "b", "validation": {"checks": [
            {"id": "llm_judge", "result": "real_bug", "weight": 0.3}]}},
        {"id": "c", "validation": {"checks": [{"id": "path", "result": "ok"}]}},
    ]
    texts: list[str] = []
    monkeypatch.setattr("shared.validate.run_l5", lambda *a, **k: None)
    _run_l5_phase(findings, [], ValidateConfig(enable_l5=True), "aid",
                  None, texts, [], {})

    summary = _l5_summary(texts)
    assert "1 finding(s) judged" in summary, summary
    assert "1 returned no verdict" in summary, summary


def test_a_wholly_dead_judge_says_so(monkeypatch):
    """Zero real verdicts is the case an operator most needs told."""
    from shared.validate import _run_l5_phase

    findings = [{"id": str(i), "validation": {"checks": [
        {"id": "llm_judge", "result": "error", "reason": "no verdict"}]}}
        for i in range(3)]
    texts: list[str] = []
    monkeypatch.setattr("shared.validate.run_l5", lambda *a, **k: None)
    _run_l5_phase(findings, [], ValidateConfig(enable_l5=True), "aid",
                  None, texts, [], {})

    summary = _l5_summary(texts)
    assert "0 finding(s) judged" in summary, summary
    assert "CONTRIBUTED NOTHING" in summary, summary
