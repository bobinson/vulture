"""Feature 0074 P-1 (T-1.1) — business contract: a model-authored ``check_id``
never makes an LLM-family finding deterministic (AC33).

The hazard (D1b). The LLM tier may author a ``check_id``. The parse gate keeps
it, ``_restore_dedup_identity`` publishes it so an LLM duplicate still collapses
onto its skill twin, and the L5 judge, on a surviving verdict, re-tags the row
``provenance="llm_l5_verified"``. ``_is_deterministic`` keyed on
``provenance == "llm"`` exactly, so after the re-tag the row satisfied
"has a check_id and is not 'llm'" and was promoted to the AUTHORITATIVE tier:
the judge's own later demotion was then neutralised as
``deterministic_authoritative``. A model guess bought itself demotion immunity.

The contract (owner decision O1, option a): any provenance whose
``strip().lower()`` starts with ``llm`` is LLM-family and never deterministic —
the rule the Go backend already applies (``isLLMProvenance``). A skill row
carrying a ``check_id`` stays deterministic and keeps its exemption.

Fully offline: the LLM phase is the ``FakeLLMProvider`` seam and the judge is
``patch_l5_judge`` (tests/_fake_llm.py). No model is called.
"""

from __future__ import annotations

import pytest

from tests._fake_llm import (
    FakeLLMProvider,
    fake_finding,
    install_fake_runner,
    patch_l5_judge,
)
from tests.support.agent_run import DUMMY_TOOLS, result_findings
from tests.support.llm_family import llm_family_variants

# Every spelling Go's isLLMProvenance calls LLM-authored, read from the fixture
# both languages share. "llm" was always handled; the rest are the D1b surface.
LLM_FAMILY_VARIANTS = llm_family_variants()

_MODEL_CHECK_ID = "model.invented.sqli"
_SKILL_CHECK_ID = "cwe.injection.sql"
_SOURCE_LINES = "import db\n\ndef login(uid):\n    return db.execute('SELECT * FROM u WHERE id=' + uid)\n"
_SNIPPET = "4:     return db.execute('SELECT * FROM u WHERE id=' + uid)"
JUDGE_PATHS = (False, True)  # validate() without / with a source root
JUDGE_PATH_IDS = ("tool_free", "source_root")
_DEMOTING = 0.0     # exploitable probability the stub judge returns to demote
_CONFIRMING = 0.95  # ... and to confirm


@pytest.fixture(autouse=True)
def _no_l5_cache(monkeypatch):
    """No L5 verdict cache (env and cache-path isolation are the conftest's).

    Switched off outright rather than left on its fresh per-test file: one
    test here judges the SAME code twice with two different stub verdicts, and
    a cached first verdict would answer the second call without reaching the
    stub.
    """
    from shared.validate import l5_cache

    monkeypatch.setattr(l5_cache, "_DISABLED", True)


# ── helpers ─────────────────────────────────────────────────────────────────

def _source(tmp_path) -> str:
    target = tmp_path / "app" / "auth.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_SOURCE_LINES)
    return str(tmp_path)


def _llm_row_from_a_real_run(tmp_path, monkeypatch) -> dict:
    """Run the combined audit with a model that authors a ``check_id``; return
    the emitted LLM row exactly as the result snapshot carries it."""
    from shared.audit_runner import run_combined_audit

    src = _source(tmp_path)
    install_fake_runner(monkeypatch, FakeLLMProvider(scripted=[fake_finding(
        title="SQL injection in login", category="CWE-89",
        file_path="app/auth.py", line_start=4, line_end=4,
        check_id=_MODEL_CHECK_ID,
    )]))
    events = list(run_combined_audit(
        run_id="d1b", source_path=src, categories=["x"],
        skill_map={"x": lambda _p: {"findings": []}},
        skill_tools=DUMMY_TOOLS, instructions="audit",
        model="gpt-4o", use_llm=True,
        validate_use_llm=False,  # the judge runs below, stubbed, never in-run
    ))
    rows = [f for f in result_findings(events) if f.get("title") == "SQL injection in login"]
    assert len(rows) == 1, f"the scripted LLM row must reach the result; got {rows!r}"
    return rows[0]


def _judgeable(row: dict, fid: str, tmp_path) -> dict:
    """The row as the validate layer receives it: an id the stub judge echoes,
    a real code window (L5 skips blind rows), no prior validation blob."""
    fresh = {k: v for k, v in row.items() if not k.startswith("validation")}
    fresh.update(id=fid, file_path=str(tmp_path / "app" / "auth.py"),
                 line_start=4, line_end=4, code_snippet=_SNIPPET)
    return fresh


def _validate_once(finding: dict, verdict: float, monkeypatch, source_path: str = "") -> dict:
    """One validate pass with the stub judge.

    ``source_path=""`` keeps the judge on its tool-free path; a source root
    (what a real run passes) attaches the judge's file tools first, and the
    shared stub answers that path through its documented fallback. The row's
    absolute ``file_path`` gives L1 its path evidence either way.
    """
    from shared.validate import ValidateConfig, validate

    patch_l5_judge(monkeypatch, verdicts={finding["id"]: verdict})
    cfg = ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=True)
    result = validate([finding], source_path=source_path, config=cfg,
                      audit_id=f"d1b-{finding['id']}")
    return next(f for f in result.findings if f.get("id") == finding["id"])


def _l5_check(finding: dict) -> dict:
    checks = finding.get("validation", {}).get("checks", [])
    found = [c for c in checks if c.get("id") == "llm_judge"]
    assert found, f"the stub judge must have produced a verdict; checks={checks!r}"
    return found[0]


def _llm_row(provenance: str, tmp_path) -> dict:
    return fake_finding(
        title="SQL injection in login", category="CWE-89",
        file_path=str(tmp_path / "app" / "auth.py"), line_start=4, line_end=4,
        description="d", recommendation="r", id="llm-row",
        check_id=_MODEL_CHECK_ID, provenance=provenance, code_snippet=_SNIPPET,
    )


def _verified_row(tmp_path, monkeypatch, fid: str) -> dict:
    """The D1b precondition, built by the real pipeline: the model's check_id is
    the emitted row's public identity (the restore that keeps 0057's duplicate
    collapse working stays), and a confirming judge re-tags the row."""
    emitted = _llm_row_from_a_real_run(tmp_path, monkeypatch)
    assert (emitted.get("provenance"), emitted.get("check_id")) == ("llm", _MODEL_CHECK_ID), emitted
    verified = _validate_once(_judgeable(emitted, fid, tmp_path), _CONFIRMING, monkeypatch)
    assert (verified.get("provenance"), verified.get("check_id")) == (
        "llm_l5_verified", _MODEL_CHECK_ID), verified
    return verified


def _safeguard(check: dict) -> object:
    return (check.get("extras") or {}).get("safeguard")


# ── the full path: model check_id → result row → L5 re-tag → still demotable ─
#
# The private predicates (`_is_deterministic`, `_is_l5_exempt`) are not asserted
# here: test_0074_llm_family_parity pins `_is_deterministic` for every spelling
# of the shared fixture, and the L5 check's weight and safeguard below are the
# observable form of `_is_l5_exempt` (an exempt row's demotion is neutralised
# to weight 0.0 as `deterministic_authoritative`).

class TestModelCheckIdThroughTheRealPipeline:
    def test_retagged_llm_row_stays_l5_demotable(self, tmp_path, monkeypatch):
        """AC33 / T-1.1: the D1b chain, end to end — a later demoting verdict
        on the re-tagged row is honoured: no demotion immunity."""
        verified = _verified_row(tmp_path, monkeypatch, "llm-2")
        rejudged = _validate_once(_judgeable(verified, "llm-3", tmp_path),
                                  _DEMOTING, monkeypatch)
        check = _l5_check(rejudged)
        assert check.get("weight", 0.0) < 0, (
            "AC33: the judge's demotion of an LLM-family row must keep its weight; "
            f"it was neutralised instead: {check!r}"
        )
        assert _safeguard(check) != "deterministic_authoritative", check


# ── every LLM-family spelling, and the skill control ────────────────────────

class TestLlmFamilyVariants:
    @pytest.mark.parametrize("with_root", JUDGE_PATHS, ids=JUDGE_PATH_IDS)
    @pytest.mark.parametrize("provenance", LLM_FAMILY_VARIANTS)
    def test_llm_family_row_demotion_is_honoured(self, provenance, with_root, tmp_path, monkeypatch):
        """AC33: the family rule is prefix-based, case- and whitespace-
        insensitive, so the demotion reaches the voter for every spelling, on
        both judge paths (tool-free, and the source-root path a real run takes).
        ("llm" already holds today; it is the regression pin of the set.)"""
        root = _source(tmp_path) if with_root else ""
        out = _validate_once(_llm_row(provenance, tmp_path), _DEMOTING,
                             monkeypatch, source_path=root)
        check = _l5_check(out)
        assert check.get("weight", 0.0) < 0, f"provenance={provenance!r}: {check!r}"
        assert _safeguard(check) != "deterministic_authoritative", f"provenance={provenance!r}: {check!r}"

    @pytest.mark.parametrize("with_root", JUDGE_PATHS, ids=JUDGE_PATH_IDS)
    def test_skill_row_with_check_id_stays_deterministic(self, with_root, tmp_path, monkeypatch):
        """AC33 control: the authoritative tier is untouched — a skill row with a
        check_id keeps its deterministic status and its exemption."""
        root = _source(tmp_path) if with_root else ""
        row = {**_llm_row("skill", tmp_path), "id": "skill-row", "check_id": _SKILL_CHECK_ID}
        check = _l5_check(_validate_once(row, _DEMOTING, monkeypatch, source_path=root))
        assert (check.get("weight"), _safeguard(check)) == (0.0, "deterministic_authoritative"), check
