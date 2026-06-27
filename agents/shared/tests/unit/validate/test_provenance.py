"""T23 — Feature 0057 Phase 6 (P6b / R3-prime): every finding carries EXACTLY
ONE provenance tag drawn from the fixed vocabulary, set centrally.

Vocabulary (exactly one per finding):
    skill | signature_trusted | signature_candidate | catalog_rollup
    | llm | llm_l5_verified

Phase 1 already stamps ``provenance="llm"`` on LLM findings. Phase 6 EXTENDS
this to the full deterministic vocabulary at the finalisation choke point
(``audit_runner._set_provenance`` — applied in ``_attach_code_snippet`` over
``all_findings`` BEFORE validate) plus the L5-survival re-tag at the validate
vote choke point (``validate._apply_validation_to_finding``).

The tags are ADDITIVE metadata and must NOT change the existing
``_is_deterministic`` / ``_is_l5_exempt`` determinations (those key off
``check_id`` / ``signature_status`` / ``provenance=="llm"``) — a regression
guard for that is included.

Fully deterministic — NO model is called.

RED until:
  * ``audit_runner.PROVENANCE_VALUES`` (the 6-value vocabulary) exists,
  * ``audit_runner._set_provenance(finding)`` classifies the deterministic
    tiers with setdefault semantics (preserves a pre-set ``llm``),
  * ``validate._apply_validation_to_finding`` re-tags an L5-surviving LLM
    finding to ``llm_l5_verified``.
"""

from __future__ import annotations

import pytest

import shared.audit_runner as audit_runner
from shared.validate import _apply_validation_to_finding, validate
from shared.validate.llm_judge import _is_deterministic, _is_l5_exempt
from shared.validate.types import ValidationCheck, ValidateConfig


_VOCAB = {
    "skill",
    "signature_trusted",
    "signature_candidate",
    "catalog_rollup",
    "llm",
    "llm_l5_verified",
}


# ── the vocabulary constant ────────────────────────────────────────────
class TestProvenanceVocabulary:
    def test_vocabulary_constant_is_the_six_value_set(self):
        assert set(audit_runner.PROVENANCE_VALUES) == _VOCAB


# ── _set_provenance: deterministic-tier classification ──────────────────
class TestSetProvenanceDeterministicTiers:
    def test_plain_skill_finding_is_skill(self):
        f = {"check_id": "cwe.injection.sql", "category": "CWE-89"}
        audit_runner._set_provenance(f)
        assert f["provenance"] == "skill"

    def test_trusted_signature_is_signature_trusted(self):
        f = {"check_id": "cwe.sig.ldap", "signature_status": "trusted"}
        audit_runner._set_provenance(f)
        assert f["provenance"] == "signature_trusted"

    def test_candidate_signature_is_signature_candidate(self):
        f = {"check_id": "cwe.sig.x", "signature_status": "candidate"}
        audit_runner._set_provenance(f)
        assert f["provenance"] == "signature_candidate"

    def test_catalog_rollup_is_catalog_rollup(self):
        f = {"check_id": "cwe.catalog.cwe_20.rollup", "category": "CWE-20"}
        audit_runner._set_provenance(f)
        assert f["provenance"] == "catalog_rollup"

    def test_existing_llm_tag_is_preserved(self):
        # setdefault semantics: the Phase-1 llm tag must survive untouched.
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        audit_runner._set_provenance(f)
        assert f["provenance"] == "llm"


# ── exactly one tag, always in vocabulary ───────────────────────────────
class TestExactlyOneProvenanceInVocabulary:
    @pytest.mark.parametrize(
        "finding",
        [
            {"check_id": "cwe.injection.sql"},
            {"check_id": "cwe.sig.ldap", "signature_status": "trusted"},
            {"check_id": "cwe.sig.x", "signature_status": "candidate"},
            {"check_id": "cwe.catalog.cwe_20.rollup"},
            {"check_id": "cwe.injection.sql", "provenance": "llm"},
        ],
    )
    def test_every_finding_gets_exactly_one_vocab_tag(self, finding):
        audit_runner._set_provenance(finding)
        assert finding["provenance"] in _VOCAB
        # exactly one: provenance is a single scalar, never a list/set
        assert isinstance(finding["provenance"], str)


# ── additive: provenance tags must NOT move the L5 tier determinations ──
class TestProvenanceTagsAreAdditive:
    def test_skill_tag_stays_deterministic(self):
        f = {"check_id": "cwe.injection.sql"}
        audit_runner._set_provenance(f)
        assert _is_deterministic(f) is True
        assert _is_l5_exempt(f) is True

    def test_signature_candidate_tag_stays_non_deterministic(self):
        f = {"check_id": "cwe.sig.x", "signature_status": "candidate"}
        audit_runner._set_provenance(f)
        assert _is_deterministic(f) is False

    def test_llm_tag_stays_non_deterministic(self):
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        audit_runner._set_provenance(f)
        assert _is_deterministic(f) is False


# ── L5 re-tag: an LLM finding that SURVIVES L5 becomes llm_l5_verified ──
def _llm_judge_check(weight: float) -> ValidationCheck:
    return ValidationCheck(
        id="llm_judge", result="confirm" if weight >= 0 else "advisory",
        weight=weight, reason="judge verdict", extras={},
    )


class TestL5VerifiedRetag:
    def test_llm_finding_with_confirming_l5_becomes_llm_l5_verified(self):
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        checks = [_llm_judge_check(0.4)]  # non-demoting (confirming)
        out = _apply_validation_to_finding(f, checks, ValidateConfig())
        assert out["provenance"] == "llm_l5_verified"

    def test_llm_finding_with_demoting_l5_stays_llm(self):
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        checks = [_llm_judge_check(-0.4)]  # demoting verdict
        out = _apply_validation_to_finding(f, checks, ValidateConfig())
        assert out["provenance"] == "llm"

    def test_llm_finding_without_l5_check_stays_llm(self):
        # No llm_judge check present -> not L5-verified yet.
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        checks = [ValidationCheck(id="l1.x", result="ok", weight=0.1,
                                  reason="", extras={})]
        out = _apply_validation_to_finding(f, checks, ValidateConfig())
        assert out["provenance"] == "llm"

    def test_skill_finding_with_confirming_l5_is_not_retagged(self):
        # A deterministic finding is never re-tagged to an llm_* provenance.
        f = {"check_id": "cwe.injection.sql", "provenance": "skill"}
        checks = [_llm_judge_check(0.4)]
        out = _apply_validation_to_finding(f, checks, ValidateConfig())
        assert out["provenance"] == "skill"

    def test_retag_does_not_disturb_validation_fields(self):
        # The re-tag is additive: validation_status / confidence still stamped.
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        checks = [_llm_judge_check(0.4)]
        out = _apply_validation_to_finding(f, checks, ValidateConfig())
        assert "validation_status" in out
        assert "validation_confidence" in out
        assert "validation" in out


# ── END-TO-END: EVERY emitted record (findings + L2 rollup parents) carries
#    a provenance tag. This is the invariant P6b actually promises ("tag every
#    finding with exactly one provenance"). The unit tests above only exercise
#    the _set_provenance / _retag set-points on individual dicts; this test runs
#    the real finalisation choke point (_attach_code_snippet → _set_provenance)
#    followed by the full validate() pipeline (which mints L2 rollup parents)
#    and asserts NO record ships without provenance. Without the rollup-parent
#    fix, res.rollups[0] has provenance=None and this test goes RED. ───────────
class TestPipelineEveryRecordTagged:
    def _two_same_group_findings(self) -> list[dict]:
        # Same (category, normalised title, file_path) so L2 rolls them up into
        # one parent. Distinct lines → distinct member findings.
        base = {
            "category": "CWE-89",
            "title": "SQL injection via string concatenation",
            "file_path": "app/db.py",
            "severity": "high",
            "check_id": "cwe.injection.sql",
            "code_snippet": "x",  # pre-set so _attach_code_snippet does no I/O
        }
        return [
            {**base, "id": "f1", "line_start": 10, "line_end": 10},
            {**base, "id": "f2", "line_start": 20, "line_end": 20},
        ]

    def test_finalisation_then_validate_tags_every_record(self):
        findings = self._two_same_group_findings()

        # Finalisation choke point: stamp deterministic provenance on members.
        # source_path "" → no file resolves, snippets pre-set → pure no-op I/O.
        audit_runner._attach_code_snippet(findings, source_path="")
        for f in findings:
            assert f["provenance"] in _VOCAB, f

        # Full validate pipeline (L1 + L2; L5 off → deterministic, no model).
        res = validate(
            findings, source_path="", audit_id="audit-prov-e2e",
            config=ValidateConfig(enable_l1=True, enable_l2=True, enable_l5=False),
        )

        # L2 must have produced exactly one rollup parent from the pair.
        assert len(res.rollups) == 1, res.rollups

        # EVERY record the audit ships (members + rollup parents) is tagged.
        for record in list(res.findings) + list(res.rollups):
            assert record.get("provenance") in _VOCAB, record

        # The grouping parent is specifically the catalog_rollup tag.
        assert res.rollups[0]["provenance"] == "catalog_rollup"
        # Members keep their deterministic skill tag (not re-tagged by rollup).
        assert all(f["provenance"] == "skill" for f in res.findings)
