"""T15 — Feature 0057 Phase 4 (P4e): validation tiering for signatures.

The signature tier carries a ``status`` (candidate|trusted) surfaced on
findings as ``signature_status``. The voter / L5-judge logic must treat it
as a tier marker, EXTENDING the Phase-1 (check_id + provenance) logic:

  * A ``candidate`` signature finding is L5-demotable like an LLM finding:
    it is NOT deterministic-authoritative, so a single demoting ``llm_judge``
    verdict is NOT neutralised (the candidate can fall to the voter's
    likely_fp band).
  * A ``trusted`` signature finding (and an ordinary skill finding with no
    ``signature_status``) IS deterministic-authoritative: a single demoting
    L5 verdict is neutralised, so it keeps the voter's >=2-demoting-check
    floor before it can be demoted to likely_fp.

These tests are RED until ``_is_deterministic`` / ``_is_l5_exempt`` read
``signature_status``. Fully deterministic — NO model.
"""

from __future__ import annotations

from shared.validate.llm_judge import (
    _is_deterministic,
    _is_l5_exempt,
    _apply_l5_safeguards,
)
from shared.validate.types import ValidationCheck


# ── Unit: _is_deterministic / _is_l5_exempt read signature_status ─────

class TestDeterministicTierClassification:
    def test_candidate_signature_is_not_deterministic(self):
        # A candidate signature is L5-demotable like an LLM finding.
        f = {"check_id": "cwe.sig.ldap", "signature_status": "candidate"}
        assert _is_deterministic(f) is False
        assert _is_l5_exempt(f) is False

    def test_trusted_signature_is_deterministic(self):
        f = {"check_id": "cwe.sig.ldap", "signature_status": "trusted"}
        assert _is_deterministic(f) is True
        assert _is_l5_exempt(f) is True

    def test_plain_skill_finding_stays_deterministic(self):
        # No signature_status, no llm provenance -> authoritative skill.
        f = {"check_id": "cwe.injection.sql"}
        assert _is_deterministic(f) is True
        assert _is_l5_exempt(f) is True

    def test_llm_finding_stays_non_deterministic(self):
        f = {"check_id": "cwe.injection.sql", "provenance": "llm"}
        assert _is_deterministic(f) is False
        assert _is_l5_exempt(f) is False

    def test_candidate_signature_with_crypto_category_still_exempt(self):
        # Crypto/policy CWEs are never auto-suppressed regardless of tier.
        f = {
            "check_id": "cwe.sig.x", "signature_status": "candidate",
            "category": "CWE-327",
        }
        assert _is_l5_exempt(f) is True


# ── End-to-end via _apply_l5_safeguards (the real neutralisation path) ─

def _demoting_l5_check() -> ValidationCheck:
    return ValidationCheck(
        id="llm_judge", result="advisory", weight=-0.4,
        reason="model says not exploitable", extras={},
    )


def _finding_with_l5(check_id: str, **extra) -> dict:
    """A finding shaped as the runner produces it, with one demoting
    llm_judge check already attached in its validation blob."""
    chk = _demoting_l5_check()
    f = {
        "id": check_id,
        "check_id": check_id,
        "category": extra.pop("category", "CWE-90"),
        "file_path": "a.java",
        "line_start": 1,
        "line_end": 1,
        "validation": {"checks": [chk.to_json()]},
    }
    f.update(extra)
    return f


class TestL5SafeguardRespectsSignatureStatus:
    def test_candidate_signature_demotion_is_NOT_neutralised(self):
        # A candidate is L5-demotable: the demoting verdict survives.
        f = _finding_with_l5("cwe.sig.ldap", signature_status="candidate")
        out = [[_demoting_l5_check()]]
        _apply_l5_safeguards([f], [0], out)
        # Verdict still demoting (negative weight) -> not safeguarded.
        assert out[0][0].weight < 0
        chk = f["validation"]["checks"][0]
        assert "safeguard" not in chk.get("extras", {})

    def test_trusted_signature_demotion_IS_neutralised(self):
        # A trusted signature is authoritative: the lone demoting verdict
        # is neutralised, preserving the voter's >=2-demoting-check floor.
        f = _finding_with_l5("cwe.sig.ldap", signature_status="trusted")
        out = [[_demoting_l5_check()]]
        _apply_l5_safeguards([f], [0], out)
        assert out[0][0].weight == 0.0
        chk = f["validation"]["checks"][0]
        assert chk.get("extras", {}).get("safeguard") == "deterministic_authoritative"

    def test_plain_skill_demotion_IS_neutralised(self):
        # Regression guard: skills stay AUTHORITATIVE.
        f = _finding_with_l5("cwe.injection.sql")  # no signature_status
        out = [[_demoting_l5_check()]]
        _apply_l5_safeguards([f], [0], out)
        assert out[0][0].weight == 0.0
        chk = f["validation"]["checks"][0]
        assert chk.get("extras", {}).get("safeguard") == "deterministic_authoritative"
