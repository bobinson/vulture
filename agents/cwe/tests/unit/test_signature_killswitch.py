"""Feature 0057 FIX — signature-tier kill switches (audit MEDIUM "ROLLBACK-killswitch").

Two documented-but-missing escape hatches for the deterministic SIGNATURE
tier, both routed through ``check_catalog_generic`` (R11):

  * ``VULTURE_CWE_DISABLE_SIGNATURES`` — skip the signature tier ENTIRELY
    (mirrors ``VULTURE_CWE_DISABLE_LLM`` for the LLM phase). When set, the
    catalog engine emits zero signature findings; the keyword/rollup path is
    untouched. Unset ⇒ signatures present.

  * ``VULTURE_CWE_SIGNATURES_CANDIDATE_OFF`` — run TRUSTED signatures only,
    filtering out any finding carrying ``signature_status == "candidate"``.
    All 7 shipped signatures are ``trusted`` today, so we monkeypatch a
    CANDIDATE-status signature into the matcher to prove the filter actually
    drops candidates while keeping trusted ones.

Deterministic. NO model. Env via monkeypatch only — no global mutation leaks.
"""

from __future__ import annotations

import cwe_agent.skills.catalog_detector as cd
from cwe_agent.skills.catalog_detector import check_catalog_generic


# A .js file whose only weakness is a ReDoS regex literal (CWE-1333, trusted
# signature). The 21 regex skills have no ReDoS skill, so this CWE can ONLY
# come from the signature tier — it is a clean probe for "signatures on/off".
_REDOS_JS = (
    "function check(s) {\n"
    "  const re = new RegExp('^(a+)+$');\n"
    "  return re.test(s);\n"
    "}\n"
)


def _write_redos(tmp_path):
    src = tmp_path / "app"
    src.mkdir()
    (src / "validate.js").write_text(_REDOS_JS)
    return str(src)


def _cwe1333_findings(result):
    return [f for f in result["findings"] if f.get("category") == "CWE-1333"]


def _signature_findings(result):
    return [
        f for f in result["findings"]
        if f.get("signature_status") in {"candidate", "trusted"}
    ]


# ── VULTURE_CWE_DISABLE_SIGNATURES: skip the signature tier entirely ──────

class TestDisableSignaturesKillSwitch:
    def test_signatures_present_when_unset(self, tmp_path, monkeypatch):
        # Control: with the kill switch UNSET, the trusted ReDoS signature
        # fires through check_catalog_generic.
        monkeypatch.delenv("VULTURE_CWE_DISABLE_SIGNATURES", raising=False)
        src = _write_redos(tmp_path)
        result = check_catalog_generic(src)
        assert _cwe1333_findings(result), (
            "ReDoS signature (CWE-1333) must fire when the kill switch is unset"
        )

    def test_signatures_absent_when_disabled_truthy(self, tmp_path, monkeypatch):
        # Kill switch ON: the signature tier is skipped entirely — zero
        # signature findings, and specifically no CWE-1333 (skills have no
        # ReDoS detector, so its absence proves the tier was skipped).
        monkeypatch.setenv("VULTURE_CWE_DISABLE_SIGNATURES", "true")
        src = _write_redos(tmp_path)
        result = check_catalog_generic(src)
        assert _cwe1333_findings(result) == [], (
            "VULTURE_CWE_DISABLE_SIGNATURES=true must skip the signature tier"
        )
        assert _signature_findings(result) == [], (
            "no finding may carry a signature_status when signatures are disabled"
        )

    def test_disable_respects_env_truthy_variants(self, tmp_path, monkeypatch):
        # Mirror the _env_truthy contract used for VULTURE_CWE_DISABLE_LLM:
        # 1/yes/TRUE are truthy; "0"/"false"/"" are not.
        for val in ("1", "yes", "TRUE"):
            monkeypatch.setenv("VULTURE_CWE_DISABLE_SIGNATURES", val)
            base = tmp_path / f"off_{val}"
            base.mkdir()
            src = _write_redos(base)
            assert _cwe1333_findings(check_catalog_generic(src)) == [], (
                f"value {val!r} must disable signatures"
            )
        for val in ("0", "false", ""):
            monkeypatch.setenv("VULTURE_CWE_DISABLE_SIGNATURES", val)
            d = tmp_path / f"on_{val or 'empty'}"
            d.mkdir()
            (d / "validate.js").write_text(_REDOS_JS)
            assert _cwe1333_findings(check_catalog_generic(str(d))), (
                f"value {val!r} must NOT disable signatures"
            )


# ── VULTURE_CWE_SIGNATURES_CANDIDATE_OFF: trusted signatures only ─────────

class TestCandidateOffKillSwitch:
    @staticmethod
    def _matcher_with_candidate(real_matcher):
        """Wrap the real matcher so every fired signature also yields one
        synthetic CANDIDATE-status finding at the same site. Lets us prove the
        candidate filter without editing the (all-trusted) family modules."""
        def _patched(lines, file_ext):
            out = list(real_matcher(lines, file_ext))
            for f in list(out):
                if f.get("signature_status") == "trusted":
                    cand = dict(f)
                    cand["check_id"] = "cwe.sig.candidate_probe"
                    cand["category"] = "CWE-9001"
                    cand["signature_status"] = "candidate"
                    out.append(cand)
                    break
            return out
        return _patched

    def test_candidate_findings_present_when_unset(self, tmp_path, monkeypatch):
        # Control: with the switch UNSET, BOTH the trusted ReDoS finding and
        # the injected candidate ride through check_catalog_generic.
        monkeypatch.delenv("VULTURE_CWE_SIGNATURES_CANDIDATE_OFF", raising=False)
        monkeypatch.delenv("VULTURE_CWE_DISABLE_SIGNATURES", raising=False)
        monkeypatch.setattr(
            cd, "match_signatures", self._matcher_with_candidate(cd.match_signatures)
        )
        src = _write_redos(tmp_path)
        result = check_catalog_generic(src)
        statuses = {f.get("signature_status") for f in _signature_findings(result)}
        assert "candidate" in statuses, "candidate finding must be present when unset"
        assert "trusted" in statuses, "trusted finding must be present when unset"

    def test_candidate_filtered_when_on_trusted_kept(self, tmp_path, monkeypatch):
        # Switch ON: candidate-status findings are filtered out; the trusted
        # ReDoS finding survives (run trusted signatures only).
        monkeypatch.delenv("VULTURE_CWE_DISABLE_SIGNATURES", raising=False)
        monkeypatch.setenv("VULTURE_CWE_SIGNATURES_CANDIDATE_OFF", "true")
        monkeypatch.setattr(
            cd, "match_signatures", self._matcher_with_candidate(cd.match_signatures)
        )
        src = _write_redos(tmp_path)
        result = check_catalog_generic(src)
        sig = _signature_findings(result)
        assert sig, "trusted signatures must still fire when only candidates are off"
        assert all(f.get("signature_status") == "trusted" for f in sig), (
            "VULTURE_CWE_SIGNATURES_CANDIDATE_OFF must drop every candidate finding"
        )
        assert not any(f.get("category") == "CWE-9001" for f in result["findings"]), (
            "the synthetic candidate CWE must be filtered out"
        )
        assert _cwe1333_findings(result), (
            "the trusted CWE-1333 ReDoS finding must be kept"
        )

    def test_candidate_off_does_not_imply_disable(self, tmp_path, monkeypatch):
        # The two switches are independent: CANDIDATE_OFF keeps trusted
        # signatures, it does not skip the whole tier.
        monkeypatch.delenv("VULTURE_CWE_DISABLE_SIGNATURES", raising=False)
        monkeypatch.setenv("VULTURE_CWE_SIGNATURES_CANDIDATE_OFF", "true")
        src = _write_redos(tmp_path)
        result = check_catalog_generic(src)
        assert _cwe1333_findings(result), (
            "candidate-off alone must not disable the trusted signature tier"
        )
