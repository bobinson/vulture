"""T14 — Feature 0057 Phase 4: R11 single-report contract (P4d, BLOCKING).

Signatures route THROUGH ``check_catalog_generic`` and the
``_DEDICATED_SKILL_CWES`` ownership set. They MUST NOT be a parallel skill
category, because the audit dedup key is ``(check_id, file_path)``
(``shared.audit_runner._dedup_key``): a parallel category would
double-report a site that both a signature and another detector flag.

This test asserts:

  1. The 7 signature-owned CWE ids are members of the dedicated/ownership
     set, so the keyword engine NEVER also emits them (no
     signature-vs-keyword double-emit of the same CWE).
  2. ``check_catalog_generic`` output has unique ``(check_id, file_path)``
     keys for signature findings (no internal duplicate emit).
  3. Through the real audit dedup machinery, a site flagged by a signature
     AND a second (keyword/rollup) finding collapses to ONE entry per
     ``(check_id, file_path)``.

Deterministic. NO model.
"""

from __future__ import annotations

import pytest

from cwe_agent.skills.catalog_detector import (
    check_catalog_generic,
    _BASE_DEDICATED_CWES,
    _DEDICATED_SKILL_CWES,
)
from cwe_agent.skills.signatures.registry import covered_cwe_ids

# The real audit-level dedup used in production.
from shared.audit_runner import _dedup_key, _deduplicate_findings


class TestSignatureOwnershipPreventsKeywordDoubleEmit:
    def test_signature_cwes_are_in_base_dedicated_set(self):
        # R11: every signature-owned CWE must be in the base dedicated set
        # so the keyword path is suppressed from re-emitting it.
        missing = covered_cwe_ids() - _BASE_DEDICATED_CWES
        assert not missing, (
            f"signature CWEs not owned by the dedicated set (keyword path "
            f"would double-emit): {sorted(missing)}"
        )

    def test_signature_cwes_resolve_in_dedicated_superset(self):
        assert covered_cwe_ids() <= _DEDICATED_SKILL_CWES


class TestNoInternalDuplicateEmit:
    def test_catalog_generic_signature_findings_have_unique_keys(self, tmp_path):
        # A file that fires a signature must not yield two findings sharing
        # the same (check_id, file_path) from the catalog engine itself.
        src = tmp_path / "app"
        src.mkdir()
        (src / "Directory.java").write_text(
            "public void find(HttpServletRequest request) {\n"
            "  String user = request.getParameter(\"user\");\n"
            "  String filter = \"(uid=\" + user + \")\";\n"
            "  ctx.search(\"ou=people\", filter, controls);\n"
            "}\n"
        )
        findings = check_catalog_generic(str(src))["findings"]
        keys = [_dedup_key(f, str(src)) for f in findings]
        assert len(keys) == len(set(keys)), "duplicate (check_id, file_path) keys emitted"


class TestSingleReportUnderAuditDedup:
    def test_signature_and_other_finding_same_site_reports_once(self, tmp_path):
        # Simulate the audit-runner cross-phase dedup: a signature finding
        # (base) and a second detector flagging the SAME site with the SAME
        # check_id must collapse to one.
        src = str(tmp_path)
        signature_finding = {
            "check_id": "cwe.sig.ldap",
            "category": "CWE-90",
            "file_path": "Directory.java",
            "line_start": 4,
            "signature_status": "candidate",
        }
        # A second pass re-discovers the identical site/check_id.
        rediscovered = dict(signature_finding)

        new_only = _deduplicate_findings([signature_finding], [rediscovered], src)
        assert new_only == [], (
            "a site flagged twice under the same (check_id, file_path) must "
            "report ONCE — the second is deduped away"
        )

    def test_distinct_detectors_same_site_distinct_check_ids_both_kept(self, tmp_path):
        # Sanity / negative control: two genuinely different detectors with
        # DIFFERENT check_ids on the same file are NOT collapsed — dedup is
        # keyed on (check_id, file_path), not file alone.
        src = str(tmp_path)
        sig = {
            "check_id": "cwe.sig.ldap", "category": "CWE-90",
            "file_path": "Directory.java", "line_start": 4,
        }
        other = {
            "check_id": "cwe.catalog.cwe_77", "category": "CWE-77",
            "file_path": "Directory.java", "line_start": 4,
        }
        new_only = _deduplicate_findings([sig], [other], src)
        assert new_only == [other], (
            "distinct check_ids on the same file are distinct findings"
        )
