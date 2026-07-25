"""T13 — Feature 0057 Phase 4: the deterministic SIGNATURE tier.

These are RED tests written BEFORE the implementation. They assert the
business contract for the sink/source/sanitizer signature tier:

  * A signature detects a cross-line / structural CWE that the 21 regex
    skills miss (ReDoS regex literal CWE-1333; LDAP filter sink CWE-90).
  * Signatures route THROUGH ``check_catalog_generic`` (R11 / P4d), NOT a
    parallel skill category, so they share the single catalog output and
    the ``(check_id, file_path)`` dedup key.
  * Signatures are introspectable (registry exposes covered CWE ids) for
    the Phase-5 corpus gate (P4c).
  * The generic 3-step matcher honours sink-gate -> require_source ->
    sanitizer-suppress (P4b).
  * Signature status is data-driven by the Phase-5 corpus gate: the 7-CWE
    tranche all VERIFIED, so each is promoted candidate -> trusted.
  * Regex are ReDoS-safe: bounded quantifiers / length caps (invariant).

Everything is deterministic — NO model, LLM OFF.
"""

from __future__ import annotations

import re

import pytest

# --- Modules under test (do not yet exist — RED) ----------------------
from cwe_agent.skills.signatures.schema import CweSignature
from cwe_agent.skills.signatures.registry import (
    SIGNATURES,
    covered_cwe_ids,
)
from cwe_agent.skills.signatures.detector import match_signatures
from cwe_agent.skills.catalog_detector import check_catalog_generic


# The tranche the recon committed to (7 solid; CWE-489 dropped — collides
# with the existing configuration skill).
_TRANCHE_CWES = frozenset({"1333", "90", "91", "917", "943", "117", "548"})


# ── P4a: the CweSignature schema ──────────────────────────────────────

class TestSignatureSchema:
    def test_signature_is_frozen_dataclass(self):
        sig = SIGNATURES[0]
        assert isinstance(sig, CweSignature)
        with pytest.raises(Exception):
            sig.cwe_id = "9999"  # frozen — must not be settable

    def test_signature_required_fields(self):
        sig = SIGNATURES[0]
        assert sig.cwe_id and isinstance(sig.cwe_id, str)
        assert sig.sig_id and isinstance(sig.sig_id, str)
        assert sig.title
        assert sig.severity in {"critical", "high", "medium", "low"}
        assert isinstance(sig.languages, tuple) and sig.languages
        # sink is a compiled, ReDoS-safe regex
        assert isinstance(sig.sink, re.Pattern)
        # optional dataflow patterns
        assert sig.source is None or isinstance(sig.source, re.Pattern)
        assert sig.sanitizer is None or isinstance(sig.sanitizer, re.Pattern)
        assert isinstance(sig.window, int) and sig.window >= 0
        assert 0.0 <= sig.confidence <= 1.0
        assert isinstance(sig.require_source, bool)

    def test_signature_status_is_data_driven_by_the_corpus_gate(self):
        # P4 shipped every signature as candidate. Phase 5's corpus gate then
        # promotes (data-driven) each CWE that VERIFIES to trusted. After
        # promotion the only legal statuses are candidate/trusted, and every
        # status equals the gate's decision for that CWE — never hand-set.
        assert all(sig.status in {"candidate", "trusted"} for sig in SIGNATURES)
        # Track the LIVE gate, not a hardcoded all-trusted snapshot: derive the
        # expected status per signature from the corpus runner's VERIFIED set so
        # this assertion follows the data-driven promotion/demotion path
        # (Risk #9). A signature whose CWE VERIFIES must be trusted; one whose
        # CWE legitimately regresses below the gate must be candidate.
        from tests.corpus.corpus_runner import build_report

        verified = set(build_report()["verified"])
        for sig in SIGNATURES:
            expected = "trusted" if sig.cwe_id in verified else "candidate"
            assert sig.status == expected, (
                f"{sig.sig_id} (CWE-{sig.cwe_id}) status {sig.status!r} does not "
                f"match the live gate decision {expected!r} "
                f"(CWE {'in' if sig.cwe_id in verified else 'not in'} VERIFIED set)"
            )


# ── P4c: registry introspection ───────────────────────────────────────

class TestSignatureRegistry:
    def test_signatures_is_nonempty_tuple(self):
        assert isinstance(SIGNATURES, tuple)
        assert len(SIGNATURES) >= 7

    def test_sig_ids_are_unique(self):
        ids = [s.sig_id for s in SIGNATURES]
        assert len(ids) == len(set(ids))

    def test_covered_cwe_ids_is_introspectable_frozenset(self):
        ids = covered_cwe_ids()
        assert isinstance(ids, frozenset)
        # exactly the committed tranche of 7 (489 dropped)
        assert ids == _TRANCHE_CWES

    def test_cwe_489_is_not_shipped(self):
        # Provisional — dropped because it collides with the existing
        # configuration skill (CWE-1188 / CWE-1295).
        assert "489" not in covered_cwe_ids()


# ── P4b: the generic 3-step matcher in isolation ──────────────────────

class TestThreeStepMatcher:
    def test_sink_gates_the_line(self):
        # A line with no sink yields nothing regardless of source presence.
        lines = ("user_input = request.args.get('q')",
                 "result = harmless_call(user_input)")
        out = match_signatures(lines, ".py")
        assert out == []

    def test_require_source_suppresses_when_no_source_in_window(self):
        # CWE-90 LDAP requires a tainted source. A filter sink built from a
        # CONSTANT (no source within +/- window) must NOT fire.
        lines = (
            "base = '(uid=admin)'",
            "ctx.search(base, '(uid=' + 'admin' + ')')",
        )
        out = [f for f in match_signatures(lines, ".java")
               if f["category"] == "CWE-90"]
        assert out == []

    def test_sanitizer_in_window_suppresses(self):
        # CWE-90: a sink fed by a tainted source but escaped via
        # encodeForLDAP within the window must be suppressed.
        lines = (
            "String u = request.getParameter(\"user\");",
            "String safe = Encoder.encodeForLDAP(u);",
            "ctx.search(base, \"(uid=\" + safe + \")\");",
        )
        out = [f for f in match_signatures(lines, ".java")
               if f["category"] == "CWE-90"]
        assert out == [], "sanitizer in window must suppress the finding"

    def test_matcher_indexed_by_extension(self):
        # A Java-only signature must not fire on a .py file and vice-versa;
        # the matcher is indexed by file extension (low complexity).
        java_only = (
            "String u = request.getParameter(\"user\");",
            "parser.parseExpression(\"T(\" + u + \")\");",  # SpEL / CWE-917
        )
        # CWE-917 (EL injection) is Java-only in the tranche.
        on_java = [f for f in match_signatures(java_only, ".java")
                   if f["category"] == "CWE-917"]
        on_py = [f for f in match_signatures(java_only, ".py")
                 if f["category"] == "CWE-917"]
        assert on_java, "Java EL injection signature must fire on .java"
        assert on_py == [], "Java-only signature must not fire on .py"

    def test_finding_check_id_is_the_sig_id(self):
        # P4b: emit check_id = sig_id, category = CWE-N.
        redos_js = (
            "const re = new RegExp('(a+)+$');",  # nested unbounded quantifier
        )
        out = match_signatures(redos_js, ".js")
        hits = [f for f in out if f["category"] == "CWE-1333"]
        assert hits, "ReDoS signature must fire"
        sig_ids = {s.sig_id for s in SIGNATURES if s.cwe_id == "1333"}
        assert hits[0]["check_id"] in sig_ids
        # carries its signature status for the voter tiering (P4e). After the
        # Phase-5 gate promoted CWE-1333 (VERIFIED), the status rides as trusted.
        assert hits[0].get("signature_status") == "trusted"
        # snippet/enrich reuse — a code snippet is attached.
        assert hits[0].get("code_snippet")


# ── T13 proper: signatures catch what the 21 skills miss, LLM OFF ─────

class TestSignaturesCatchWhatSkillsMiss:
    def test_redos_regex_literal_detected_via_catalog(self, tmp_path):
        # CWE-1333 ReDoS — a regex literal with a nested/overlapping
        # unbounded quantifier. The 21 regex skills have no ReDoS skill;
        # this is a structural CWE only the signature tier catches.
        src = tmp_path / "app"
        src.mkdir()
        (src / "validate.js").write_text(
            "function check(s) {\n"
            "  const re = new RegExp('^(a+)+$');\n"
            "  return re.test(s);\n"
            "}\n"
        )
        result = check_catalog_generic(str(src))
        cats = {f["category"] for f in result["findings"]}
        assert "CWE-1333" in cats, "ReDoS must be detected via check_catalog_generic"

    def test_ldap_filter_sink_detected_via_catalog(self, tmp_path):
        # CWE-90 LDAP injection — a cross-line tainted filter sink.
        src = tmp_path / "app"
        src.mkdir()
        (src / "Directory.java").write_text(
            "public void find(HttpServletRequest request) {\n"
            "  String user = request.getParameter(\"user\");\n"
            "  String filter = \"(uid=\" + user + \")\";\n"
            "  ctx.search(\"ou=people\", filter, controls);\n"
            "}\n"
        )
        result = check_catalog_generic(str(src))
        cats = {f["category"] for f in result["findings"]}
        assert "CWE-90" in cats, "LDAP injection must be detected via check_catalog_generic"

    def test_signature_findings_carry_their_status_end_to_end(self, tmp_path):
        # Through check_catalog_generic, a signature finding carries its
        # signature_status so the voter can tier it (P4e). After the Phase-5
        # gate promoted CWE-1333, that status rides end-to-end as trusted.
        src = tmp_path / "app"
        src.mkdir()
        (src / "re.js").write_text(
            "const r = new RegExp('(x+)+y');\n"
        )
        result = check_catalog_generic(str(src))
        sig_hits = [f for f in result["findings"]
                    if f.get("signature_status") in {"candidate", "trusted"}]
        assert sig_hits, "signature findings must carry a signature_status"
        redos = [f for f in result["findings"] if f.get("category") == "CWE-1333"]
        assert redos and redos[0].get("signature_status") == "trusted"


# ── ReDoS-safety invariant on the signature regex themselves ──────────

class TestSignatureRegexAreReDoSSafe:
    def test_no_unbounded_nested_quantifiers_in_sink_patterns(self):
        # Bounded quantifiers / length caps only — reject the classic
        # catastrophic-backtracking shapes in our own regex sources.
        bad = re.compile(r"\([^)]*[+*]\)[+*]|\(\.\*\)[+*]|\(\.\+\)[+*]")
        for sig in SIGNATURES:
            for pat in (sig.sink, sig.source, sig.sanitizer):
                if pat is None:
                    continue
                assert not bad.search(pat.pattern), (
                    f"{sig.sig_id} regex has an unbounded nested quantifier: "
                    f"{pat.pattern!r}"
                )
