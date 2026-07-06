"""Feature 0058 T3 (R4, P2b) — CWE attribution on translated findings.

RED-phase TDD. Contract pinned by these tests, on
``src.translate.translate_findings(semgrep_json, agent_type, root="")``:

* EVERY finding dict carries a ``"cwe"`` key.
* ``finding["cwe"]`` is the canonical ``"CWE-NNN"`` extracted from the
  Semgrep result's ``extra.metadata.cwe`` (list-of-strings or scalar
  string, descriptive suffix stripped).
* When ``extra.metadata.cwe`` is absent or unparseable, ``finding["cwe"]``
  is the LITERAL string ``"CWE-unknown"`` — the finding is NEVER dropped.
* The existing ``"category"`` behavior is UNCHANGED: canonical CWE when
  extractable, else the raw ``check_id`` (NOT "CWE-unknown").
"""

from __future__ import annotations

from src.translate import translate_findings


def _result(check_id: str, metadata: dict | None) -> dict:
    """One semgrep-JSON result in the real 1.84.0 output shape."""
    extra: dict = {
        "message": "Something risky.",
        "severity": "ERROR",
        "lines": "do_risky_thing(x)",
    }
    if metadata is not None:
        extra["metadata"] = metadata
    return {
        "check_id": check_id,
        "path": "app/views.py",
        "start": {"line": 10, "col": 1, "offset": 0},
        "end": {"line": 12, "col": 5, "offset": 0},
        "extra": extra,
    }


def _doc(*results: dict) -> dict:
    return {
        "version": "1.84.0",
        "results": list(results),
        "errors": [],
        "paths": {"scanned": [], "skipped": []},
    }


def _one(doc: dict) -> dict:
    findings = translate_findings(doc, agent_type="semgrep")
    assert len(findings) == 1
    return findings[0]


# ---------------------------------------------------------------------------
# "cwe" key — canonical extraction (RED: key does not exist today)
# ---------------------------------------------------------------------------


def test_finding_has_cwe_key_extracted_from_metadata_list():
    f = _one(_doc(_result(
        "python.django.security.injection.sql.sql-injection-using-raw",
        {"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]},
    )))
    assert f["cwe"] == "CWE-89"


def test_finding_cwe_key_handles_scalar_metadata_form():
    f = _one(_doc(_result(
        "custom.vulture.cmd-injection-taint",
        {"cwe": "CWE-78: OS Command Injection"},
    )))
    assert f["cwe"] == "CWE-78"


# ---------------------------------------------------------------------------
# "cwe" key — CWE-unknown fallback, never dropped (RED: fallback missing)
# ---------------------------------------------------------------------------


def test_finding_without_cwe_metadata_gets_literal_cwe_unknown():
    f = _one(_doc(_result("custom.rules.some-unmapped-rule", None)))
    assert f["cwe"] == "CWE-unknown"


def test_finding_with_unparseable_cwe_metadata_gets_literal_cwe_unknown():
    f = _one(_doc(_result(
        "custom.rules.garbled-metadata",
        {"cwe": ["totally-not-a-cwe", 42]},
    )))
    assert f["cwe"] == "CWE-unknown"


def test_unmapped_finding_is_never_dropped():
    doc = _doc(
        _result("rule.with.cwe", {"cwe": ["CWE-79: XSS"]}),
        _result("rule.without.cwe", None),
    )
    findings = translate_findings(doc, agent_type="semgrep")
    assert len(findings) == 2, "unmapped findings must be tagged CWE-unknown, never dropped (R4)"
    by_check = {f["check_id"]: f for f in findings}
    assert by_check["rule.with.cwe"]["cwe"] == "CWE-79"
    assert by_check["rule.without.cwe"]["cwe"] == "CWE-unknown"


# ---------------------------------------------------------------------------
# "category" — existing behavior UNCHANGED (regression pins)
# ---------------------------------------------------------------------------


def test_category_still_prefers_canonical_cwe():
    f = _one(_doc(_result("rule.mapped", {"cwe": ["CWE-89: SQL Injection"]})))
    assert f["category"] == "CWE-89"


def test_category_still_falls_back_to_check_id_not_cwe_unknown():
    f = _one(_doc(_result("custom.rules.some-unmapped-rule", None)))
    assert f["category"] == "custom.rules.some-unmapped-rule", (
        "category must keep its check_id fallback (downstream 0050 prefix/rule "
        "maps resolve it); the CWE-unknown literal belongs ONLY in the `cwe` key"
    )
