"""Unit tests for the OWASP mapper agent (feature 0063)."""

import json

from owasp_agent.agent import run_audit


def _events(gen):
    out = []
    for chunk in gen:
        head, _, body = chunk.partition("\n")
        out.append((head.split("event: ", 1)[1].strip(),
                    json.loads(body.split("data: ", 1)[1])))
    return out


def _cwe(cwe, title, path="app.py", line=10, **extra):
    d = {"category": f"CWE-{cwe}", "title": title, "severity": "critical",
         "file_path": path, "line_start": line, "line_end": line,
         "description": "d", "check_id": f"cwe.x.{cwe}"}
    d.update(extra)
    return d


def test_maps_cwe_findings_to_owasp_categories():
    prior = [_cwe(89, "SQL injection"), _cwe(918, "SSRF")]
    findings = [d for t, d in _events(run_audit("r1", "/s", {"edition": "2021"}, prior))
                if t == "finding"]
    cats = {f["category"] for f in findings}
    assert any(c.startswith("A03") for c in cats)
    assert any(c.startswith("A10") for c in cats)
    assert all(f["mapped_from"].startswith("CWE-") for f in findings)
    # OWASP finding carries the source page reference.
    assert all(any("owasp.org" in r for r in f["references"]) for f in findings)


def test_result_carries_coverage_manifest():
    result = next(d for t, d in _events(run_audit("r2", "/s", {"edition": "2021"}, [_cwe(89, "x")]))
              if t == "result")
    assert len(result["owasp_coverage"]["categories"]) == 10
    assert result["owasp_coverage"]["cwe_stage_status"] == "completed"


def test_2025_edition_folds_ssrf_into_a01():
    prior = [_cwe(918, "SSRF")]
    findings = [d for t, d in _events(run_audit("r2b", "/s", {"edition": "2025"}, prior))
                if t == "finding"]
    assert findings and all(f["category"].startswith("A01") for f in findings)


def test_no_prior_findings_completes_without_failure():
    events = _events(run_audit("r3", "/s", {"edition": "2021", "cwe_stage_status": "absent"}, None))
    types = [t for t, _ in events]
    assert "result" in types and types[-1] == "agent_end"
    assert next(d for t, d in events if t == "agent_end")["status"] == "completed"
    assert "CWE" in " ".join(d.get("content", "") for t, d in events if t == "thinking")
    assert next(d for t, d in events if t == "result")["owasp_coverage"]["cwe_stage_status"] == "absent"


def test_bad_edition_falls_back_without_failure():
    # A bad edition id must NOT raise — fall back to default, complete cleanly.
    events = _events(run_audit("r3b", "/s", {"edition": "9999"}, [_cwe(89, "x")]))
    types = [t for t, _ in events]
    assert types[-1] == "agent_end"
    assert next(d for t, d in events if t == "result")["owasp_coverage"]["edition"] == "2025"
    assert any("falling back" in d.get("content", "") for t, d in events if t == "thinking")


def test_malformed_prior_does_not_crash():
    # Missing severity/description and a non-dict entry must not raise.
    prior = ["not-a-dict", {"category": "CWE-89", "title": "only title"}]
    events = _events(run_audit("r3c", "/s", {"edition": "2021"}, prior))
    findings = [d for t, d in events if t == "finding"]
    assert findings and all(f["severity"] for f in findings)
    assert [t for t, _ in events][-1] == "agent_end"


def test_category_filter_restricts_output():
    prior = [_cwe(89, "SQLi"), _cwe(918, "SSRF")]
    findings = [d for t, d in _events(run_audit("r4", "/s", {"edition": "2021", "categories": ["A10"]}, prior))
                if t == "finding"]
    assert findings and all(f["category"].startswith("A10") for f in findings)


def test_no_code_snippet_leaks_into_owasp_findings():
    p = _cwe(89, "SQLi", code_snippet="SECRET_KEY = 'sk-live-xyz'")
    findings = [d for t, d in _events(run_audit("r5", "/s", {"edition": "2021"}, [p]))
                if t == "finding"]
    assert findings
    assert all("code_snippet" not in f or not f["code_snippet"] for f in findings)


def test_unmapped_cwe_is_counted_but_emits_no_finding():
    # CWE-99999 maps to no category: no finding, but it must not crash.
    events = _events(run_audit("r6", "/s", {"edition": "2021"}, [_cwe(99999, "weird")]))
    assert not [d for t, d in events if t == "finding"]
    assert [t for t, _ in events][-1] == "agent_end"
