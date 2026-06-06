"""Unit tests for src/translate.py.

RED phase (feature 0053). The `src.translate` module does NOT yet
exist; these imports fail with ModuleNotFoundError until the GREEN
phase ships the implementation.
"""

import json
from pathlib import Path


# Imports will fail at RED time — that is the correct RED state for TDD.
from src.translate import (  # noqa: E402  (import at top is fine; failure is intentional in RED)
    extract_cwe,
    map_severity,
    translate_findings,
)


FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "semgrep_output_real.json"


# ---------------------------------------------------------------------------
# extract_cwe
# ---------------------------------------------------------------------------


def test_extract_cwe_strips_descriptive_text_BLOCKER5():
    # Real Semgrep emits the CWE id followed by a colon and human prose.
    # The translator must strip everything after the canonical "CWE-NNN".
    rule = {
        "extra": {
            "metadata": {
                "cwe": [
                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
                ]
            }
        }
    }
    assert extract_cwe(rule) == "CWE-89"


def test_extract_cwe_handles_list_of_strings():
    rule = {"extra": {"metadata": {"cwe": ["CWE-79: Cross-site Scripting (XSS)"]}}}
    assert extract_cwe(rule) == "CWE-79"


def test_extract_cwe_tolerates_scalar_form():
    # Older or hand-authored rules sometimes emit a single string instead
    # of a list. The translator must tolerate this rather than crash.
    rule = {"extra": {"metadata": {"cwe": "CWE-89: SQL Injection"}}}
    assert extract_cwe(rule) == "CWE-89"


def test_extract_cwe_returns_none_for_missing():
    rule = {"extra": {"metadata": {}}}
    assert extract_cwe(rule) is None


def test_extract_cwe_returns_none_for_non_cwe_strings():
    # Anything that doesn't match ^CWE-\d+ resolves to None — the 0050
    # layer will fall back to the check_id prefix map.
    rule = {"extra": {"metadata": {"cwe": ["FOO-123", "best-practice"]}}}
    assert extract_cwe(rule) is None


def test_extract_cwe_returns_none_for_empty_extra():
    assert extract_cwe({}) is None


# ---------------------------------------------------------------------------
# map_severity
# ---------------------------------------------------------------------------


def test_map_severity_error_to_high_MINOR14():
    # MINOR #14: align Semgrep ERROR with the in-tree "high" severity so
    # L2 rollup groups findings cleanly. Explicitly NOT "critical".
    assert map_severity("ERROR") == "high"
    assert map_severity("ERROR") != "critical"


def test_map_severity_warning_to_medium():
    assert map_severity("WARNING") == "medium"


def test_map_severity_info_to_info():
    assert map_severity("INFO") == "info"


def test_map_severity_unknown_to_info():
    # Graceful fallback for any Semgrep severity Vulture doesn't recognise.
    assert map_severity("UNKNOWN") == "info"
    assert map_severity("") == "info"
    assert map_severity(None) == "info"  # tolerate None too


# ---------------------------------------------------------------------------
# translate_findings (end-to-end against the real Semgrep JSON fixture)
# ---------------------------------------------------------------------------


def _load_fixture():
    with FIXTURE_PATH.open() as fp:
        return json.load(fp)


def test_translate_findings_full_fixture():
    semgrep_json = _load_fixture()
    findings = translate_findings(semgrep_json, agent_type="semgrep")

    # Fixture has four results; all should translate.
    assert len(findings) == 4

    by_check = {f["check_id"]: f for f in findings}

    sql = by_check["python.django.security.injection.sql.sql-injection-using-raw"]
    assert sql["agent_type"] == "semgrep"
    assert sql["severity"] == "high"          # ERROR → high
    assert sql["category"] == "CWE-89"        # canonical CWE preferred
    assert sql["file_path"] == "app/views.py"
    assert sql["line_start"] == 42
    assert sql["line_end"] == 44
    assert sql["title"]                       # non-empty
    assert sql["description"]                 # non-empty
    assert "cursor.execute" in sql["code_snippet"]

    xss = by_check["javascript.express.security.audit.xss.direct-response-write"]
    assert xss["severity"] == "medium"        # WARNING → medium
    assert xss["category"] == "CWE-79"

    md5 = by_check["go.lang.security.audit.crypto.weak-hashes.use-of-md5"]
    assert md5["severity"] == "medium"
    assert md5["category"] == "CWE-327"


def test_translate_findings_falls_back_to_check_id():
    # The "unused-variable" rule in the fixture has NO cwe metadata —
    # the translator must fall back to using check_id as the category
    # so the 0050 prefix map can attempt resolution downstream.
    semgrep_json = _load_fixture()
    findings = translate_findings(semgrep_json, agent_type="semgrep")
    unused = next(f for f in findings if f["check_id"] == "python.lang.best-practice.unused-variable")
    assert unused["category"] == "python.lang.best-practice.unused-variable"
    assert unused["severity"] == "info"


def test_translate_findings_empty_results_returns_empty_list():
    assert translate_findings({"results": []}, agent_type="semgrep") == []
    assert translate_findings({}, agent_type="semgrep") == []


def test_translate_findings_title_truncated_to_200_chars():
    # Multi-line Semgrep messages should produce a title that is the first
    # line truncated to <=200 chars; the full message lives in description.
    long_first_line = "x" * 250
    rule = {
        "check_id": "test.rule",
        "path": "f.py",
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {
            "message": long_first_line + "\nsecond line",
            "severity": "INFO",
            "lines": "",
        },
    }
    findings = translate_findings({"results": [rule]}, agent_type="semgrep")
    assert len(findings) == 1
    assert len(findings[0]["title"]) <= 200
    assert findings[0]["description"].startswith(long_first_line)
