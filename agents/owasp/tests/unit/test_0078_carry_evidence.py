"""OWASP must carry its input's EVIDENCE metadata, not strip it.

Measured: every owasp row in the install-mode run carried empty provenance --
217 of 217, and after track C that was the entire remaining empty population
fleet-wide. `_relabel` copies a fixed `_CARRY` set and drops everything else, so
an OWASP row reached the DB with no provenance, no validation status and no
confidence, however well-evidenced the CWE finding it was derived from.

Provenance is INHERITED rather than given a new `owasp_categorized` tag: the
useful question about an OWASP row is whether the underlying detection was
deterministic or a model's guess, and inheriting answers it. Inventing a sixth
vocabulary value in the feature whose thesis is closed declared vocabularies
would contradict itself.

`code_snippet` stays EXCLUDED -- that is a deliberate 0063 security constraint
(snippets can carry secrets and must not be re-emitted here), and this change
does not weaken it.
"""

from owasp_agent.agent import _CARRY, _relabel


class _Cat:
    id = "A03"
    name = "Injection"
    slug = "A03-injection"
    source_url = "https://example.invalid/a03"


PRIOR = {
    "file_path": "src/db.ts",
    "line_start": 12,
    "line_end": 12,
    "recommendation": "Use parameterised queries",
    "title": "SQL injection via string interpolation",
    "description": "…",
    "severity": "critical",
    "provenance": "skill",
    "validation_status": "high_confidence",
    "validation_confidence": 0.82,
    "validation": {"status": "high_confidence", "confidence": 0.82,
                   "checks": [{"id": "path", "result": "neutral", "weight": 0}]},
    "code_snippet": "12: const q = `SELECT * FROM t WHERE id = ${id}`",
}


class TestEvidenceIsCarried:
    def test_provenance_inherited(self):
        assert _relabel(PRIOR, _Cat, 89, "run1", 0)["provenance"] == "skill"

    def test_llm_provenance_inherited_not_flattened(self):
        row = _relabel({**PRIOR, "provenance": "llm_l5_verified"}, _Cat, 89, "run1", 0)
        assert row["provenance"] == "llm_l5_verified"

    def test_validation_status_carried(self):
        assert _relabel(PRIOR, _Cat, 89, "run1", 0)["validation_status"] == "high_confidence"

    def test_validation_confidence_carried(self):
        assert _relabel(PRIOR, _Cat, 89, "run1", 0)["validation_confidence"] == 0.82

    def test_validation_blob_carried(self):
        # Carried so the backend does not SYNTHESISE one: stream_handler.go
        # builds a blob from scratch when Validation is nil and re-votes it, so
        # an absent blob yields a FABRICATED confidence, not "unvalidated".
        assert _relabel(PRIOR, _Cat, 89, "run1", 0)["validation"]["confidence"] == 0.82


class TestSecurityConstraintHeld:
    def test_code_snippet_still_excluded(self):
        assert "code_snippet" not in _relabel(PRIOR, _Cat, 89, "run1", 0)

    def test_code_snippet_not_in_carry_set(self):
        assert "code_snippet" not in _CARRY

    def test_no_snippet_text_leaks_via_validation_extras(self):
        prior = {**PRIOR, "validation": {
            "status": "suspicious", "confidence": 0.4,
            "checks": [{"id": "anchor", "result": "exact",
                        "extras": {"quote_text": "SECRET=hunter2", "delta": 0}}]}}
        blob = _relabel(prior, _Cat, 89, "run1", 0).get("validation")
        assert "hunter2" not in str(blob)


class TestUnchangedBehaviour:
    def test_category_is_rederived_not_inherited(self):
        assert _relabel(PRIOR, _Cat, 89, "run1", 0)["category"] == "A03-injection"

    def test_missing_metadata_is_not_invented(self):
        bare = {"file_path": "a.ts", "line_start": 1, "line_end": 1}
        row = _relabel(bare, _Cat, 89, "run1", 0)
        assert "provenance" not in row and "validation_status" not in row
