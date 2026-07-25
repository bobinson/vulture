"""Unit tests for check_id-enhanced deduplication in audit_runner."""


from shared.audit_runner import _dedup_key, _deduplicate_findings
from shared.tools.memory_client import _normalize_title


# ---------------------------------------------------------------------------
# _dedup_key prefers check_id when present
# ---------------------------------------------------------------------------

class TestDedupKeyPrefersCheckId:
    """Test that _dedup_key uses check_id over normalized title when available."""

    def test_uses_check_id_when_present(self):
        finding = {
            "check_id": "injection.sql_query",
            "title": "SQL Injection in login handler",
            "file_path": "/src/db.py",
        }
        key = _dedup_key(finding)
        assert key == ("injection.sql_query", "/src/db.py")

    def test_check_id_is_preferred_over_title(self):
        finding = {
            "check_id": "auth.hardcoded_creds",
            "title": "Hardcoded credentials in config",
            "file_path": "/src/config.py",
        }
        key = _dedup_key(finding)
        # Should use check_id, not normalized title
        assert key[0] == "auth.hardcoded_creds"
        assert key[0] != _normalize_title(finding["title"])

    def test_empty_check_id_treated_as_absent(self):
        finding = {
            "check_id": "",
            "title": "SQL Injection in handler",
            "file_path": "/src/db.py",
        }
        key = _dedup_key(finding)
        # Should fall back to normalized title
        expected_title = _normalize_title("SQL Injection in handler")
        assert key == (expected_title, "/src/db.py")


# ---------------------------------------------------------------------------
# _dedup_key falls back to normalized title when no check_id
# ---------------------------------------------------------------------------

class TestDedupKeyFallback:
    """Test _dedup_key fallback to normalized title when check_id is absent."""

    def test_no_check_id_key_uses_title(self):
        finding = {
            "title": "Buffer Overflow at line 42",
            "file_path": "/src/parser.c",
        }
        key = _dedup_key(finding)
        expected_title = _normalize_title("Buffer Overflow at line 42")
        assert key == (expected_title, "/src/parser.c")

    def test_missing_check_id_field_entirely(self):
        finding = {
            "title": "XSS in template",
            "file_path": "/src/template.html",
        }
        key = _dedup_key(finding)
        expected_title = _normalize_title("XSS in template")
        assert key == (expected_title, "/src/template.html")

    def test_missing_file_path_uses_empty_string(self):
        finding = {"title": "Some issue", "check_id": "test.issue"}
        key = _dedup_key(finding)
        assert key == ("test.issue", "")

    def test_missing_title_uses_empty_normalized(self):
        finding = {"file_path": "/src/x.py"}
        key = _dedup_key(finding)
        assert key == (_normalize_title(""), "/src/x.py")


# ---------------------------------------------------------------------------
# _deduplicate_findings with check_ids
# ---------------------------------------------------------------------------

class TestDeduplicateFindingsWithCheckIds:
    """Test _deduplicate_findings using check_id-based deduplication."""

    def test_duplicate_check_ids_removed(self):
        base = [
            {"check_id": "injection.sql", "title": "SQL Injection", "file_path": "/src/db.py"},
            {"check_id": "auth.weak", "title": "Weak Auth", "file_path": "/src/auth.py"},
        ]
        new = [
            {"check_id": "injection.sql", "title": "SQL Injection variant", "file_path": "/src/db.py"},
            {"check_id": "crypto.weak_hash", "title": "Weak Hash", "file_path": "/src/crypto.py"},
        ]
        result = _deduplicate_findings(base, new)
        assert len(result) == 1
        assert result[0]["check_id"] == "crypto.weak_hash"

    def test_same_check_id_different_files_not_deduped(self):
        base = [
            {"check_id": "injection.sql", "title": "SQL Injection", "file_path": "/src/db.py"},
        ]
        new = [
            {"check_id": "injection.sql", "title": "SQL Injection", "file_path": "/src/api.py"},
        ]
        result = _deduplicate_findings(base, new)
        # Different file_path means different key, so it should be kept
        assert len(result) == 1
        assert result[0]["file_path"] == "/src/api.py"

    def test_all_duplicates_produces_empty_list(self):
        base = [
            {"check_id": "a.b", "title": "A", "file_path": "/x.py"},
            {"check_id": "c.d", "title": "C", "file_path": "/y.py"},
        ]
        new = [
            {"check_id": "a.b", "title": "A", "file_path": "/x.py"},
            {"check_id": "c.d", "title": "C", "file_path": "/y.py"},
        ]
        result = _deduplicate_findings(base, new)
        assert result == []

    def test_all_unique_produces_full_list(self):
        base = [
            {"check_id": "a.b", "title": "A", "file_path": "/x.py"},
        ]
        new = [
            {"check_id": "e.f", "title": "E", "file_path": "/z.py"},
            {"check_id": "g.h", "title": "G", "file_path": "/w.py"},
        ]
        result = _deduplicate_findings(base, new)
        assert len(result) == 2

    def test_empty_base_returns_all_new(self):
        new = [
            {"check_id": "a.b", "title": "A", "file_path": "/x.py"},
            {"check_id": "c.d", "title": "C", "file_path": "/y.py"},
        ]
        result = _deduplicate_findings([], new)
        assert len(result) == 2

    def test_empty_new_returns_empty(self):
        base = [
            {"check_id": "a.b", "title": "A", "file_path": "/x.py"},
        ]
        result = _deduplicate_findings(base, [])
        assert result == []


# ---------------------------------------------------------------------------
# _deduplicate_findings mixed (some with check_id, some without)
# ---------------------------------------------------------------------------

class TestDeduplicateFindingsMixed:
    """Test deduplication when some findings have check_id and some do not."""

    def test_check_id_dedup_does_not_match_title_dedup(self):
        """A finding with check_id and one without should not dedup against each other
        even if they have the same title, because their key types differ."""
        base = [
            {"check_id": "injection.sql", "title": "SQL Injection", "file_path": "/src/db.py"},
        ]
        new = [
            {"title": "SQL Injection", "file_path": "/src/db.py"},  # no check_id
        ]
        result = _deduplicate_findings(base, new)
        # Base uses check_id key, new uses title key -- different namespaces
        # So the new finding is NOT a duplicate
        assert len(result) == 1

    def test_title_based_dedup_still_works_for_non_check_id(self):
        base = [
            {"title": "SQL Injection in handler", "file_path": "/src/db.py"},
        ]
        new = [
            {"title": "SQL Injection in handler", "file_path": "/src/db.py"},
        ]
        result = _deduplicate_findings(base, new)
        # Both use title-based dedup, normalized titles match
        assert len(result) == 0

    def test_mixed_findings_preserve_unique_entries(self):
        base = [
            {"check_id": "injection.sql", "title": "SQL Injection", "file_path": "/src/db.py"},
            {"title": "XSS in template", "file_path": "/src/tmpl.html"},
        ]
        new = [
            {"check_id": "injection.sql", "title": "SQL Injection", "file_path": "/src/db.py"},  # dup
            {"title": "XSS in template", "file_path": "/src/tmpl.html"},  # dup
            {"check_id": "crypto.weak", "title": "Weak Crypto", "file_path": "/src/enc.py"},  # new
            {"title": "CSRF vulnerability", "file_path": "/src/form.py"},  # new
        ]
        result = _deduplicate_findings(base, new)
        assert len(result) == 2
        titles = {f.get("title") for f in result}
        assert "Weak Crypto" in titles
        assert "CSRF vulnerability" in titles

    def test_dedup_within_new_list_itself(self):
        """Duplicates within the new list should also be deduped."""
        base = []
        new = [
            {"check_id": "a.b", "title": "A", "file_path": "/x.py"},
            {"check_id": "a.b", "title": "A duplicate", "file_path": "/x.py"},
        ]
        result = _deduplicate_findings(base, new)
        # Second entry has same check_id + file_path as first
        assert len(result) == 1
        assert result[0]["title"] == "A"

    def test_normalized_title_dedup_ignores_line_numbers(self):
        """Titles differing only by line number should dedup."""
        base = [
            {"title": "SQL Injection at line 42", "file_path": "/src/db.py"},
        ]
        new = [
            {"title": "SQL Injection at line 99", "file_path": "/src/db.py"},
        ]
        result = _deduplicate_findings(base, new)
        # _normalize_title strips "at line N", so these should match
        assert len(result) == 0

    def test_normalized_title_dedup_ignores_handler_suffix(self):
        """Titles differing only by 'in X handler' should dedup."""
        base = [
            {"title": "SQL Injection in login handler", "file_path": "/src/db.py"},
        ]
        new = [
            {"title": "SQL Injection in auth handler", "file_path": "/src/db.py"},
        ]
        result = _deduplicate_findings(base, new)
        # _normalize_title strips "in <identifier>" suffixes
        assert len(result) == 0
