"""Unit tests for memory_client token optimization functions."""

from unittest.mock import patch

import pytest

from shared.tools.memory_client import (
    _adapt_prior_findings,
    _dedup_key,
    _fetch_edge_clusters,
    _filter_and_dedup,
    _MAX_CONTEXT_FINDINGS,
    _normalize_title,
    _SEVERITY_RANK,
    _SKIP_STATUSES,
    _staleness_weight,
    _STALENESS_DAYS,
    build_prior_context,
    estimate_tokens,
)


class TestEstimateTokens:
    def test_empty_string(self):
        assert estimate_tokens("") == 1

    def test_short_string(self):
        assert estimate_tokens("hi") == 1

    def test_normal_string(self):
        # 20 chars -> ~5 tokens
        assert estimate_tokens("a" * 20) == 5

    def test_long_string(self):
        assert estimate_tokens("x" * 400) == 100


class TestNormalizeTitle:
    def test_strips_line_numbers(self):
        assert _normalize_title("SQL Injection at line 42") == "sql injection"

    def test_strips_in_handler(self):
        assert _normalize_title("SQL Injection in login handler") == "sql injection"

    def test_preserves_core_title(self):
        assert _normalize_title("Missing retry logic for HTTP call") == "missing retry logic for http call"

    def test_normalizes_case(self):
        assert _normalize_title("CRITICAL XSS") == "critical xss"

    def test_strips_whitespace(self):
        assert _normalize_title("  spaced  ") == "spaced"


class TestStalenessWeight:
    def test_fresh_finding(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        w = _staleness_weight({"created_at": now})
        assert 0.9 < w <= 1.0

    def test_old_finding_zero_weight(self):
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        assert _staleness_weight({"created_at": old}) == 0.0

    def test_missing_created_at(self):
        assert _staleness_weight({}) == 0.5

    def test_invalid_date_string(self):
        assert _staleness_weight({"created_at": "not-a-date"}) == 0.5

    def test_half_life(self):
        from datetime import datetime, timezone, timedelta
        mid = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        w = _staleness_weight({"created_at": mid})
        assert 0.4 < w < 0.6


class TestDedupKey:
    def test_basic_key(self):
        m = {"title": "SQL Injection", "file_paths": ["/src/db.py"]}
        assert _dedup_key(m) == "sql injection|/src/db.py"

    def test_missing_file_paths(self):
        m = {"title": "Missing Auth"}
        assert _dedup_key(m) == "missing auth|"

    def test_empty_file_paths(self):
        m = {"title": "XSS", "file_paths": []}
        assert _dedup_key(m) == "xss|"

    def test_uses_first_path_only(self):
        m = {"title": "Bug", "file_paths": ["/a.py", "/b.py"]}
        assert _dedup_key(m) == "bug|/a.py"

    def test_strips_whitespace(self):
        m = {"title": "  Spaces  ", "file_paths": [" /path "]}
        assert _dedup_key(m) == "spaces|/path"

    def test_fuzzy_dedup_line_numbers(self):
        """Same issue reported at different lines should produce same key."""
        m1 = {"title": "SQL Injection at line 10", "file_paths": ["/db.py"]}
        m2 = {"title": "SQL Injection at line 25", "file_paths": ["/db.py"]}
        assert _dedup_key(m1) == _dedup_key(m2)

    def test_fuzzy_dedup_different_handlers(self):
        """Same vulnerability class with different handler names should produce same key."""
        m1 = {"title": "SQL Injection in login handler", "file_paths": ["/db.py"]}
        m2 = {"title": "SQL Injection in auth handler", "file_paths": ["/db.py"]}
        assert _dedup_key(m1) == _dedup_key(m2)


class TestFilterAndDedup:
    def test_removes_resolved(self):
        memories = [
            {"title": "A", "severity": "high", "remediation_status": "resolved"},
            {"title": "B", "severity": "medium", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == 1
        assert result[0]["title"] == "B"

    def test_removes_false_positive(self):
        memories = [
            {"title": "FP", "severity": "low", "remediation_status": "false_positive"},
        ]
        assert _filter_and_dedup(memories) == []

    def test_deduplicates_by_title_and_path(self):
        memories = [
            {"title": "SQL Inj", "file_paths": ["/db.py"], "severity": "high", "remediation_status": "open"},
            {"title": "SQL Inj", "file_paths": ["/db.py"], "severity": "high", "remediation_status": "open"},
            {"title": "SQL Inj", "file_paths": ["/db.py"], "severity": "critical", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == 1

    def test_different_files_not_deduped(self):
        memories = [
            {"title": "XSS", "file_paths": ["/a.js"], "severity": "high", "remediation_status": "open"},
            {"title": "XSS", "file_paths": ["/b.js"], "severity": "high", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == 2

    def test_sorts_by_severity(self):
        memories = [
            {"title": "Low", "severity": "low", "remediation_status": "open"},
            {"title": "Crit", "severity": "critical", "remediation_status": "open"},
            {"title": "High", "severity": "high", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories)
        assert [m["title"] for m in result] == ["Crit", "High", "Low"]

    def test_caps_at_max(self):
        memories = [
            {"title": f"Finding {i}", "severity": "medium", "remediation_status": "open"}
            for i in range(40)
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == _MAX_CONTEXT_FINDINGS
        assert _MAX_CONTEXT_FINDINGS == 25

    def test_custom_max_count(self):
        memories = [
            {"title": f"Finding {i}", "severity": "medium", "remediation_status": "open"}
            for i in range(40)
        ]
        result = _filter_and_dedup(memories, max_count=5)
        assert len(result) == 5

    def test_fuzzy_dedup_line_numbers(self):
        """Same issue reported at different lines should be deduped."""
        memories = [
            {"title": "SQL Injection at line 10", "file_paths": ["/db.py"], "severity": "critical", "remediation_status": "open"},
            {"title": "SQL Injection at line 25", "file_paths": ["/db.py"], "severity": "critical", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == 1

    def test_fuzzy_dedup_different_handlers(self):
        """Same vulnerability class in same file with different handler names deduped."""
        memories = [
            {"title": "SQL Injection in login handler", "file_paths": ["/db.py"], "severity": "critical", "remediation_status": "open"},
            {"title": "SQL Injection in auth handler", "file_paths": ["/db.py"], "severity": "critical", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == 1

    def test_keeps_in_progress(self):
        memories = [
            {"title": "A", "severity": "high", "remediation_status": "in_progress"},
        ]
        result = _filter_and_dedup(memories)
        assert len(result) == 1

    def test_empty_input(self):
        assert _filter_and_dedup([]) == []

    @patch("shared.tools.memory_client.memory_get_edges")
    def test_edge_based_dedup(self, mock_edges):
        mock_edges.side_effect = lambda mid: [
            {"source_id": "a", "target_id": "b", "relation_type": "same_issue", "strength": 0.9}
        ] if mid == "a" else []
        memories = [
            {"id": "a", "title": "Hardcoded Password", "file_paths": ["/config.py"], "severity": "high", "remediation_status": "open"},
            {"id": "b", "title": "Hardcoded Secret", "file_paths": ["/config.py"], "severity": "high", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories, use_edges=True)
        assert len(result) == 1  # Should be deduped by semantic similarity

    @patch("shared.tools.memory_client.memory_get_edges")
    def test_edge_dedup_preserves_different_issues(self, mock_edges):
        mock_edges.return_value = []  # No edges
        memories = [
            {"id": "a", "title": "SQL Injection", "file_paths": ["/db.py"], "severity": "critical", "remediation_status": "open"},
            {"id": "b", "title": "XSS Attack", "file_paths": ["/web.py"], "severity": "high", "remediation_status": "open"},
        ]
        result = _filter_and_dedup(memories, use_edges=True)
        assert len(result) == 2


class TestFetchEdgeClusters:
    def test_empty_memories(self):
        assert _fetch_edge_clusters([]) == {}

    def test_no_ids(self):
        assert _fetch_edge_clusters([{"title": "A"}]) == {}

    @patch("shared.tools.memory_client.memory_get_edges")
    def test_clusters_same_issue_edges(self, mock_edges):
        mock_edges.side_effect = lambda mid: [
            {"source_id": "a", "target_id": "b", "relation_type": "same_issue", "strength": 0.9}
        ] if mid == "a" else []
        memories = [
            {"id": "a", "title": "Hardcoded Password", "severity": "high"},
            {"id": "b", "title": "Hardcoded Secret", "severity": "high"},
        ]
        clusters = _fetch_edge_clusters(memories)
        assert clusters["a"] == clusters["b"]  # same cluster

    @patch("shared.tools.memory_client.memory_get_edges")
    def test_ignores_weak_edges(self, mock_edges):
        mock_edges.return_value = [
            {"source_id": "a", "target_id": "b", "relation_type": "same_issue", "strength": 0.5}
        ]
        memories = [
            {"id": "a", "title": "A", "severity": "high"},
            {"id": "b", "title": "B", "severity": "high"},
        ]
        clusters = _fetch_edge_clusters(memories)
        assert clusters["a"] != clusters["b"]

    @patch("shared.tools.memory_client.memory_get_edges")
    def test_ignores_non_same_issue(self, mock_edges):
        mock_edges.return_value = [
            {"source_id": "a", "target_id": "b", "relation_type": "related_compliance", "strength": 0.9}
        ]
        memories = [
            {"id": "a", "title": "A", "severity": "high"},
            {"id": "b", "title": "B", "severity": "high"},
        ]
        clusters = _fetch_edge_clusters(memories)
        assert clusters["a"] != clusters["b"]

    @patch("shared.tools.memory_client.memory_get_edges")
    def test_edge_fetch_failure_graceful(self, mock_edges):
        mock_edges.side_effect = Exception("network error")
        memories = [{"id": "a", "title": "A", "severity": "high"}]
        clusters = _fetch_edge_clusters(memories)
        assert clusters == {"a": "a"}  # Each memory is its own cluster


class TestBuildPriorContext:
    @patch("shared.tools.memory_client.memory_get_context")
    def test_returns_empty_when_no_memories(self, mock_ctx):
        mock_ctx.return_value = []
        assert build_prior_context("/code", "owasp") == ""

    @patch("shared.tools.memory_client.memory_get_context")
    def test_returns_empty_when_all_resolved(self, mock_ctx):
        mock_ctx.return_value = [
            {"title": "A", "severity": "high", "remediation_status": "resolved"},
        ]
        assert build_prior_context("/code", "owasp") == ""

    @patch("shared.tools.memory_client.memory_get_context")
    def test_compact_format_with_severity_initial(self, mock_ctx):
        mock_ctx.return_value = [
            {
                "title": "SQL Injection",
                "severity": "critical",
                "category": "injection",
                "file_paths": ["/src/db.py"],
                "remediation_status": "open",
            },
        ]
        result = build_prior_context("/code", "owasp")
        assert "Known issues (1):" in result
        assert "C:[injection] SQL Injection @db.py" in result
        assert "Skip known issues" in result

    @patch("shared.tools.memory_client.memory_get_context")
    def test_shows_duplicates_excluded_count(self, mock_ctx):
        mock_ctx.return_value = [
            {"title": "Dup", "file_paths": ["/a.py"], "severity": "high", "remediation_status": "open"},
            {"title": "Dup", "file_paths": ["/a.py"], "severity": "high", "remediation_status": "open"},
            {"title": "Dup", "file_paths": ["/a.py"], "severity": "high", "remediation_status": "open"},
        ]
        result = build_prior_context("/code", "chaos")
        assert "2 duplicates/resolved excluded" in result

    @patch("shared.tools.memory_client.memory_get_context")
    def test_file_basename_only(self, mock_ctx):
        mock_ctx.return_value = [
            {
                "title": "Bug",
                "severity": "medium",
                "file_paths": ["/very/long/path/to/file.ts"],
                "remediation_status": "open",
            },
        ]
        result = build_prior_context("/code", "chaos")
        # Should show just the filename, not full path
        assert "@file.ts" in result
        assert "/very/long/path" not in result

    @patch("shared.tools.memory_client.memory_get_context")
    def test_no_file_path_still_works(self, mock_ctx):
        mock_ctx.return_value = [
            {
                "title": "General Issue",
                "severity": "info",
                "file_paths": [],
                "remediation_status": "open",
            },
        ]
        result = build_prior_context("/code", "soc2")
        assert "I:General Issue" in result
        assert "@" not in result.split("\n")[1]  # no @ when no file

    @patch("shared.tools.memory_client.memory_get_context")
    def test_token_count_smaller_than_raw(self, mock_ctx):
        """Verify the optimized format uses fewer tokens than raw dump."""
        many = [
            {
                "title": f"Finding {i}",
                "severity": "medium",
                "file_paths": [f"/src/file{i}.py"],
                "remediation_status": "open",
                "content": f"Long description of finding {i} " * 10,
            }
            for i in range(10)
        ]
        # Duplicate each entry 3x to simulate real-world duplication
        mock_ctx.return_value = many * 3

        result = build_prior_context("/code", "owasp")
        compact_tokens = estimate_tokens(result)

        # Raw format: dump all 30 findings with full content
        raw_lines = []
        for m in many * 3:
            raw_lines.append(f"  [{m['severity'].upper()}] {m['title']} ({m['file_paths'][0]}) — open")
        raw_tokens = estimate_tokens("\n".join(raw_lines))

        assert compact_tokens < raw_tokens

    @patch("shared.tools.memory_client.memory_get_context")
    def test_severity_order_in_output(self, mock_ctx):
        mock_ctx.return_value = [
            {"title": "Low", "severity": "low", "remediation_status": "open", "file_paths": []},
            {"title": "Crit", "severity": "critical", "remediation_status": "open", "file_paths": []},
        ]
        result = build_prior_context("/code", "chaos")
        lines = result.split("\n")
        finding_lines = [ln for ln in lines if ln.startswith(" ") and ":" in ln]
        assert "C:Crit" in finding_lines[0]
        assert "L:Low" in finding_lines[1]

    def test_preloaded_skips_api_call(self):
        """When preloaded findings are provided, should not call memory_get_context."""
        preloaded = [
            {"title": "SQL Injection", "severity": "high", "category": "injection",
             "file_path": "/src/db.py", "remediation_status": "open"},
        ]
        result = build_prior_context("/code", "owasp", preloaded=preloaded)
        assert "Known issues (1):" in result
        assert "H:[injection] SQL Injection @db.py" in result

    def test_preloaded_empty_falls_back_to_api(self):
        """Empty preloaded list should fall back to API call."""
        with patch("shared.tools.memory_client.memory_get_context") as mock_ctx:
            mock_ctx.return_value = []
            result = build_prior_context("/code", "owasp", preloaded=[])
            assert result == ""
            mock_ctx.assert_called_once()

    def test_preloaded_filters_resolved(self):
        preloaded = [
            {"title": "A", "severity": "high", "file_path": "/a.py", "remediation_status": "resolved"},
            {"title": "B", "severity": "medium", "file_path": "/b.py", "remediation_status": "open"},
        ]
        result = build_prior_context("/code", "chaos", preloaded=preloaded)
        assert "Known issues (1):" in result
        assert "B" in result
        assert "A" not in result.split("Known issues")[1]

    def test_preloaded_with_no_file_path(self):
        preloaded = [
            {"title": "General", "severity": "info", "remediation_status": "open"},
        ]
        result = build_prior_context("/code", "soc2", preloaded=preloaded)
        assert "I:General" in result

    @patch("shared.tools.memory_client.memory_get_context")
    def test_custom_max_findings(self, mock_ctx):
        mock_ctx.return_value = [
            {"title": f"Finding {i}", "severity": "medium", "file_paths": [f"/f{i}.py"], "remediation_status": "open"}
            for i in range(30)
        ]
        result = build_prior_context("/code", "owasp", max_findings=5)
        lines = [ln for ln in result.split("\n") if ln.startswith(" ") and ":" in ln]
        assert len(lines) == 5

    @patch("shared.tools.memory_client.memory_get_edges")
    @patch("shared.tools.memory_client.memory_get_context")
    def test_api_sourced_uses_edges(self, mock_ctx, mock_edges):
        """When not preloaded, edge-based dedup should be attempted."""
        mock_ctx.return_value = [
            {"id": "a", "title": "Hardcoded Password", "severity": "high", "file_paths": ["/c.py"], "remediation_status": "open"},
            {"id": "b", "title": "Hardcoded Secret", "severity": "high", "file_paths": ["/c.py"], "remediation_status": "open"},
        ]
        mock_edges.side_effect = lambda mid: [
            {"source_id": "a", "target_id": "b", "relation_type": "same_issue", "strength": 0.9}
        ] if mid == "a" else []
        result = build_prior_context("/code", "owasp")
        assert "Known issues (1):" in result  # Should be deduped to 1


class TestAdaptPriorFindings:
    def test_adapts_go_format(self):
        preloaded = [
            {"title": "XSS", "severity": "high", "category": "injection",
             "file_path": "/src/web.js", "remediation_status": "open"},
        ]
        result = _adapt_prior_findings(preloaded)
        assert len(result) == 1
        assert result[0]["title"] == "XSS"
        assert result[0]["file_paths"] == ["/src/web.js"]
        assert result[0]["remediation_status"] == "open"

    def test_handles_missing_file_path(self):
        preloaded = [
            {"title": "Config", "severity": "medium"},
        ]
        result = _adapt_prior_findings(preloaded)
        assert result[0]["file_paths"] == []

    def test_handles_empty_list(self):
        assert _adapt_prior_findings([]) == []

    def test_defaults_for_missing_fields(self):
        preloaded = [{}]
        result = _adapt_prior_findings(preloaded)
        assert result[0]["title"] == ""
        assert result[0]["severity"] == "info"
        assert result[0]["remediation_status"] == "open"
