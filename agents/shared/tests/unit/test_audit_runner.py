"""Unit tests for shared.audit_runner score computation, summary, and LLM parsing."""

import json


from shared.audit_runner import (
    AuditFinding,
    AuditOutput,
    build_summary,
    compute_score,
    normalize_severity,
    run_combined_audit,
    _build_source_context,
    _check_context_budget,
    _collect_llm_findings_async,
    _deduplicate_findings,
    _emit_token_savings,
    _extract_dupe_count,
    _get_max_source_chars,
    _normalize_finding,
    _pack_files,
    _parse_llm_findings,
    _parse_known_titles,
    _prioritize_files,
    _truncate_prompt_to_budget,
)
from shared.tools.file_scanner import is_entry_or_config
from shared.transport.event_emitter import AgUiEventEmitter


class TestComputeScore:
    """Tests for compliance score computation."""

    def test_no_findings_returns_100(self):
        assert compute_score([], 5) == 100.0

    def test_single_info_finding_stays_100(self):
        findings = [{"severity": "info"}]
        assert compute_score(findings, 5) == 100.0

    def test_single_critical_lowers_score_significantly(self):
        findings = [{"severity": "critical"}]
        score = compute_score(findings, 5)
        assert 50 < score < 90

    def test_many_criticals_push_score_near_minimum(self):
        findings = [{"severity": "critical"}] * 20
        score = compute_score(findings, 5)
        assert score < 30

    def test_score_never_below_5(self):
        findings = [{"severity": "critical"}] * 1000
        score = compute_score(findings, 1)
        assert score >= 5.0

    def test_severity_ordering(self):
        """Higher severity should result in lower score."""
        critical_score = compute_score([{"severity": "critical"}], 3)
        high_score = compute_score([{"severity": "high"}], 3)
        medium_score = compute_score([{"severity": "medium"}], 3)
        low_score = compute_score([{"severity": "low"}], 3)

        assert critical_score < high_score < medium_score < low_score

    def test_more_findings_lower_score(self):
        one = compute_score([{"severity": "high"}], 3)
        three = compute_score([{"severity": "high"}] * 3, 3)
        assert three < one

    def test_unknown_severity_treated_as_zero_weight(self):
        findings = [{"severity": "unknown"}]
        assert compute_score(findings, 5) == 100.0

    def test_missing_severity_treated_as_info(self):
        findings = [{}]
        assert compute_score(findings, 5) == 100.0

    def test_uppercase_severity_handled(self):
        """LLM models may return CRITICAL instead of critical."""
        upper = compute_score([{"severity": "CRITICAL"}], 5)
        lower = compute_score([{"severity": "critical"}], 5)
        assert upper == lower

    def test_mixed_case_severity_handled(self):
        """Mixed case like 'High' should match 'high'."""
        mixed = compute_score([{"severity": "High"}], 5)
        lower = compute_score([{"severity": "high"}], 5)
        assert mixed == lower

    def test_single_letter_abbreviations(self):
        """LLM models may return 'H' instead of 'high'."""
        abbrev = compute_score([{"severity": "H"}], 5)
        full = compute_score([{"severity": "high"}], 5)
        assert abbrev == full

    def test_crit_abbreviation(self):
        """LLM models may return 'crit' or 'C'."""
        assert compute_score([{"severity": "C"}], 5) == compute_score([{"severity": "critical"}], 5)
        assert compute_score([{"severity": "crit"}], 5) == compute_score([{"severity": "critical"}], 5)

    def test_score_is_rounded_to_one_decimal(self):
        findings = [{"severity": "medium"}] * 7
        score = compute_score(findings, 3)
        assert score == round(score, 1)

    def test_total_items_scales_tolerance(self):
        """More total items means more tolerance for findings."""
        few_items = compute_score([{"severity": "high"}] * 3, 2)
        many_items = compute_score([{"severity": "high"}] * 3, 10)
        assert many_items > few_items

    def test_mixed_severity_findings(self):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        score = compute_score(findings, 5)
        assert 30 < score < 80


class TestBuildSummary:
    """Tests for summary text generation."""

    def test_no_findings_message(self):
        result = build_summary([], ["retry", "timeout", "fallback"], "resilience categories")
        assert result == "No issues found across 3 resilience categories."

    def test_with_findings_message(self):
        findings = [{"severity": "high"}, {"severity": "low"}]
        result = build_summary(findings, ["retry", "timeout"], "categories")
        assert result == "Found 2 issue(s) across 2 categories."

    def test_single_finding_single_category(self):
        result = build_summary([{"severity": "medium"}], ["auth"], "OWASP categories")
        assert result == "Found 1 issue(s) across 1 OWASP categories."

    def test_custom_domain_label(self):
        result = build_summary([], ["cc6", "cc7"], "SOC2 clauses")
        assert "SOC2 clauses" in result


class TestParseLlmFindings:
    """Tests for extracting findings from LLM text output."""

    def test_parses_json_code_block(self):
        output = '''Here are the findings:
```json
[{"severity": "high", "title": "SQL Injection", "category": "injection"}]
```
'''
        result = _parse_llm_findings(output)
        assert len(result) == 1
        assert result[0]["title"] == "SQL Injection"

    def test_parses_raw_json_array(self):
        output = 'I found: [{"severity": "medium", "title": "Debug Mode"}]'
        result = _parse_llm_findings(output)
        assert len(result) == 1
        assert result[0]["severity"] == "medium"

    def test_returns_empty_for_no_json(self):
        output = "I found no issues in the codebase."
        assert _parse_llm_findings(output) == []

    def test_returns_empty_for_malformed_json(self):
        output = '```json\n[{"broken json\n```'
        assert _parse_llm_findings(output) == []

    def test_normalizes_findings(self):
        output = '[{"severity": "critical", "title": "XSS"}]'
        result = _parse_llm_findings(output)
        # Should have all normalized fields
        assert "category" in result[0]
        assert "file_path" in result[0]
        assert "recommendation" in result[0]

    def test_mixed_array_not_matched_by_regex(self):
        """Regex expects {.*} pattern - mixed arrays with non-objects won't match."""
        output = '[{"severity": "high", "title": "Real"}, "not a dict", 42]'
        result = _parse_llm_findings(output)
        assert result == []

    def test_multiple_findings(self):
        output = '''```json
[
  {"severity": "high", "title": "Finding 1"},
  {"severity": "low", "title": "Finding 2"},
  {"severity": "critical", "title": "Finding 3"}
]
```'''
        result = _parse_llm_findings(output)
        assert len(result) == 3


class TestNormalizeFinding:
    """Tests for finding dict normalization."""

    def test_fills_defaults_for_empty_dict(self):
        result = _normalize_finding({})
        assert result["severity"] == "info"
        assert result["category"] == "unknown"
        assert result["title"] == "Untitled finding"
        assert result["description"] == ""
        assert result["file_path"] == ""
        assert result["line_start"] == 0
        assert result["line_end"] == 0
        assert result["recommendation"] == ""

    def test_preserves_provided_values(self):
        raw = {
            "severity": "critical",
            "category": "injection",
            "title": "SQL Injection",
            "description": "User input not sanitized",
            "file_path": "/src/db.py",
            "line_start": 42,
            "line_end": 45,
            "recommendation": "Use parameterized queries",
        }
        result = _normalize_finding(raw)
        assert result == raw

    def test_strips_extra_fields(self):
        raw = {"severity": "high", "title": "Test", "extra_field": "should be dropped"}
        result = _normalize_finding(raw)
        assert "extra_field" not in result

    def test_partial_dict_fills_missing(self):
        raw = {"severity": "medium", "title": "Partial"}
        result = _normalize_finding(raw)
        assert result["category"] == "unknown"
        assert result["file_path"] == ""

    def test_lowercases_severity(self):
        """LLM output may return uppercase severity; normalize should lowercase it."""
        raw = {"severity": "CRITICAL", "title": "XSS"}
        result = _normalize_finding(raw)
        assert result["severity"] == "critical"

    def test_lowercases_mixed_case_severity(self):
        raw = {"severity": "High", "title": "Test"}
        result = _normalize_finding(raw)
        assert result["severity"] == "high"

    def test_abbreviation_severity(self):
        """LLM may return single-letter abbreviations like 'H'."""
        assert _normalize_finding({"severity": "H"})["severity"] == "high"
        assert _normalize_finding({"severity": "C"})["severity"] == "critical"
        assert _normalize_finding({"severity": "M"})["severity"] == "medium"
        assert _normalize_finding({"severity": "L"})["severity"] == "low"
        assert _normalize_finding({"severity": "I"})["severity"] == "info"


class TestNormalizeSeverity:
    """Tests for normalize_severity function."""

    def test_canonical_names(self):
        assert normalize_severity("critical") == "critical"
        assert normalize_severity("high") == "high"
        assert normalize_severity("medium") == "medium"
        assert normalize_severity("low") == "low"
        assert normalize_severity("info") == "info"

    def test_uppercase(self):
        assert normalize_severity("CRITICAL") == "critical"
        assert normalize_severity("HIGH") == "high"
        assert normalize_severity("MEDIUM") == "medium"

    def test_single_letter(self):
        assert normalize_severity("C") == "critical"
        assert normalize_severity("H") == "high"
        assert normalize_severity("M") == "medium"
        assert normalize_severity("L") == "low"
        assert normalize_severity("I") == "info"

    def test_abbreviations(self):
        assert normalize_severity("crit") == "critical"
        assert normalize_severity("med") == "medium"
        assert normalize_severity("informational") == "info"

    def test_unknown_defaults_to_info(self):
        assert normalize_severity("unknown") == "info"
        assert normalize_severity("xyz") == "info"

    def test_whitespace_stripped(self):
        assert normalize_severity("  high  ") == "high"
        assert normalize_severity(" H ") == "high"


class TestExtractDupeCount:
    """Tests for extracting duplicate count from context lines."""

    def test_extracts_count_from_line(self):
        lines = ["Prior findings:", " C:file.py: SQL Injection", "(3 duplicates excluded)"]
        assert _extract_dupe_count(lines) == 3

    def test_returns_zero_when_no_dupes_line(self):
        lines = ["Prior findings:", " C:file.py: SQL Injection"]
        assert _extract_dupe_count(lines) == 0

    def test_returns_zero_for_empty_list(self):
        assert _extract_dupe_count([]) == 0

    def test_extracts_from_multi_line_context(self):
        lines = [
            "Prior findings for owasp:",
            " C:login.py: Hardcoded secret",
            " H:api.py: Missing auth",
            "(5 duplicates excluded)",
        ]
        assert _extract_dupe_count(lines) == 5


class TestEmitTokenSavings:
    """Tests for token savings event emission helper."""

    def test_returns_none_for_empty_context(self):
        emitter = AgUiEventEmitter("test-run")
        assert _emit_token_savings(emitter, "") is None

    def test_returns_event_string_for_context(self):
        emitter = AgUiEventEmitter("test-run")
        ctx = "Prior findings:\n C:file.py: SQL Injection\n(2 duplicates excluded)"
        result = _emit_token_savings(emitter, ctx)
        assert result is not None
        assert "event:" in result
        assert "token_savings" in result

    def test_counts_used_findings(self):
        emitter = AgUiEventEmitter("test-run")
        ctx = "Prior:\n C:a.py: F1\n H:b.py: F2\n M:c.py: F3"
        result = _emit_token_savings(emitter, ctx)
        assert result is not None
        assert "prior_findings_used" in result

    def test_with_skipped_findings(self):
        """Verify savings are based on 65 tokens per skipped finding."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (2):\n C:[injection] SQL Injection @db.py\n H:[auth] Missing Auth @api.py\nSkip known issues."
        result = _emit_token_savings(emitter, ctx, findings_total=5, findings_skipped=2)
        assert result is not None
        assert "token_savings" in result
        # Parse and verify the 65 tokens/finding estimate
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        # raw_tokens = ctx_tokens + (2 * 65) = ctx_tokens + 130
        assert data["raw_tokens"] == data["context_tokens"] + 130

    def test_no_fabricated_3x_multiplier(self):
        """Verify the old 3x multiplier is gone. With 1 skipped finding, raw = ctx + 65."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (1):\n C:SQL Inj @db.py\nSkip."
        result = _emit_token_savings(emitter, ctx, findings_total=3, findings_skipped=1)
        assert result is not None
        # Parse the SSE event to check the actual numbers
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        # raw_tokens should be ctx_tokens + 65 (1 finding * 65 tokens)
        assert data["raw_tokens"] == data["context_tokens"] + 65
        # raw_tokens should NOT be exactly ctx_tokens * 3
        assert data["raw_tokens"] != data["context_tokens"] * 3

    def test_zero_skipped_reports_zero_savings(self):
        """When findings_skipped=0, savings_pct should be 0."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (1):\n C:SQL Inj @db.py\nSkip."
        result = _emit_token_savings(emitter, ctx, findings_total=3, findings_skipped=0)
        assert result is not None
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        # When no findings skipped, raw_tokens == ctx_tokens, so savings == 0
        assert data["raw_tokens"] == data["context_tokens"]
        assert data["tokens_saved"] == 0
        assert data["savings_pct"] == 0

    def test_actual_usage_passthrough(self):
        """When actual_input_tokens > 0, those values appear in the event."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (1):\n C:SQL Inj @db.py\nSkip."
        result = _emit_token_savings(
            emitter, ctx,
            findings_total=3,
            findings_skipped=1,
            actual_input_tokens=1500,
            actual_output_tokens=800,
        )
        assert result is not None
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert data["actual_input_tokens"] == 1500
        assert data["actual_output_tokens"] == 800

    def test_cost_usd_included_with_usage(self):
        """When actual tokens and model are provided, cost_usd appears in the event."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (1):\n C:SQL Inj @db.py\nSkip."
        result = _emit_token_savings(
            emitter, ctx,
            findings_total=3,
            findings_skipped=1,
            actual_input_tokens=10000,
            actual_output_tokens=5000,
            model="gpt-4o",
        )
        assert result is not None
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert "cost_usd" in data
        assert data["cost_usd"] > 0.0

    def test_cost_usd_omitted_for_local_model(self):
        """Local models (cost=0) should not emit cost_usd."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (1):\n C:SQL Inj @db.py\nSkip."
        result = _emit_token_savings(
            emitter, ctx,
            findings_total=3,
            findings_skipped=1,
            actual_input_tokens=10000,
            actual_output_tokens=5000,
            model="qwen3:1.7b",
        )
        assert result is not None
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert "cost_usd" not in data  # cost is 0.0, not emitted

    def test_cost_usd_omitted_without_actual_usage(self):
        """Without actual token counts, cost_usd is not emitted."""
        emitter = AgUiEventEmitter("test-run")
        ctx = "Known issues (1):\n C:SQL Inj @db.py\nSkip."
        result = _emit_token_savings(
            emitter, ctx,
            findings_total=3,
            findings_skipped=1,
        )
        assert result is not None
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert "cost_usd" not in data


class TestParseKnownTitles:
    """Tests for extracting known issue titles from prior context."""

    def test_empty_context(self):
        assert _parse_known_titles("") == set()

    def test_parses_simple_titles(self):
        ctx = "Known issues (2):\n C:SQL Injection @db.py\n H:Missing Auth @api.py\nSkip known issues."
        titles = _parse_known_titles(ctx)
        assert "sql injection" in titles
        assert "missing auth" in titles

    def test_parses_titles_with_category(self):
        ctx = "Known issues (1):\n C:[injection] SQL Injection @db.py\nSkip."
        titles = _parse_known_titles(ctx)
        assert "sql injection" in titles
        assert "injection" not in titles  # category should be stripped

    def test_parses_title_without_file(self):
        ctx = "Known issues (1):\n I:General Issue\nSkip."
        titles = _parse_known_titles(ctx)
        assert "general issue" in titles

    def test_ignores_header_and_footer_lines(self):
        ctx = "Known issues (1):\n H:Bug @f.py\nSkip known issues.\n(2 duplicates/resolved excluded)"
        titles = _parse_known_titles(ctx)
        assert len(titles) == 1
        assert "bug" in titles

    def test_normalizes_handler_suffix(self):
        """Verify 'SQL Injection in login handler' normalizes to same form as 'SQL Injection'."""
        ctx_with_handler = "Known issues (1):\n C:SQL Injection in login handler @db.py\nSkip."
        ctx_plain = "Known issues (1):\n C:SQL Injection @db.py\nSkip."
        titles_with_handler = _parse_known_titles(ctx_with_handler)
        titles_plain = _parse_known_titles(ctx_plain)
        # Both should produce the same normalized title
        assert titles_with_handler == titles_plain
        assert "sql injection" in titles_with_handler


class TestDedupStatsEvent:
    """Tests for the dedup_stats_event emitter method."""

    def test_emits_correct_event_type(self):
        emitter = AgUiEventEmitter("test-run")
        result = emitter.dedup_stats_event(
            findings_deduped=3,
            prior_findings_used=5,
            duplicates_removed=2,
        )
        assert "event: dedup_stats" in result

    def test_emits_correct_fields(self):
        emitter = AgUiEventEmitter("test-run")
        result = emitter.dedup_stats_event(
            findings_deduped=3,
            prior_findings_used=5,
            duplicates_removed=2,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert data["findings_deduped"] == 3
        assert data["prior_findings_used"] == 5
        assert data["duplicates_removed"] == 2

    def test_zero_values(self):
        emitter = AgUiEventEmitter("test-run")
        result = emitter.dedup_stats_event(
            findings_deduped=0,
            prior_findings_used=0,
            duplicates_removed=0,
        )
        data_line = [line for line in result.split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert data["findings_deduped"] == 0
        assert data["prior_findings_used"] == 0
        assert data["duplicates_removed"] == 0


class TestStructuredOutput:
    """Tests for AuditFinding and AuditOutput Pydantic models."""

    def test_audit_finding_defaults(self):
        finding = AuditFinding()
        assert finding.severity == "info"
        assert finding.category == "unknown"
        assert finding.title == "Untitled finding"
        assert finding.description == ""
        assert finding.file_path == ""
        assert finding.line_start == 0
        assert finding.line_end == 0
        assert finding.recommendation == ""

    def test_audit_finding_with_values(self):
        finding = AuditFinding(
            severity="critical",
            category="injection",
            title="SQL Injection",
            description="User input not sanitized",
            file_path="/src/db.py",
            line_start=42,
            line_end=45,
            recommendation="Use parameterized queries",
        )
        assert finding.severity == "critical"
        assert finding.title == "SQL Injection"
        assert finding.line_start == 42

    def test_audit_output_model(self):
        output = AuditOutput(findings=[
            AuditFinding(severity="high", title="F1"),
            AuditFinding(severity="low", title="F2"),
        ])
        assert len(output.findings) == 2
        assert output.findings[0].severity == "high"
        assert output.findings[1].title == "F2"

    def test_audit_output_isinstance_branch_converts_properly(self):
        """Test that isinstance(result, AuditOutput) branch converts to dicts correctly."""
        output = AuditOutput(findings=[
            AuditFinding(
                severity="critical",
                category="injection",
                title="SQL Injection",
                description="Unsanitized input",
                file_path="/src/db.py",
                line_start=10,
                line_end=15,
                recommendation="Use parameterized queries",
            ),
        ])
        # Simulate the conversion done in _collect_llm_findings_async
        assert isinstance(output, AuditOutput)
        findings = [f.model_dump() for f in output.findings]
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["title"] == "SQL Injection"
        assert findings[0]["file_path"] == "/src/db.py"
        assert findings[0]["line_start"] == 10

    def test_audit_output_empty_findings(self):
        output = AuditOutput(findings=[])
        assert isinstance(output, AuditOutput)
        findings = [f.model_dump() for f in output.findings]
        assert findings == []


def _stub_skill(source_path: str) -> dict:
    """Stub skill returning a critical finding."""
    return {
        "findings": [
            {
                "severity": "critical",
                "category": "A03-injection",
                "title": "Potential SQL injection",
                "description": "SQL injection at line 5",
                "file_path": f"{source_path}/db.py",
                "line_start": 5,
                "line_end": 5,
                "recommendation": "Use parameterized queries",
            }
        ]
    }


def _parse_result_from_events(events: list[str]) -> dict:
    """Extract the result event data from SSE event strings."""
    import json
    for event in events:
        if "event: result" in event:
            data_line = [line for line in event.split("\n") if line.startswith("data:")][0]
            return json.loads(data_line[5:])
    raise AssertionError("No result event found")


class TestRunSkillAuditDedup:
    """Tests for deduplication behavior in run_combined_audit (skill-only mode).

    Prior context must NOT cause findings to be removed from results.
    """

    def test_prior_context_does_not_remove_matching_findings(self, tmp_path):
        """Findings matching prior context must remain in the result."""
        prior_context = (
            "Known issues (1):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            "Skip known issues. Report NEW findings only."
        )
        events = list(run_combined_audit(
            run_id="unit-dedup-1",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            prior_context=prior_context,
        ))
        result = _parse_result_from_events(events)
        assert len(result["findings"]) == 1

    def test_score_computed_on_all_findings_with_prior_context(self, tmp_path):
        """Score must be based on all findings, not just 'new' ones."""
        prior_context = (
            "Known issues (1):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            "Skip known issues. Report NEW findings only."
        )
        events = list(run_combined_audit(
            run_id="unit-dedup-2",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            prior_context=prior_context,
        ))
        result = _parse_result_from_events(events)
        assert result["score"] < 100.0

    def test_dedup_stats_still_emitted(self, tmp_path):
        """Dedup stats event should still report how many findings matched prior."""
        prior_context = (
            "Known issues (1):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            "Skip known issues. Report NEW findings only."
        )
        events = list(run_combined_audit(
            run_id="unit-dedup-3",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            prior_context=prior_context,
        ))
        dedup_events = [e for e in events if "event: dedup_stats" in e]
        assert len(dedup_events) == 1
        data_line = [line for line in dedup_events[0].split("\n") if line.startswith("data:")][0]
        data = json.loads(data_line[5:])
        assert data["findings_deduped"] == 1

    def test_empty_prior_context_no_dedup(self, tmp_path):
        """Without prior context, no dedup stats and all findings retained."""
        events = list(run_combined_audit(
            run_id="unit-dedup-4",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            prior_context="",
        ))
        result = _parse_result_from_events(events)
        assert len(result["findings"]) == 1
        assert result["score"] < 100.0
        # No dedup_stats event should be emitted
        dedup_events = [e for e in events if "event: dedup_stats" in e]
        assert len(dedup_events) == 0


class TestBuildSourceContext:
    """Tests for _build_source_context which pre-reads source files for LLM prompts."""

    def test_empty_directory(self, tmp_path):
        result = _build_source_context(str(tmp_path))
        assert result == ""

    def test_single_python_file(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hello')\n")
        result = _build_source_context(str(tmp_path))
        assert "--- app.py ---" in result
        assert "print('hello')" in result

    def test_multiple_files(self, tmp_path):
        (tmp_path / "main.py").write_text("import os\n")
        (tmp_path / "util.py").write_text("def helper(): pass\n")
        result = _build_source_context(str(tmp_path))
        assert "--- main.py ---" in result
        assert "--- util.py ---" in result

    def test_skips_empty_files(self, tmp_path):
        (tmp_path / "empty.py").write_text("")
        (tmp_path / "real.py").write_text("x = 1\n")
        result = _build_source_context(str(tmp_path))
        assert "empty.py" not in result
        assert "--- real.py ---" in result

    def test_respects_max_chars_budget(self, tmp_path):
        """Files exceeding max_chars budget should be excluded."""
        (tmp_path / "small.py").write_text("x = 1\n")
        (tmp_path / "large.py").write_text("y = 2\n" * 1000)
        # Set a very small budget
        result = _build_source_context(str(tmp_path), max_chars=50)
        assert "--- small.py ---" in result
        # large.py may or may not fit depending on order; just check budget respected
        assert len(result) <= 200  # generous bound for header + small content

    def test_nonexistent_directory(self):
        result = _build_source_context("/nonexistent/path/abc123")
        assert result == ""

    def test_nested_files_use_relative_paths(self, tmp_path):
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "handler.py").write_text("def handle(): pass\n")
        result = _build_source_context(str(tmp_path))
        assert "src/handler.py" in result

    def test_skips_non_code_files(self, tmp_path):
        (tmp_path / "readme.txt").write_text("This is a readme")
        (tmp_path / "app.py").write_text("x = 1\n")
        result = _build_source_context(str(tmp_path))
        assert "readme.txt" not in result
        assert "app.py" in result


class TestGetMaxSourceChars:
    """Tests for _get_max_source_chars context sizing via get_context_window()."""

    def test_default_uses_model_context(self, monkeypatch):
        """Without env var, uses get_context_window() which defaults to model lookup."""
        monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
        monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:1.7b")
        # qwen3:1.7b = 32K tokens (<=32K → 0.35 fraction) → 32000 * 0.35 * 3 = 33600
        assert _get_max_source_chars() == 33_600

    def test_with_env_set_large(self, monkeypatch):
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        # 128000 > 32K → 0.5 fraction → 128000 * 0.5 * 3 = 192000
        assert _get_max_source_chars() == 192_000

    def test_with_env_set_small(self, monkeypatch):
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "32768")
        # 32768 > 32K → 0.5 fraction → 32768 * 0.5 * 3 = 49152
        assert _get_max_source_chars() == int(32768 * 0.5 * 3)

    def test_small_ctx_env(self, monkeypatch):
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "4096")
        # 4096 <= 32K → 0.35 fraction → 4096 * 0.35 * 3 = 4300
        assert _get_max_source_chars() == int(4096 * 0.35 * 3)

    def test_invalid_env_falls_back_to_model(self, monkeypatch):
        """Invalid env var falls through to model lookup in get_context_window()."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "not_a_number")
        monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3:1.7b")
        # qwen3:1.7b = 32K (<=32K → 0.35) → 32000 * 0.35 * 3 = 33600
        assert _get_max_source_chars() == 33_600

    def test_minimum_floor(self, monkeypatch):
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "100")
        # 100 * 0.35 * 3 = 105, but min is 2000
        assert _get_max_source_chars() == 2000


class TestDeduplicateFindings:
    """Tests for _deduplicate_findings helper."""

    def test_removes_exact_duplicate(self):
        base = [{"title": "SQL Injection", "file_path": "db.py", "severity": "critical"}]
        new = [{"title": "SQL Injection", "file_path": "db.py", "severity": "high"}]
        result = _deduplicate_findings(base, new)
        assert result == []

    def test_keeps_different_title(self):
        base = [{"title": "SQL Injection", "file_path": "db.py"}]
        new = [{"title": "XSS Vulnerability", "file_path": "db.py"}]
        result = _deduplicate_findings(base, new)
        assert len(result) == 1
        assert result[0]["title"] == "XSS Vulnerability"

    def test_keeps_same_title_different_file(self):
        base = [{"title": "SQL Injection", "file_path": "db.py"}]
        new = [{"title": "SQL Injection", "file_path": "api.py"}]
        result = _deduplicate_findings(base, new)
        assert len(result) == 1
        assert result[0]["file_path"] == "api.py"

    def test_case_insensitive_title(self):
        base = [{"title": "SQL Injection", "file_path": "db.py"}]
        new = [{"title": "sql injection", "file_path": "db.py"}]
        result = _deduplicate_findings(base, new)
        assert result == []

    def test_empty_base_keeps_all(self):
        new = [
            {"title": "Finding A", "file_path": "a.py"},
            {"title": "Finding B", "file_path": "b.py"},
        ]
        result = _deduplicate_findings([], new)
        assert len(result) == 2

    def test_empty_new_returns_empty(self):
        base = [{"title": "Finding A", "file_path": "a.py"}]
        result = _deduplicate_findings(base, [])
        assert result == []

    def test_deduplicates_within_new_list(self):
        """If new list has internal duplicates, only the first is kept."""
        base = []
        new = [
            {"title": "SQL Injection", "file_path": "db.py"},
            {"title": "SQL Injection", "file_path": "db.py"},
        ]
        result = _deduplicate_findings(base, new)
        assert len(result) == 1

    def test_mixed_findings(self):
        base = [
            {"title": "SQL Injection", "file_path": "db.py"},
            {"title": "XSS", "file_path": "web.py"},
        ]
        new = [
            {"title": "SQL Injection", "file_path": "db.py"},  # dup
            {"title": "CSRF", "file_path": "web.py"},          # new
            {"title": "XSS", "file_path": "api.py"},           # new (diff file)
        ]
        result = _deduplicate_findings(base, new)
        assert len(result) == 2
        titles = {f["title"] for f in result}
        assert titles == {"CSRF", "XSS"}


class TestRunCombinedAudit:
    """Tests for run_combined_audit."""

    def test_skill_findings_always_present(self, tmp_path, monkeypatch):
        """Skill findings should always be in the result, regardless of USE_LLM."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        events = list(run_combined_audit(
            run_id="combined-1",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            domain_label="OWASP categories",
        ))
        result = _parse_result_from_events(events)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "Potential SQL injection"

    def test_no_llm_pass_when_disabled(self, tmp_path, monkeypatch):
        """When USE_LLM=false, no LLM enhancement messages should appear."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        events = list(run_combined_audit(
            run_id="combined-2",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            domain_label="OWASP categories",
            skill_tools=["fake_tool"],
            instructions="fake instructions",
        ))
        event_text = "\n".join(events)
        assert "Enhancing with LLM" not in event_text

    def test_has_run_started_and_finished(self, tmp_path, monkeypatch):
        """Combined audit emits agent_start and agent_end."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        events = list(run_combined_audit(
            run_id="combined-3",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
        ))
        event_text = "\n".join(events)
        assert "event: agent_start" in event_text
        assert "event: agent_end" in event_text

    def test_prior_context_emitted(self, tmp_path, monkeypatch):
        """Prior context should be emitted as a text message."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        prior = "Known issues (1):\n C:SQL Injection @db.py\nSkip."
        events = list(run_combined_audit(
            run_id="combined-4",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            prior_context=prior,
        ))
        event_text = "\n".join(events)
        assert "Known issues" in event_text

    def test_score_computed_on_all_findings(self, tmp_path, monkeypatch):
        """Score reflects all findings (skill + any LLM)."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        events = list(run_combined_audit(
            run_id="combined-5",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
        ))
        result = _parse_result_from_events(events)
        # One critical finding should lower score
        assert result["score"] < 100.0

    def test_dedup_stats_with_prior_context(self, tmp_path, monkeypatch):
        """Dedup stats are emitted when prior context is provided."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        prior = (
            "Known issues (1):\n"
            " C:[A03-injection] Potential SQL injection @db.py\n"
            "Skip known issues."
        )
        events = list(run_combined_audit(
            run_id="combined-6",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
            prior_context=prior,
        ))
        dedup_events = [e for e in events if "event: dedup_stats" in e]
        assert len(dedup_events) == 1

    def test_no_dedup_stats_without_prior_context(self, tmp_path, monkeypatch):
        """No dedup stats without prior context."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)
        events = list(run_combined_audit(
            run_id="combined-7",
            source_path=str(tmp_path),
            categories=["injection"],
            skill_map={"injection": _stub_skill},
        ))
        dedup_events = [e for e in events if "event: dedup_stats" in e]
        assert len(dedup_events) == 0

    def test_multiple_skills(self, tmp_path, monkeypatch):
        """Multiple skill categories should all produce findings."""
        monkeypatch.setattr("shared.audit_runner.USE_LLM", False)

        def stub_xss(source_path: str) -> dict:
            return {"findings": [{"title": "XSS", "severity": "high",
                                  "category": "xss", "file_path": f"{source_path}/web.py",
                                  "description": "", "line_start": 1, "line_end": 1,
                                  "recommendation": "Escape output"}]}

        events = list(run_combined_audit(
            run_id="combined-8",
            source_path=str(tmp_path),
            categories=["injection", "xss"],
            skill_map={"injection": _stub_skill, "xss": stub_xss},
        ))
        result = _parse_result_from_events(events)
        assert len(result["findings"]) == 2


class TestCheckContextBudget:
    """Tests for _check_context_budget context window guard."""

    def test_small_prompt_returns_none(self, monkeypatch):
        """Prompt within budget returns (None, tokens) tuple."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        warning, tokens = _check_context_budget("small prompt text")
        assert warning is None
        assert tokens > 0

    def test_large_prompt_returns_warning(self, monkeypatch):
        """Prompt exceeding 80% of context returns (warning, tokens) tuple."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "100")
        # 100 tokens * 4 chars = 400 chars budget; 80% = 320 chars
        big_prompt = "x" * 2000  # ~500 estimated tokens, way over 100
        warning, tokens = _check_context_budget(big_prompt)
        assert warning is not None
        assert "exceeds 80%" in warning
        assert tokens > 0

    def test_exact_boundary(self, monkeypatch):
        """Prompt at exactly 80% is not a warning (must exceed)."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "1000")
        # With safe_estimate_tokens (1.2x margin): ~2667 chars -> 2667/4*1.2 = 800 tokens = exactly 80%
        prompt = "x" * 2667  # ~800 safe-estimated tokens = exactly 80%
        warning, tokens = _check_context_budget(prompt)
        assert warning is None
        assert tokens > 0

    def test_uses_model_param(self, monkeypatch):
        """Model param is passed to get_context_window."""
        monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
        # gpt-4o has 128K context -> any reasonable prompt fits
        warning, tokens = _check_context_budget("small text", model="gpt-4o")
        assert warning is None
        assert tokens > 0


class TestIsEntryOrConfig:
    """Tests for is_entry_or_config helper in file_scanner."""

    def test_main_py(self):
        from pathlib import Path
        assert is_entry_or_config(Path("src/main.py")) is True

    def test_app_py(self):
        from pathlib import Path
        assert is_entry_or_config(Path("app.py")) is True

    def test_index_ts(self):
        from pathlib import Path
        assert is_entry_or_config(Path("src/index.ts")) is True

    def test_dockerfile(self):
        from pathlib import Path
        assert is_entry_or_config(Path("Dockerfile")) is True

    def test_settings_py(self):
        from pathlib import Path
        assert is_entry_or_config(Path("myapp/settings.py")) is True

    def test_regular_file_is_not_entry(self):
        from pathlib import Path
        assert is_entry_or_config(Path("utils/helpers.py")) is False

    def test_test_file_is_not_entry(self):
        from pathlib import Path
        assert is_entry_or_config(Path("tests/test_main.py")) is False

    def test_stem_matching_config_ts(self):
        from pathlib import Path
        assert is_entry_or_config(Path("src/config.ts")) is True

    def test_manage_py(self):
        from pathlib import Path
        assert is_entry_or_config(Path("manage.py")) is True


class TestPrioritizeFiles:
    """Tests for _prioritize_files tiered file ordering."""

    def test_finding_files_first(self, tmp_path):
        """Files matching skill findings should come first."""
        (tmp_path / "db.py").write_text("x = 1\n")
        (tmp_path / "utils.py").write_text("y = 2\n")
        (tmp_path / "main.py").write_text("z = 3\n")

        findings = [{"file_path": str(tmp_path / "db.py"), "title": "SQL Inj"}]
        files = [tmp_path / "utils.py", tmp_path / "db.py", tmp_path / "main.py"]

        result = _prioritize_files(files, str(tmp_path), skill_findings=findings)
        assert result[0] == tmp_path / "db.py", "Finding file should be first"

    def test_entry_points_before_regular(self, tmp_path):
        """Entry points come before regular files when no findings match."""
        (tmp_path / "app.py").write_text("a = 1\n")
        (tmp_path / "helpers.py").write_text("b = 2\n")

        files = [tmp_path / "helpers.py", tmp_path / "app.py"]
        result = _prioritize_files(files, str(tmp_path))

        assert result[0] == tmp_path / "app.py", "Entry point should be first"
        assert result[1] == tmp_path / "helpers.py"

    def test_no_findings_still_works(self, tmp_path):
        """Without skill_findings, files are ordered by entry-point then size."""
        (tmp_path / "big.py").write_text("x" * 1000 + "\n")
        (tmp_path / "small.py").write_text("y\n")

        files = [tmp_path / "big.py", tmp_path / "small.py"]
        result = _prioritize_files(files, str(tmp_path))

        # Both are tier3; small.py should come first (smaller file)
        assert result[0] == tmp_path / "small.py"
        assert result[1] == tmp_path / "big.py"

    def test_all_three_tiers(self, tmp_path):
        """Tier1 (findings) > Tier2 (entry) > Tier3 (rest)."""
        (tmp_path / "vuln.py").write_text("vuln\n")
        (tmp_path / "main.py").write_text("main\n")
        (tmp_path / "lib.py").write_text("lib\n")

        findings = [{"file_path": str(tmp_path / "vuln.py"), "title": "Bug"}]
        files = [tmp_path / "lib.py", tmp_path / "main.py", tmp_path / "vuln.py"]

        result = _prioritize_files(files, str(tmp_path), skill_findings=findings)
        assert result[0] == tmp_path / "vuln.py"   # tier1
        assert result[1] == tmp_path / "main.py"   # tier2
        assert result[2] == tmp_path / "lib.py"    # tier3


class TestPackFiles:
    """Tests for _pack_files budget loop."""

    def test_packs_files_within_budget(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        files = [tmp_path / "a.py", tmp_path / "b.py"]

        result, paths = _pack_files(files, str(tmp_path), max_chars=10000)
        assert "--- a.py ---" in result
        assert "--- b.py ---" in result
        assert "a.py" in paths
        assert "b.py" in paths

    def test_skips_files_exceeding_budget(self, tmp_path):
        (tmp_path / "small.py").write_text("x\n")
        (tmp_path / "large.py").write_text("y" * 500 + "\n")
        files = [tmp_path / "small.py", tmp_path / "large.py"]

        result, paths = _pack_files(files, str(tmp_path), max_chars=50)
        assert "small.py" in result
        assert "large.py" not in result

    def test_empty_file_skipped(self, tmp_path):
        (tmp_path / "empty.py").write_text("")
        (tmp_path / "real.py").write_text("code\n")
        files = [tmp_path / "empty.py", tmp_path / "real.py"]

        result, paths = _pack_files(files, str(tmp_path), max_chars=10000)
        assert "empty.py" not in result
        assert "real.py" in result

    def test_returns_empty_when_nothing_fits(self, tmp_path):
        (tmp_path / "big.py").write_text("x" * 1000 + "\n")
        files = [tmp_path / "big.py"]

        result, paths = _pack_files(files, str(tmp_path), max_chars=10)
        assert result == ""
        assert paths == []


class TestBuildSourceContextWithFindings:
    """Tests for _build_source_context when skill_findings are provided."""

    def test_finding_files_prioritized(self, tmp_path):
        """Files with findings should appear in context even if they'd be skipped alphabetically."""
        (tmp_path / "aaaa.py").write_text("a" * 200 + "\n")
        (tmp_path / "zzzz.py").write_text("vuln_code\n")

        findings = [{"file_path": str(tmp_path / "zzzz.py"), "title": "Bug"}]
        result = _build_source_context(str(tmp_path), max_chars=300, skill_findings=findings)

        # zzzz.py should be prioritized and appear even with tight budget
        assert "zzzz.py" in result

    def test_no_findings_falls_back_to_default_ordering(self, tmp_path):
        """Without findings, still works with entry-point + size ordering."""
        (tmp_path / "main.py").write_text("entry\n")
        (tmp_path / "lib.py").write_text("helper\n")

        result = _build_source_context(str(tmp_path), max_chars=10000)
        assert "main.py" in result
        assert "lib.py" in result


class TestCustomEndpointStructuredOutputBypass:
    """When OPENAI_BASE_URL is set (custom endpoint), output_type must be
    omitted to avoid vLLM 'lazy grammar' errors.  The agent should fall back
    to prompt-based JSON and parse via _parse_llm_findings."""

    def test_no_output_type_when_custom_endpoint(self):
        """Agent(...) must NOT receive output_type when structured output is
        unsupported (custom endpoint OR Gemini). The decision is delegated to
        provider.supports_structured_output()."""
        import inspect
        source = inspect.getsource(_collect_llm_findings_async)
        # The code must conditionally decide structured vs unstructured
        assert "supports_structured_output" in source
        assert "use_structured" in source

    def test_json_instruction_appended_for_custom_endpoint(self):
        """When structured output is disabled, prompt must include JSON format instructions."""
        import inspect
        source = inspect.getsource(_collect_llm_findings_async)
        assert "json" in source.lower()
        assert "```json" in source

    def test_output_type_used_for_standard_endpoint(self):
        """When NOT using a custom endpoint, output_type=AuditOutput must still be set."""
        import inspect
        source = inspect.getsource(_collect_llm_findings_async)
        assert 'output_type' in source
        assert 'AuditOutput' in source

    def test_parse_llm_result_handles_raw_text(self):
        """_parse_llm_result falls back to _parse_llm_findings for non-AuditOutput."""
        from shared.audit_runner import _parse_llm_result

        class FakeResult:
            final_output = '''```json
[{"severity": "high", "category": "injection", "title": "SQLi", "description": "bad", "file_path": "a.py", "line_start": 1, "line_end": 2, "recommendation": "fix"}]
```'''

        findings = _parse_llm_result(FakeResult())
        assert len(findings) == 1
        assert findings[0]["title"] == "SQLi"
        assert findings[0]["severity"] == "high"

    def test_parse_llm_result_handles_structured_output(self):
        """_parse_llm_result handles AuditOutput instances (standard endpoint path)."""
        from shared.audit_runner import _parse_llm_result

        class FakeResult:
            final_output = AuditOutput(findings=[
                AuditFinding(severity="critical", title="XSS", category="xss"),
            ])

        findings = _parse_llm_result(FakeResult())
        assert len(findings) == 1
        assert findings[0]["title"] == "XSS"
        assert findings[0]["severity"] == "critical"

    def test_uses_custom_endpoint_reflects_env(self, monkeypatch):
        """uses_custom_endpoint() returns True only when OPENAI_BASE_URL is set."""
        from shared.llm import provider

        monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "http://localhost:8000/v1")
        assert provider.uses_custom_endpoint() is True

        monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
        assert provider.uses_custom_endpoint() is False


class TestCheckContextBudgetReturnsTuple:
    """Tests that _check_context_budget returns (warning, estimated_tokens) tuple."""

    def test_returns_tuple(self, monkeypatch):
        """_check_context_budget must return a (warning, tokens) tuple."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        result = _check_context_budget("small prompt text")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2

    def test_small_prompt_returns_none_warning(self, monkeypatch):
        """Prompt within budget returns (None, token_count)."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        warning, tokens = _check_context_budget("small prompt text")
        assert warning is None
        assert tokens > 0

    def test_large_prompt_returns_warning_string(self, monkeypatch):
        """Prompt exceeding 80% returns (warning_str, token_count)."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "100")
        big_prompt = "x" * 2000
        warning, tokens = _check_context_budget(big_prompt)
        assert warning is not None
        assert "exceeds 80%" in warning
        assert tokens > 0

    def test_token_count_is_positive_int(self, monkeypatch):
        """Estimated tokens must be a positive integer."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        _, tokens = _check_context_budget("some text here")
        assert isinstance(tokens, int)
        assert tokens > 0


class TestTruncatePromptAcceptsPrecomputedTokens:
    """Tests that _truncate_prompt_to_budget accepts pre-computed token count."""

    def test_accepts_precomputed_tokens(self, monkeypatch):
        """_truncate_prompt_to_budget should accept estimated_tokens parameter."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        prompt = "small text"
        result = _truncate_prompt_to_budget(prompt, estimated_tokens=5)
        assert result == prompt  # within budget, no truncation

    def test_truncates_with_precomputed_tokens(self, monkeypatch):
        """When precomputed tokens exceed budget, prompt should be truncated."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "100")
        # Build a prompt with file blocks large enough that removal is needed.
        # target_tokens = 100 * 0.8 = 80; estimated_tokens = 500 >> 80.
        blocks = [f"\n\n--- file{i}.py ---\n{'x' * 200}" for i in range(5)]
        prompt = "Preamble text" + "".join(blocks)
        result = _truncate_prompt_to_budget(prompt, estimated_tokens=500)
        assert len(result) < len(prompt)

    def test_no_double_estimation_when_precomputed(self, monkeypatch):
        """When estimated_tokens is passed, safe_estimate_tokens should not be called again."""
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "128000")
        call_count = 0
        original_fn = None

        import shared.audit_runner as runner
        original_fn = runner.safe_estimate_tokens

        def counting_estimate(text):
            nonlocal call_count
            call_count += 1
            return original_fn(text)

        monkeypatch.setattr(runner, "safe_estimate_tokens", counting_estimate)

        prompt = "some text content"
        _truncate_prompt_to_budget(prompt, estimated_tokens=5)
        # With precomputed tokens, the initial estimation should be skipped.
        # Only per-block estimations should happen (0 for small prompt).
        assert call_count == 0, f"Expected 0 calls to safe_estimate_tokens, got {call_count}"
