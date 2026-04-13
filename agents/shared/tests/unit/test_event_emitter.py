"""Unit tests for SSE event emitter."""

import json

from shared.transport.event_emitter import AgUiEventEmitter


def _parse_sse(raw: str) -> tuple[str, dict]:
    """Parse an SSE string into (event_name, data_dict)."""
    lines = raw.strip().split("\n")
    event_name = ""
    data_str = ""
    for line in lines:
        if line.startswith("event: "):
            event_name = line[len("event: "):]
        elif line.startswith("data: "):
            data_str = line[len("data: "):]
    return event_name, json.loads(data_str)


class TestAgUiEventEmitter:
    """Tests for SSE event formatting."""

    def setup_method(self):
        self.emitter = AgUiEventEmitter("run-123")

    def test_run_started(self):
        raw = self.emitter.run_started()
        event, data = _parse_sse(raw)
        assert event == "agent_start"
        assert data["run_id"] == "run-123"
        assert "agent_name" in data

    def test_run_finished(self):
        raw = self.emitter.run_finished()
        event, data = _parse_sse(raw)
        assert event == "agent_end"
        assert data["run_id"] == "run-123"
        assert data["status"] == "completed"

    def test_run_finished_custom_status(self):
        raw = self.emitter.run_finished(status="failed")
        _, data = _parse_sse(raw)
        assert data["status"] == "failed"

    def test_text_message(self):
        raw = self.emitter.text_message("Analyzing patterns...")
        event, data = _parse_sse(raw)
        assert event == "thinking"
        assert data["content"] == "Analyzing patterns..."

    def test_step_started(self):
        raw = self.emitter.step_started("chaos")
        event, data = _parse_sse(raw)
        assert event == "step_start"
        assert data["step_name"] == "chaos"
        assert data["run_id"] == "run-123"

    def test_tool_call(self):
        raw = self.emitter.tool_call("read_file", {"path": "/src/main.py"})
        event, data = _parse_sse(raw)
        assert event == "tool_call"
        assert data["tool"] == "read_file"
        assert data["args"]["path"] == "/src/main.py"

    def test_finding_event(self):
        raw = self.emitter.finding_event(
            severity="critical",
            category="injection",
            title="SQL Injection",
            description="User input not sanitized",
            file_path="/src/db.py",
            line_start=42,
            line_end=45,
            recommendation="Use parameterized queries",
        )
        event, data = _parse_sse(raw)
        assert event == "finding"
        assert data["severity"] == "critical"
        assert data["category"] == "injection"
        assert data["title"] == "SQL Injection"
        assert data["file_path"] == "/src/db.py"
        assert data["line_start"] == 42
        assert data["line_end"] == 45

    def test_finding_event_defaults(self):
        raw = self.emitter.finding_event(
            severity="info",
            category="docs",
            title="Missing docs",
            description="No docstring",
        )
        _, data = _parse_sse(raw)
        assert data["file_path"] == ""
        assert data["line_start"] == 0
        assert data["recommendation"] == ""

    def test_progress_event(self):
        raw = self.emitter.progress_event(
            files_analyzed=10,
            total_files=50,
            findings_count=3,
        )
        event, data = _parse_sse(raw)
        assert event == "progress"
        assert data["files_analyzed"] == 10
        assert data["total_files"] == 50
        assert data["findings_count"] == 3

    def test_result_event(self):
        findings = [{"severity": "high", "title": "Test"}]
        raw = self.emitter.result_event(
            findings=findings,
            summary="Found 1 issue(s) across 3 categories.",
            score=72.5,
        )
        event, data = _parse_sse(raw)
        assert event == "result"
        assert data["findings"] == findings
        assert data["findings_count"] == 1
        assert data["summary"] == "Found 1 issue(s) across 3 categories."
        assert data["score"] == 72.5

    def test_sse_format_ends_with_double_newline(self):
        raw = self.emitter.run_started()
        assert raw.endswith("\n\n")

    def test_sse_format_has_event_and_data_lines(self):
        raw = self.emitter.text_message("test")
        lines = raw.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("event: ")
        assert lines[1].startswith("data: ")

    def test_data_is_valid_json(self):
        raw = self.emitter.finding_event(
            severity="medium",
            category="test",
            title="Test",
            description="Desc",
        )
        _, data = _parse_sse(raw)
        # If we got here without error, JSON is valid
        assert isinstance(data, dict)

    def test_token_savings_event(self):
        raw = self.emitter.token_savings_event(
            context_tokens=50,
            raw_tokens=150,
            prior_findings_used=5,
            duplicates_removed=10,
        )
        event, data = _parse_sse(raw)
        assert event == "token_savings"
        assert data["context_tokens"] == 50
        assert data["raw_tokens"] == 150
        assert data["tokens_saved"] == 100
        assert data["savings_pct"] == 67
        assert data["prior_findings_used"] == 5
        assert data["duplicates_removed"] == 10

    def test_token_savings_zero_raw(self):
        raw = self.emitter.token_savings_event(
            context_tokens=0,
            raw_tokens=0,
            prior_findings_used=0,
            duplicates_removed=0,
        )
        _, data = _parse_sse(raw)
        assert data["tokens_saved"] == 0
        assert data["savings_pct"] == 0

    def test_token_savings_with_actual_usage(self):
        raw = self.emitter.token_savings_event(
            context_tokens=50,
            raw_tokens=150,
            prior_findings_used=5,
            duplicates_removed=2,
            actual_input_tokens=1500,
            actual_output_tokens=800,
        )
        _, data = _parse_sse(raw)
        assert data["actual_input_tokens"] == 1500
        assert data["actual_output_tokens"] == 800

    def test_token_savings_with_cost_usd(self):
        raw = self.emitter.token_savings_event(
            context_tokens=50,
            raw_tokens=150,
            prior_findings_used=5,
            duplicates_removed=2,
            actual_input_tokens=10000,
            actual_output_tokens=5000,
            cost_usd=0.075,
        )
        _, data = _parse_sse(raw)
        assert "cost_usd" in data
        assert data["cost_usd"] == 0.075

    def test_token_savings_zero_cost_omitted(self):
        raw = self.emitter.token_savings_event(
            context_tokens=50,
            raw_tokens=150,
            prior_findings_used=5,
            duplicates_removed=2,
            cost_usd=0.0,
        )
        _, data = _parse_sse(raw)
        assert "cost_usd" not in data

    def test_token_savings_zero_actual_tokens_omitted(self):
        raw = self.emitter.token_savings_event(
            context_tokens=50,
            raw_tokens=150,
            prior_findings_used=5,
            duplicates_removed=2,
            actual_input_tokens=0,
            actual_output_tokens=0,
        )
        _, data = _parse_sse(raw)
        assert "actual_input_tokens" not in data
        assert "actual_output_tokens" not in data
