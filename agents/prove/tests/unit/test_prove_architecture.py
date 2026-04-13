"""Tests for prove agent architecture fixes (Issues 38-46).

Covers: token tracking, cooldown/fallback, max_iterations cap,
model resolution, model passthrough, context window awareness.
"""

import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Issue 38: Prove agent token tracking
# ---------------------------------------------------------------------------


class TestIssue38ProveTokenTracking:
    """llm_helper must track token usage across calls."""

    def test_prove_token_usage_dataclass(self):
        from prove_agent.llm_helper import ProveTokenUsage
        usage = ProveTokenUsage()
        assert usage.input_tokens == 0
        assert usage.output_tokens == 0
        assert usage.call_count == 0
        usage.record(100, 50)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50
        assert usage.call_count == 1
        assert usage.total_tokens == 150

    def test_prove_token_usage_accumulates(self):
        from prove_agent.llm_helper import ProveTokenUsage
        usage = ProveTokenUsage()
        usage.record(100, 50)
        usage.record(200, 100)
        usage.record(300, 150)
        assert usage.call_count == 3
        assert usage.input_tokens == 600
        assert usage.output_tokens == 300
        assert usage.total_tokens == 900

    def test_prove_token_usage_cost_estimate(self):
        from prove_agent.llm_helper import ProveTokenUsage
        usage = ProveTokenUsage()
        usage.record(1_000_000, 500_000)
        cost = usage.estimate_cost_usd("gpt-4o")
        assert cost > 0, "Should compute non-zero cost for cloud model"

    def test_prove_token_usage_zero_cost_local(self):
        from prove_agent.llm_helper import ProveTokenUsage
        usage = ProveTokenUsage()
        usage.record(1_000_000, 500_000)
        cost = usage.estimate_cost_usd("qwen3:8b")
        assert cost == 0.0, "Local models should have zero cost"

    def test_session_reset(self):
        from prove_agent.llm_helper import get_token_usage, reset_token_usage
        reset_token_usage()
        usage = get_token_usage()
        assert usage.call_count == 0
        usage.record(100, 50)
        assert get_token_usage().call_count == 1
        reset_token_usage()
        assert get_token_usage().call_count == 0

    def test_error_tracking(self):
        from prove_agent.llm_helper import ProveTokenUsage
        usage = ProveTokenUsage()
        usage.record_error()
        usage.record_error()
        assert usage.errors == 2
        assert usage.call_count == 0


# ---------------------------------------------------------------------------
# Issue 39: Prove agent cooldown/fallback
# ---------------------------------------------------------------------------


class TestIssue39ProveCooldownFallback:
    """llm_helper must use cooldown-aware model resolution."""

    def test_llm_helper_imports_cooldown(self):
        import prove_agent.llm_helper as h
        assert hasattr(h, "cooldown_manager")

    def test_llm_helper_uses_fallback_resolver(self):
        import inspect
        import prove_agent.llm_helper as h
        source = inspect.getsource(h.llm_json_call)
        # Uses cached model resolution which internally calls fallback resolver
        assert "_get_cached_model" in source

    def test_llm_helper_records_failure_on_exhaust(self):
        import inspect
        import prove_agent.llm_helper as h
        source = inspect.getsource(h.llm_json_call)
        assert "record_failure" in source

    def test_llm_helper_records_success(self):
        import inspect
        import prove_agent.llm_helper as h
        source = inspect.getsource(h.llm_json_call)
        assert "record_success" in source


# ---------------------------------------------------------------------------
# Issue 40: max_iterations capped to 10
# ---------------------------------------------------------------------------


class TestIssue40MaxIterationsCap:
    """max_iterations must be capped at 10."""

    def test_config_schema_max_is_10(self):
        from prove_agent.config import CONFIG_SCHEMA
        props = CONFIG_SCHEMA["properties"]["max_iterations"]
        assert props["maximum"] == 10

    def test_agent_caps_iterations(self):
        import inspect
        import prove_agent.agent as agent_mod
        source = inspect.getsource(agent_mod.run_prove)
        assert "_MAX_ITERATIONS_CAP" in source


# ---------------------------------------------------------------------------
# Issue 42: Model passthrough from config
# ---------------------------------------------------------------------------


class TestIssue42ModelPassthrough:
    """Prove agent should accept model from config."""

    def test_agent_reads_model_from_config(self):
        import inspect
        import prove_agent.agent as agent_mod
        source = inspect.getsource(agent_mod.run_prove)
        assert 'config.get("model")' in source or "model_preference" in source


# ---------------------------------------------------------------------------
# Issue 43: _get_findings uses agent_type
# ---------------------------------------------------------------------------


class TestIssue43GetFindingsAgentType:
    """_get_findings filters by agent_type."""

    def test_get_findings_uses_agent_type(self):
        import inspect
        import prove_agent.agent as agent_mod
        source = inspect.getsource(agent_mod._get_findings)
        assert 'f.get("agent_type")' in source

    def test_findings_filter_by_type(self):
        from prove_agent.agent import _get_findings
        findings = [
            {"agent_type": "owasp", "title": "XSS"},
            {"agent_type": "cwe", "title": "Buffer"},
            {"agent_type": "soc2", "title": "Logging"},
        ]
        result = _get_findings({}, findings, "/src", ["owasp", "cwe"])
        assert len(result) == 2
        assert all(f["agent_type"] in ("owasp", "cwe") for f in result)


# ---------------------------------------------------------------------------
# Issue 46: Context window awareness in prove agent
# ---------------------------------------------------------------------------


class TestIssue46ContextWindowAwareness:
    """llm_helper must truncate prompts to fit model context window."""

    def test_truncate_prompt_exists(self):
        from prove_agent.llm_helper import _truncate_prompt
        assert callable(_truncate_prompt)

    def test_short_prompt_unchanged(self, monkeypatch):
        monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
        monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
        from prove_agent.llm_helper import _truncate_prompt
        short = "Check this endpoint: /api/users"
        result = _truncate_prompt(short, 4096)
        assert result == short

    def test_long_prompt_truncated(self, monkeypatch):
        monkeypatch.setenv("VULTURE_LLM_CTX_SIZE", "8000")
        from prove_agent.llm_helper import _truncate_prompt
        long_prompt = "x" * 100_000
        result = _truncate_prompt(long_prompt, 4096)
        assert len(result) < 100_000
        assert "truncated" in result

    def test_llm_json_call_calls_truncate(self):
        import inspect
        import prove_agent.llm_helper as h
        source = inspect.getsource(h.llm_json_call)
        assert "_truncate_prompt" in source
