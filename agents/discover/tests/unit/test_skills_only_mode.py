"""Feature 0043 v1.1: discover honors VULTURE_USE_LLM via shared helper.

Asserts ``LLMEndpointPlugin.accepts()`` returns False whenever
``is_skills_only()`` returns True — i.e. the LLM endpoint-suggestion
plugin is skipped entirely in skills-only mode. Plugin-based
discovery (Playwright crawl, source-file URL extraction) continues
to run — that's the whole "skills mode for discover" path.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch):
    monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_BASE", raising=False)


def _accepts(plugin_ctx) -> bool:
    """Run LLMEndpointPlugin.accepts(ctx) synchronously."""
    from discover_agent.plugins.llm_suggest import LLMEndpointPlugin

    plugin = LLMEndpointPlugin()
    return asyncio.run(plugin.accepts(plugin_ctx))


class TestLLMSuggestPluginGating:
    def test_unset_use_llm_skips_plugin(self):
        ctx = MagicMock()
        assert _accepts(ctx) is False

    def test_explicit_false_skips_plugin(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "false")
        ctx = MagicMock()
        assert _accepts(ctx) is False

    def test_use_llm_true_without_key_still_skipped(self, monkeypatch):
        """USE_LLM=true but no provider key → still skip (avoid
        AuthenticationError when no key is available)."""
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        ctx = MagicMock()
        assert _accepts(ctx) is False

    def test_use_llm_true_with_openai_key_runs_plugin(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        ctx = MagicMock()
        assert _accepts(ctx) is True

    def test_use_llm_true_with_anthropic_key_runs_plugin(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        ctx = MagicMock()
        assert _accepts(ctx) is True

    def test_use_llm_true_with_ollama_runs_plugin(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        monkeypatch.setenv("OLLAMA_API_BASE", "http://localhost:11434")
        ctx = MagicMock()
        assert _accepts(ctx) is True
