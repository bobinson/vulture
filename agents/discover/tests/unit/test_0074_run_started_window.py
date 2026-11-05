"""0074 verification item 7 (AC7): discover's LLM suggestion plugin runs when the
LLM tier is on, so its run publishes the window on ``run_started``; a
skills-only run publishes none. Synthetic model."""

from __future__ import annotations

import json

from discover_agent.agent import run_discover
from shared.llm import broker, provider


def _first_event(monkeypatch, use_llm: str) -> dict:
    monkeypatch.setenv("VULTURE_USE_LLM", use_llm)
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3-fixture-coder-32b")
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    broker.set_context_window(None)
    first = next(run_discover("0074-v7-discover", "/nonexistent", {}))
    assert first.startswith("event: agent_start")
    return json.loads(first.split("data: ", 1)[1])


def test_llm_run_publishes_its_window(monkeypatch) -> None:
    window = _first_event(monkeypatch, "yes").get("llm_window")
    assert window and window["effective"] == 32_768


def test_skills_only_run_publishes_no_window(monkeypatch) -> None:
    assert "llm_window" not in _first_event(monkeypatch, "0")
