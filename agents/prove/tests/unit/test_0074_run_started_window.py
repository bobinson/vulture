"""0074 verification item 7 (AC7): every run with the LLM tier enabled publishes
its window on ``run_started``; a skills-only run publishes none. prove calls an
LLM for its verification logic, so it is held to the same contract as the
agents that run through ``run_combined_audit``. Synthetic model."""

from __future__ import annotations

import json

import pytest

from prove_agent.agent import run_prove
from shared.llm import broker, provider


def _first_event(monkeypatch, use_llm: str) -> dict:
    monkeypatch.setenv("VULTURE_USE_LLM", use_llm)
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen3-fixture-coder-32b")
    monkeypatch.delenv("VULTURE_LLM_CTX_SIZE", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    broker.set_context_window(None)
    first = next(run_prove("0074-v7-prove", "/nonexistent", {}))
    assert first.startswith("event: agent_start")
    return json.loads(first.split("data: ", 1)[1])


@pytest.mark.parametrize("token", ["true", "on"])
def test_llm_run_publishes_its_window(token, monkeypatch) -> None:
    window = _first_event(monkeypatch, token).get("llm_window")
    assert window and window["effective"] == window["resolved"] == 32_768
    assert window["model"] == "qwen3-fixture-coder-32b"


def test_skills_only_run_publishes_no_window(monkeypatch) -> None:
    assert "llm_window" not in _first_event(monkeypatch, "false")
