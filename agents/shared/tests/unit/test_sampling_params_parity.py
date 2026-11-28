"""No agent sends `temperature` to a Claude model that rejects it.

Every Claude model from Opus 4.7 on answers a non-default temperature/top_p
with a 400. The broker drops it for them (claudeLegacySampling in
backend/internal/broker/provider/modelcaps.go); without the broker
(`vulture.sh dev anthropic --no-broker`) the agents call Anthropic through
LiteLLM themselves, and they sent temperature 0.1 on every call. Both sides now
use ONE closed allowlist of the older models that still accept it, and this
test keeps the Python copy identical to the Go one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from shared.llm import provider

MODELCAPS_GO = (Path(__file__).resolve().parents[4]
                / "backend" / "internal" / "broker" / "provider" / "modelcaps.go")

CURRENT = ["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5", "claude-fable-5-2",
           "claude-opus-4-7", "litellm/anthropic/claude-sonnet-5-5", "anthropic/claude-opus-5-5"]
LEGACY = ["claude-sonnet-4-6", "claude-haiku-4-5-20251001", "claude-3-5-sonnet-20241022",
          "litellm/anthropic/claude-opus-4-1-20250805"]
NOT_CLAUDE = ["gpt-4o", "gemini-2.5-flash", "qwen3:8b"]


def test_python_and_go_share_one_allowlist() -> None:
    m = re.search(r"claudeLegacySampling = regexp\.MustCompile\(\s*`([^`]+)`\)",
                  MODELCAPS_GO.read_text(encoding="utf-8"))
    assert m, "claudeLegacySampling not found in modelcaps.go"
    assert provider._CLAUDE_LEGACY_SAMPLING.pattern == m.group(1)


@pytest.mark.parametrize("model", CURRENT)
def test_no_temperature_for_a_current_claude_model(model: str) -> None:
    assert provider.sampling_settings(model) == {}


@pytest.mark.parametrize("model", LEGACY + NOT_CLAUDE)
def test_temperature_kept_where_it_is_accepted(model: str) -> None:
    assert provider.sampling_settings(model) == {"temperature": 0.1}


def test_generate_phase_settings_follow_the_model() -> None:
    assert "temperature" not in provider.get_model_settings("litellm/anthropic/claude-sonnet-5-5")
    assert provider.get_model_settings("gpt-4o")["temperature"] == 0.1


def test_agent_factory_settings_follow_the_model() -> None:
    from shared.base_agent import create_agent

    assert create_agent("a", "i", [], model="litellm/anthropic/claude-sonnet-5-5").model_settings.temperature is None
    assert create_agent("a", "i", [], model="gpt-4o").model_settings.temperature == 0.1
