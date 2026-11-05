"""Feature 0074 review items 1 and 8 — one window key, logged once per run.

Item 1 (AC36): ``profile_for`` (the prompt budget), ``effective_context_window``
(the per-batch source budget) and ``publish_llm_window`` (the published
window) must resolve the SAME window for every model key the agent knows,
including behind a custom endpoint where ``get_model`` wraps the key in a
LiteLLM route prefix. Before the fix the profile looked up the wrapped key and
12 of 18 table keys fell through to a 32000 family/default guess.

Item 8: the clamp and default-window warnings are per-RUN facts. They are
emitted once by ``publish_llm_window``; the per-call resolvers stay silent so a
run's log carries one line, not one per batch or judge prompt.

All fixtures are synthetic.
"""

from __future__ import annotations

import logging

import pytest

from shared.llm import provider
from shared.prompt import profile_for
from tests.support.window import GATEWAY, MODEL, set_gateway

_KEYS = sorted(set(provider.MODEL_MAP) | set(provider.CONTEXT_WINDOWS))
_UNKNOWN = "fixture-unknown-model"
_CLAMP = "llm_body_window_clamped"
_DEFAULT = "custom_endpoint_default_ctx"


def _three_windows(key: str) -> tuple[tuple[int, str], ...]:
    profile = profile_for(key)
    window = provider.effective_context_window(key)
    published = provider.publish_llm_window(key)
    return (
        (profile.ctx_window, profile.ctx_provenance),
        (window.effective, window.provenance),
        (published["effective"], published["provenance"]),
    )


@pytest.mark.parametrize("gateway", [GATEWAY, ""], ids=["custom_endpoint", "no_endpoint"])
@pytest.mark.parametrize("key", _KEYS)
def test_profile_source_and_published_window_agree(key, gateway, monkeypatch) -> None:
    """Item 1: every known key resolves one window and one provenance."""
    set_gateway(monkeypatch, gateway)
    profile, source, published = _three_windows(key)
    assert profile == source == published


def test_table_key_behind_gateway_keeps_its_table_window(monkeypatch) -> None:
    """Item 1 (the reproduced case): claude-sonnet is 200000/table, not a
    32000 guess, in the prompt profile too."""
    set_gateway(monkeypatch, GATEWAY)
    profile = profile_for("claude-sonnet")
    assert (profile.ctx_window, profile.ctx_provenance) == (200_000, provider.WINDOW_FROM_TABLE)


def _count(caplog: pytest.LogCaptureFixture, needle: str) -> int:
    return sum(needle in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(("model", "needle"), [(MODEL, _CLAMP), (_UNKNOWN, _DEFAULT)])
def test_per_call_resolvers_are_silent(model, needle, monkeypatch, caplog) -> None:
    """Item 8: the hot-path resolvers never log the per-run warnings."""
    set_gateway(monkeypatch, GATEWAY)
    with caplog.at_level(logging.WARNING):
        for _ in range(20):
            profile_for(model)
            provider.effective_context_window(model)
            provider.get_context_window(model)
    assert _count(caplog, needle) == 0


@pytest.mark.parametrize(("model", "needle"), [(MODEL, _CLAMP), (_UNKNOWN, _DEFAULT)])
def test_publish_logs_each_warning_once(model, needle, monkeypatch, caplog) -> None:
    """Item 8: one publication, one warning, whatever the hot path did."""
    set_gateway(monkeypatch, GATEWAY)
    with caplog.at_level(logging.WARNING):
        for _ in range(5):
            profile_for(model)
        provider.publish_llm_window(model)
    assert _count(caplog, needle) == 1


@pytest.mark.parametrize("model", [MODEL, _UNKNOWN, "claude-sonnet"])
def test_no_warning_without_a_custom_endpoint(model, caplog) -> None:
    """Item 8: no gateway, nothing clamped and no default-window warning."""
    with caplog.at_level(logging.WARNING):
        provider.publish_llm_window(model)
    assert _count(caplog, _CLAMP) + _count(caplog, _DEFAULT) == 0
