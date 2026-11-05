"""0074 verification item 8 (AC36): every prompt input is sized from the
EFFECTIVE window. The prior-findings budget used the unclamped window, so behind
a custom endpoint a family guess (32768) sized the memory context while the
source budget used the 32000 clamp. Synthetic model and endpoint."""

from __future__ import annotations

from shared.tools.memory_client import _resolve_context_limits
from tests.support.window import GATEWAY, no_ambient_window, set_gateway


def test_prior_context_budget_uses_the_clamped_window(monkeypatch) -> None:
    set_gateway(monkeypatch, GATEWAY)
    with no_ambient_window(monkeypatch):
        assert _resolve_context_limits(5, 0) == (5, int(32_000 * 0.15 * 4))


def test_prior_context_budget_unclamped_without_a_custom_endpoint(monkeypatch) -> None:
    set_gateway(monkeypatch, "")
    with no_ambient_window(monkeypatch):
        assert _resolve_context_limits(5, 0) == (5, int(32_768 * 0.15 * 4))
