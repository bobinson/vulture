"""0074 verification item 8 (AC36): prove truncates its prompt to the EFFECTIVE
window of the model it calls (the gateway clamp applies behind a custom
endpoint), not the unclamped ambient window. Synthetic model and endpoint."""

from __future__ import annotations

from prove_agent import llm_helper
from shared.llm import broker, provider

_MODEL = "qwen3-fixture-coder-32b"   # a family guess of 32768 tokens
_MARKER = "\n...[truncated to fit context window]"


def _isolate(monkeypatch, gateway: str) -> None:
    for name in ("VULTURE_LLM_CTX_SIZE", "VULTURE_LLM_GATEWAY_GUESS_CTX"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VULTURE_LLM_MODEL", _MODEL)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", gateway)
    broker.set_context_window(None)


def _budget(window: int, max_tokens: int) -> int:
    return (window - max_tokens - 50 - 256) * 4


def test_prove_prompt_is_sized_from_the_clamped_window(monkeypatch) -> None:
    _isolate(monkeypatch, "https://gateway.invalid/v1")
    out = llm_helper._truncate_prompt("x" * 1_000_000, 1000, model=_MODEL)
    assert len(out) == _budget(32_000, 1000) + len(_MARKER)


def test_prove_prompt_unclamped_without_a_custom_endpoint(monkeypatch) -> None:
    _isolate(monkeypatch, "")
    out = llm_helper._truncate_prompt("x" * 1_000_000, 1000, model=_MODEL)
    assert len(out) == _budget(32_768, 1000) + len(_MARKER)
