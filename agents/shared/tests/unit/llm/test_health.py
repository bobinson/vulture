"""Test corpus for shared.llm.health (feature 0039).

Each provider has 7 test cases:
  1. Reachable + model loaded
  2. Endpoint reachable, model not loaded
  3. Connection refused
  4. Timeout
  5. Auth failure (401)
  6. Rate limit (429)
  7. Server error (500)

Plus detection-precedence tests and message-format invariance tests.

All tests use httpx.MockTransport via monkeypatch — no network calls.
"""
from __future__ import annotations

import json

import httpx
import pytest

from shared.llm.health import (
    LLMHealthStatus,
    check_llm_health,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_env(monkeypatch):
    """Each test starts with a clean LLM-related env."""
    for k in [
        "VULTURE_USE_LLM", "VULTURE_LLM_MODEL", "OPENAI_BASE_URL",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
        "OLLAMA_API_BASE",
    ]:
        monkeypatch.delenv(k, raising=False)


def _patch_async_client(monkeypatch, handler):
    """Patch httpx.AsyncClient to use a MockTransport with the given handler.

    handler: callable (httpx.Request) -> httpx.Response or raises an exception.
    """
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        # AsyncClient doesn't accept transport AND mounts together; drop mounts.
        kwargs.pop("mounts", None)
        return real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


# ===========================================================================
# Disabled / unknown
# ===========================================================================


@pytest.mark.asyncio
async def test_disabled_when_use_llm_unset(monkeypatch):
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "disabled"
    assert r.reachable is False
    assert r.message() == (
        "LLM disabled (VULTURE_USE_LLM != true). Audit will run skills-only."
    )


@pytest.mark.asyncio
async def test_disabled_when_use_llm_false(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "disabled"


@pytest.mark.asyncio
async def test_unknown_when_no_provider_env(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "weird-custom-model")
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "unknown"
    assert r.reachable is False
    assert "cannot infer provider" in r.error


# ===========================================================================
# LM Studio (OpenAI-compatible, port 1234)
# ===========================================================================


def _make_lmstudio_env(monkeypatch, model="qwen3:8b"):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)


@pytest.mark.asyncio
async def test_lmstudio_reachable_model_loaded(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        return httpx.Response(200, json={
            "data": [{"id": "qwen3:8b"}, {"id": "llama-3-3b"}]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "lmstudio"
    assert r.reachable is True
    assert r.model == "qwen3:8b"
    assert r.endpoint == "http://localhost:1234/v1"
    assert r.message() == "LLM ready: lmstudio (qwen3:8b) at http://localhost:1234/v1"


@pytest.mark.asyncio
async def test_lmstudio_endpoint_up_model_not_loaded(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "llama-3-3b"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert "not loaded" in r.error
    msg = r.message()
    assert msg.startswith(
        "LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — model"
    )
    assert msg.endswith(" Audit will run skills-only.")


@pytest.mark.asyncio
async def test_lmstudio_connection_refused(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        raise httpx.ConnectError("Connection refused")
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.message() == (
        "LLM unavailable: lmstudio (qwen3:8b) at http://localhost:1234/v1 — "
        "connection refused at http://localhost:1234/v1. Audit will run skills-only."
    )


@pytest.mark.asyncio
async def test_lmstudio_timeout(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        raise httpx.TimeoutException("read timeout")
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=2.5)
    assert r.reachable is False
    assert "timeout" in r.error
    assert "Audit will run skills-only." in r.message()


@pytest.mark.asyncio
async def test_lmstudio_auth_401(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        return httpx.Response(401, json={"error": "unauthorized"})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "auth: invalid or missing API key"


@pytest.mark.asyncio
async def test_lmstudio_rate_limit_429(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        return httpx.Response(429, json={"error": "rate limited"})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "rate limit / quota exceeded"


@pytest.mark.asyncio
async def test_lmstudio_server_500(monkeypatch):
    _make_lmstudio_env(monkeypatch)

    def handler(request):
        return httpx.Response(500, text="internal error")
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "upstream HTTP 500"


# ===========================================================================
# vLLM (port 8000) — same probe shape, different flavour name
# ===========================================================================


@pytest.mark.asyncio
async def test_vllm_flavour_detection(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:8000/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "mistral")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "mistral"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "vllm"
    assert r.reachable is True


# ===========================================================================
# LocalAI (port 8080)
# ===========================================================================


@pytest.mark.asyncio
async def test_localai_flavour_detection(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:8080/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "any"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "localai"
    # Empty model means "any reachable endpoint counts as reachable"
    assert r.reachable is True


# ===========================================================================
# Generic OpenAI-compatible (port 9999, unknown port)
# ===========================================================================


@pytest.mark.asyncio
async def test_generic_openai_compatible(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://example.com:9999/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-x")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "gpt-x"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "openai-compatible"
    assert r.reachable is True


# ===========================================================================
# OpenAI cloud
# ===========================================================================


def _make_openai_env(monkeypatch, model="gpt-4o"):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)


@pytest.mark.asyncio
async def test_openai_reachable(monkeypatch):
    _make_openai_env(monkeypatch)

    def handler(request):
        assert "Bearer sk-test123" in request.headers.get("authorization", "")
        return httpx.Response(200, json={
            "data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}, {"id": "gpt-3.5-turbo"}]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "openai"
    assert r.reachable is True
    assert r.message() == "LLM ready: openai (gpt-4o) at https://api.openai.com/v1"


@pytest.mark.asyncio
async def test_openai_invalid_key(monkeypatch):
    _make_openai_env(monkeypatch)

    def handler(request):
        return httpx.Response(401, json={"error": {"message": "invalid"}})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "auth: invalid or missing API key"


@pytest.mark.asyncio
async def test_openai_quota_exceeded(monkeypatch):
    _make_openai_env(monkeypatch)

    def handler(request):
        return httpx.Response(429, json={"error": "quota"})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.error == "rate limit / quota exceeded"


# ===========================================================================
# Anthropic
# ===========================================================================


def _make_anthropic_env(monkeypatch, model="claude-sonnet-4-5"):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)


@pytest.mark.asyncio
async def test_anthropic_reachable(monkeypatch):
    _make_anthropic_env(monkeypatch)

    def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/v1/messages"
        assert request.headers.get("x-api-key") == "sk-ant-test"
        return httpx.Response(200, json={
            "id": "msg_123", "content": [{"type": "text", "text": "pong"}],
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "anthropic"
    assert r.reachable is True
    assert r.message() == "LLM ready: anthropic (claude-sonnet-4-5) at api.anthropic.com"


@pytest.mark.asyncio
async def test_anthropic_invalid_key(monkeypatch):
    _make_anthropic_env(monkeypatch)

    def handler(request):
        return httpx.Response(401, json={"error": "invalid x-api-key"})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "auth: invalid x-api-key"


@pytest.mark.asyncio
async def test_anthropic_no_key_set(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "claude-sonnet-4-5")
    # ANTHROPIC_API_KEY not set
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "anthropic"
    assert r.reachable is False
    assert r.error == "ANTHROPIC_API_KEY not set"


@pytest.mark.asyncio
async def test_anthropic_model_not_found_404(monkeypatch):
    _make_anthropic_env(monkeypatch, model="nonexistent-model")

    def handler(request):
        return httpx.Response(404, json={"error": "model not found"})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert "not available" in r.error


@pytest.mark.asyncio
async def test_anthropic_rate_limit(monkeypatch):
    _make_anthropic_env(monkeypatch)

    def handler(request):
        return httpx.Response(429, json={})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.error == "rate limit / quota exceeded"


@pytest.mark.asyncio
async def test_anthropic_connection_refused(monkeypatch):
    _make_anthropic_env(monkeypatch)

    def handler(request):
        raise httpx.ConnectError("conn refused")
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "connection refused"


# ===========================================================================
# Gemini
# ===========================================================================


def _make_gemini_env(monkeypatch, model="gemini-1.5-pro"):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("GEMINI_API_KEY", "gem-test123")
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)


@pytest.mark.asyncio
async def test_gemini_reachable(monkeypatch):
    _make_gemini_env(monkeypatch)

    def handler(request):
        return httpx.Response(200, json={
            "models": [
                {"name": "models/gemini-1.5-pro"},
                {"name": "models/gemini-1.5-flash"},
            ]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "gemini"
    assert r.reachable is True
    assert "LLM ready: gemini" in r.message()


@pytest.mark.asyncio
async def test_gemini_invalid_key(monkeypatch):
    _make_gemini_env(monkeypatch)

    def handler(request):
        return httpx.Response(403, json={"error": "API_KEY_INVALID"})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert r.error == "auth: invalid GEMINI_API_KEY"


@pytest.mark.asyncio
async def test_gemini_model_not_in_account(monkeypatch):
    _make_gemini_env(monkeypatch, model="gemini-3-ultra")

    def handler(request):
        return httpx.Response(200, json={
            "models": [{"name": "models/gemini-1.5-flash"}]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert "not in account" in r.error


@pytest.mark.asyncio
async def test_gemini_no_key_set(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gemini-pro")
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "gemini"
    assert r.reachable is False
    assert r.error == "GEMINI_API_KEY not set"


# ===========================================================================
# Ollama
# ===========================================================================


def _make_ollama_env(monkeypatch, model="qwen3:1.7b"):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_MODEL", model)


@pytest.mark.asyncio
async def test_ollama_reachable(monkeypatch):
    _make_ollama_env(monkeypatch)

    def handler(request):
        return httpx.Response(200, json={
            "models": [{"name": "qwen3:1.7b"}, {"name": "mistral"}]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "ollama"
    assert r.reachable is True
    assert r.message() == "LLM ready: ollama (qwen3:1.7b) at http://localhost:11434"


@pytest.mark.asyncio
async def test_ollama_model_not_pulled(monkeypatch):
    _make_ollama_env(monkeypatch, model="qwen3:8b")

    def handler(request):
        return httpx.Response(200, json={"models": [{"name": "mistral"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert "not pulled" in r.error


@pytest.mark.asyncio
async def test_ollama_serve_not_running(monkeypatch):
    _make_ollama_env(monkeypatch)

    def handler(request):
        raise httpx.ConnectError("conn refused")
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert "not running" in r.error


@pytest.mark.asyncio
async def test_ollama_custom_base_url(monkeypatch):
    _make_ollama_env(monkeypatch)
    monkeypatch.setenv("OLLAMA_API_BASE", "http://ollama-host:9999")

    def handler(request):
        return httpx.Response(200, json={"models": [{"name": "qwen3:1.7b"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.endpoint == "http://ollama-host:9999"
    assert r.reachable is True


# ===========================================================================
# Detection precedence
# ===========================================================================


@pytest.mark.asyncio
async def test_precedence_openai_base_url_wins_over_anthropic(monkeypatch):
    """When OPENAI_BASE_URL is set, the openai-compatible probe runs even
    if ANTHROPIC_API_KEY is also set. Mirrors provider.py routing exactly."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "claude-sonnet")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "claude-sonnet"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "lmstudio"  # openai-compatible at port 1234


@pytest.mark.asyncio
async def test_precedence_claude_in_model_picks_anthropic(monkeypatch):
    """No OPENAI_BASE_URL; 'claude' in model selects anthropic even without key."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "claude-sonnet")
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "anthropic"


@pytest.mark.asyncio
async def test_precedence_gemini_in_model(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gemini-pro")
    r = await check_llm_health(timeout=1.0)
    assert r.provider == "gemini"


# ===========================================================================
# Message-format invariance — assert exact strings
# ===========================================================================


def test_message_format_disabled():
    s = LLMHealthStatus("disabled", "", "", False, "LLM disabled by config", {})
    assert s.message() == (
        "LLM disabled (VULTURE_USE_LLM != true). Audit will run skills-only."
    )


def test_message_format_reachable():
    s = LLMHealthStatus(
        "lmstudio", "http://localhost:1234/v1", "qwen3:8b", True, "", {},
    )
    assert s.message() == (
        "LLM ready: lmstudio (qwen3:8b) at http://localhost:1234/v1"
    )


def test_message_format_unreachable_with_model_and_endpoint():
    s = LLMHealthStatus(
        "openai", "https://api.openai.com/v1", "gpt-4o", False,
        "auth: invalid or missing API key", {},
    )
    assert s.message() == (
        "LLM unavailable: openai (gpt-4o) at https://api.openai.com/v1 "
        "— auth: invalid or missing API key. Audit will run skills-only."
    )


def test_message_format_unreachable_without_model():
    s = LLMHealthStatus(
        "openai", "https://api.openai.com/v1", "", False,
        "OPENAI_API_KEY not set", {},
    )
    assert s.message() == (
        "LLM unavailable: openai (no model) at https://api.openai.com/v1 "
        "— OPENAI_API_KEY not set. Audit will run skills-only."
    )


def test_message_format_unreachable_without_endpoint():
    s = LLMHealthStatus(
        "unknown", "", "weird-model", False,
        "cannot infer provider from VULTURE_LLM_MODEL and env", {},
    )
    assert s.message() == (
        "LLM unavailable: unknown (weird-model) at default "
        "— cannot infer provider from VULTURE_LLM_MODEL and env. "
        "Audit will run skills-only."
    )


# ===========================================================================
# Routing-prefix normalisation (the bug observed in production with LM Studio)
# ===========================================================================


@pytest.mark.asyncio
async def test_lmstudio_openai_prefix_stripped(monkeypatch):
    """The bug observed in production: VULTURE_LLM_MODEL='openai/qwen/qwen3.6-27b'
    while LM Studio reports it as 'qwen/qwen3.6-27b' (no prefix).

    LiteLLM strips the 'openai/' prefix at call time, so the agent's actual
    LLM call succeeds. The probe must mirror this normalisation so the banner
    doesn't say 'unavailable' when the call would in fact succeed.
    """
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "openai/qwen/qwen3.6-27b")

    def handler(request):
        return httpx.Response(200, json={
            "data": [{"id": "qwen/qwen3.6-27b"}, {"id": "minimax/minimax-m2.7"}]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.provider == "lmstudio"
    assert r.reachable is True, (
        f"openai/ prefix must be stripped before matching; got error: {r.error}"
    )
    # Reported model field stays as configured (preserves user's actual env value).
    assert r.model == "openai/qwen/qwen3.6-27b"
    assert r.message() == (
        "LLM ready: lmstudio (openai/qwen/qwen3.6-27b) at http://localhost:1234/v1"
    )


@pytest.mark.asyncio
async def test_lmstudio_litellm_openai_double_prefix_stripped(monkeypatch):
    """Even if both routing prefixes are present (litellm/openai/...), the
    upstream server only sees the bare name. Probe must mirror that."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "litellm/openai/qwen/qwen3-8b")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "qwen/qwen3-8b"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is True
    assert r.model == "litellm/openai/qwen/qwen3-8b"  # raw value preserved


@pytest.mark.asyncio
async def test_lmstudio_unprefixed_model_still_works(monkeypatch):
    """Regression: bare model name (no prefix) must still match correctly."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen/qwen3-8b")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "qwen/qwen3-8b"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is True


@pytest.mark.asyncio
async def test_lmstudio_prefix_stripped_but_still_not_loaded(monkeypatch):
    """Even after prefix stripping, the bare name must actually be in the
    available list. False positive guard: if user configures a model that
    really isn't loaded, the probe must still report degraded."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "openai/some/never-loaded-model")

    def handler(request):
        return httpx.Response(200, json={"data": [{"id": "qwen/qwen3-8b"}]})
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is False
    assert "not loaded" in r.error


def test_normalise_routing_prefix_unit():
    """Direct unit test of the normaliser helper."""
    from shared.llm.health import _normalise_routing_prefix
    assert _normalise_routing_prefix("openai/qwen/qwen3-8b") == "qwen/qwen3-8b"
    assert _normalise_routing_prefix("litellm/openai/qwen/qwen3-8b") == "qwen/qwen3-8b"
    assert _normalise_routing_prefix("litellm/ollama/qwen3:1.7b") == "ollama/qwen3:1.7b"
    assert _normalise_routing_prefix("qwen/qwen3-8b") == "qwen/qwen3-8b"
    assert _normalise_routing_prefix("") == ""


def test_as_dict_serialisable():
    s = LLMHealthStatus(
        "ollama", "http://localhost:11434", "qwen3:1.7b", True, "",
        {"model_count": 3, "models": ["qwen3:1.7b", "mistral", "llama3.2"]},
    )
    d = s.as_dict()
    # Must round-trip through JSON
    j = json.dumps(d)
    parsed = json.loads(j)
    assert parsed["provider"] == "ollama"
    assert parsed["reachable"] is True
    assert parsed["detail"]["model_count"] == 3


@pytest.mark.asyncio
async def test_gemini_litellm_prefixed_model_matches(monkeypatch):
    # Real-world: the native launcher sets
    # VULTURE_LLM_MODEL=litellm/gemini/gemini-2.5-flash, but the API lists
    # names as models/gemini-2.5-flash. The health check must compare bare
    # model ids (last path segment), not the litellm routing prefix, or it
    # falsely reports "not in account" and drops to skills-only.
    _make_gemini_env(monkeypatch, model="litellm/gemini/gemini-2.5-flash")

    def handler(request):
        return httpx.Response(200, json={
            "models": [
                {"name": "models/gemini-2.5-flash"},
                {"name": "models/gemini-2.5-pro"},
            ]
        })
    _patch_async_client(monkeypatch, handler)

    r = await check_llm_health(timeout=1.0)
    assert r.reachable is True, r.error
