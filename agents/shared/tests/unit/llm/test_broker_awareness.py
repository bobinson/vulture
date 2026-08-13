"""Feature 0073 Phase 2 — the agent must behave correctly when the broker holds
the provider credential and the agent can no longer see OPENAI_BASE_URL.

Before 0073, withholding was a no-op (the launcher merely declined to *append*
the key while the agent inherited the backend's whole environment), so these
paths were never actually exercised with the URL absent. Now that the removal is
real, three predicates that keyed off OPENAI_BASE_URL would silently flip:

  1. check_llm_health()          -> provider="unknown", reachable=False
     which stamps every audit degraded and hard-fails startup under
     VULTURE_REQUIRE_LLM=true.
  2. uses_custom_endpoint()      -> False
     so supports_structured_output() flips True and a response_format JSON
     schema gets sent to LM Studio/vLLM — the "lazy grammar" case.
  3. the 0070-P5 gateway context clamp, which is gated on uses_custom_endpoint().

The launcher now passes VULTURE_LLM_ENDPOINT_KIND=openai-compatible: the endpoint
SHAPE without the URL or the key.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "OPENAI_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
        "VULTURE_LLM_BROKER", "VULTURE_LLM_BROKER_URL", "VULTURE_LLM_ENDPOINT_KIND",
        "VULTURE_USE_LLM", "VULTURE_LLM_MODEL", "OLLAMA_API_BASE",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


def _provider():
    from shared.llm import provider
    return importlib.reload(provider)


# ── uses_custom_endpoint / supports_structured_output ──────────────────────


def test_endpoint_kind_marks_custom_endpoint_without_url(monkeypatch):
    """Broker mode: no OPENAI_BASE_URL, but the shape marker says custom."""
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
    p = _provider()
    assert p.uses_custom_endpoint() is True, (
        "the agent must still know it faces an OpenAI-compatible endpoint"
    )


def test_structured_output_stays_disabled_behind_broker(monkeypatch):
    """The 'lazy grammar' guard must survive the key being withheld."""
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen/qwen3.6-35b-a3b")
    p = _provider()
    assert p.supports_structured_output() is False, (
        "sending a response_format JSON schema to LM Studio via the broker is "
        "exactly what the custom-endpoint guard exists to prevent"
    )


def test_direct_mode_unchanged(monkeypatch):
    """Mode A default: the URL is visible and behaviour is exactly as before."""
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")
    p = _provider()
    assert p.uses_custom_endpoint() is True
    assert p.supports_structured_output() is False


def test_no_endpoint_kind_and_no_url_is_not_custom(monkeypatch):
    """A plain cloud-OpenAI run must not be misreported as a custom endpoint."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    p = _provider()
    assert p.uses_custom_endpoint() is False
    assert p.supports_structured_output() is True


# ── check_llm_health ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_reports_broker_not_unknown(monkeypatch):
    """The regression that would 503 every audit: with the key withheld the
    probe used to fall through to provider='unknown', reachable=False."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://localhost:8090/v1")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "qwen/qwen3.6-35b-a3b")

    from shared.llm import health as health_mod
    importlib.reload(health_mod)

    async def _fake_readyz(url, timeout):
        assert url == "http://localhost:8090/readyz", f"unexpected probe url {url}"
        return True, ""

    monkeypatch.setattr(health_mod, "_probe_broker_readyz", _fake_readyz)
    status = await health_mod.check_llm_health(timeout=1.0)

    assert status.provider == "broker", f"expected broker, got {status.provider!r}"
    assert status.reachable is True
    assert status.model == "qwen/qwen3.6-35b-a3b"


@pytest.mark.asyncio
async def test_health_broker_unready_is_reported_honestly(monkeypatch):
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://localhost:8090/v1")

    from shared.llm import health as health_mod
    importlib.reload(health_mod)

    async def _fake_readyz(url, timeout):
        return False, "no healthy provider"

    monkeypatch.setattr(health_mod, "_probe_broker_readyz", _fake_readyz)
    status = await health_mod.check_llm_health(timeout=1.0)

    assert status.provider == "broker"
    assert status.reachable is False
    assert "no healthy provider" in (status.error or "")


@pytest.mark.asyncio
async def test_health_disabled_still_wins(monkeypatch):
    """LLM off must short-circuit before any broker probe."""
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")

    from shared.llm import health as health_mod
    importlib.reload(health_mod)
    status = await health_mod.check_llm_health(timeout=1.0)
    assert status.provider == "disabled"


@pytest.mark.asyncio
async def test_health_direct_mode_unchanged(monkeypatch):
    """Broker off: the existing precedence chain is untouched."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:1234/v1")

    from shared.llm import health as health_mod
    importlib.reload(health_mod)

    called = {}

    async def _fake_compat(base_url, model, timeout):
        called["url"] = base_url
        from shared.llm.health import LLMHealthStatus
        return LLMHealthStatus(provider="lmstudio", endpoint=base_url,
                               model=model, reachable=True, error="", detail={})

    monkeypatch.setattr(health_mod, "_probe_openai_compatible", _fake_compat)
    status = await health_mod.check_llm_health(timeout=1.0)
    assert called["url"] == "http://localhost:1234/v1"
    assert status.provider == "lmstudio"
