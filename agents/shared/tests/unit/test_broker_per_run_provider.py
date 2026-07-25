"""Feature 0064 must-fix: per-run broker client (no process-global mutation).

The former design installed the broker client via
``agents.set_default_openai_client`` — process-global SDK state. Under
``VULTURE_AUDIT_EXECUTOR_WORKERS > 1`` two concurrent audits would race the
global and could bleed one run's broker token into another run's calls
(tenant-isolation class bug). The fix: ``broker_model_provider()`` builds a
PER-RUN model provider passed via ``RunConfig(model_provider=...)`` — no
global is ever touched.
"""

import contextvars

import pytest

from shared.llm import broker


def _enable_broker(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker.internal:8090/internal/v1/llm")


class _FakeClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key


class _FakeProvider:
    def __init__(self, client):
        self.client = client


def _provider_in_ctx(token: str | None):
    """Build the provider inside a fresh context carrying *token*."""
    ctx = contextvars.copy_context()

    def _run():
        broker.set_broker_token(token)
        return broker.broker_model_provider(
            client_factory=lambda base_url, api_key: _FakeClient(base_url, api_key),
            provider_factory=lambda client: _FakeProvider(client),
        )

    return ctx.run(_run)


def test_provider_off_returns_none(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    assert _provider_in_ctx("tok-1") is None


def test_provider_on_without_token_returns_none(monkeypatch):
    _enable_broker(monkeypatch)
    assert _provider_in_ctx(None) is None


def test_provider_on_builds_client_from_ambient_token(monkeypatch):
    _enable_broker(monkeypatch)
    prov = _provider_in_ctx("run-token-A")
    assert prov is not None
    assert prov.client.base_url == "http://broker.internal:8090/internal/v1/llm"
    assert prov.client.api_key == "run-token-A"


def test_provider_is_per_run_not_global(monkeypatch):
    """Two concurrent runs get their OWN providers with their OWN tokens."""
    _enable_broker(monkeypatch)
    prov_a = _provider_in_ctx("run-token-A")
    prov_b = _provider_in_ctx("run-token-B")
    assert prov_a is not prov_b
    assert prov_a.client.api_key == "run-token-A"
    assert prov_b.client.api_key == "run-token-B"


def test_provider_never_touches_global_sdk_client(monkeypatch):
    """The race root cause: the global SDK setter must never be called."""
    _enable_broker(monkeypatch)
    import agents

    def _forbidden(*a, **k):  # pragma: no cover - failure path
        raise AssertionError("broker_model_provider mutated process-global SDK state")

    monkeypatch.setattr(agents, "set_default_openai_client", _forbidden)
    prov = _provider_in_ctx("run-token-A")
    assert prov is not None


def test_provider_real_sdk_default_factories(monkeypatch):
    """Without injected factories the provider is a real SDK ModelProvider
    (chat/completions mode) usable as RunConfig(model_provider=...)."""
    _enable_broker(monkeypatch)
    ctx = contextvars.copy_context()

    def _run():
        broker.set_broker_token("run-token-real")
        return broker.broker_model_provider()

    prov = ctx.run(_run)
    assert prov is not None
    assert hasattr(prov, "get_model"), "must satisfy the SDK ModelProvider interface"


def test_global_mutation_path_is_gone():
    """The condemned global-mutation entry point must no longer exist."""
    assert not hasattr(broker, "apply_broker_from_context")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
