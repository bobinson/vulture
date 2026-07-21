"""Feature 0064 §26 C1/M7 — Python broker seam: task_type header + client close."""

import contextvars

import pytest

from shared.llm import broker


def _enable(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker.internal:8090/v1")


class _FakeClient:
    def __init__(self, base_url, api_key, default_headers=None):
        self.base_url = base_url
        self.api_key = api_key
        self.default_headers = default_headers
        self.closed = False

    async def aclose(self):
        self.closed = True


def test_default_client_sends_task_type_header(monkeypatch):
    """§26 C1: the real client factory carries X-Vulture-Task-Type from the
    ambient task_type (request_id is NOT sent — the broker generates it)."""
    _enable(monkeypatch)
    captured = {}

    def _fake_async_openai(base_url, api_key, default_headers=None, **kwargs):
        captured["headers"] = default_headers
        captured["kwargs"] = kwargs
        return _FakeClient(base_url, api_key, default_headers)

    import types, sys

    fake_openai = types.ModuleType("openai")
    fake_openai.AsyncOpenAI = _fake_async_openai  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_openai)

    ctx = contextvars.copy_context()

    def _run():
        broker.set_broker_token("tok-1")
        broker.set_broker_task_type("scan")
        # provider_factory identity so we don't need the agents SDK here.
        return broker.broker_model_provider(provider_factory=lambda c: c)

    client = ctx.run(_run)
    assert client is not None
    assert captured["headers"] == {"X-Vulture-Task-Type": "scan"}
    assert "X-Vulture-Request-Id" not in captured["headers"]


@pytest.mark.asyncio
async def test_aclose_closes_the_run_client(monkeypatch):
    """§26 M7: the per-run client is closed by aclose_broker_client. Build and
    close run in one async context, exactly as the audit worker does."""
    _enable(monkeypatch)
    client = _FakeClient("http://broker.internal:8090/v1", "tok")
    broker.set_broker_token("tok")
    broker.broker_model_provider(
        client_factory=lambda base_url, api_key: client,
        provider_factory=lambda c: c,
    )
    await broker.aclose_broker_client()
    assert client.closed is True
    # Idempotent: a second close is a no-op (client already released).
    await broker.aclose_broker_client()


@pytest.mark.asyncio
async def test_aclose_noop_when_no_client():
    """aclose is a safe no-op when the broker was off (no client built)."""
    broker.set_broker_token(None)
    await broker.aclose_broker_client()  # must not raise


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_current_llm_path(monkeypatch):
    """§14: broker when routed through the broker, env otherwise."""
    import contextvars

    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", "http://broker.internal:8090/v1")

    def _with(token):
        ctx = contextvars.copy_context()
        return ctx.run(lambda: (broker.set_broker_token(token), broker.current_llm_path())[1])

    assert _with("run-tok") == "broker"   # enabled + url + token
    assert _with(None) == "env"           # no run token -> env-key path

    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    assert _with("run-tok") == "env"      # broker off -> env-key path
