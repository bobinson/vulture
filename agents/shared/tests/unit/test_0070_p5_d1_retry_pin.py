"""Feature 0070 P5 (D.1) — the retry pin must actually bound HTTP attempts.

The original D.1 fix set the MODULE attribute ``litellm.num_retries = 0`` and
claimed that made ``retry_llm_call`` the only retry authority. It does not, and
this file measures it rather than asserting it:

  * ``litellm.main.completion`` reads ``max_retries`` from PER-CALL kwargs only
    (``kwargs.get("max_retries", None)``). The module attribute
    ``litellm.num_retries`` is consulted on the speech / transcription paths,
    never on chat completions.
  * The one surviving module read is ``litellm.num_retries or
    openai.DEFAULT_MAX_RETRIES`` — and ``0`` is FALSY, so pinning the attribute
    to 0 selects the default (2) it was meant to suppress.

Measured against a stub gateway that counts HTTP attempts and answers 429:
3 attempts with the module pin alone, 1 with ``max_retries=0`` on the call.

The kwarg is delivered through ``ModelSettings.extra_args``, which the SDK's
LitellmModel splats into ``litellm.acompletion``. It is gated to the LiteLLM
path: the native OpenAI path spreads ``extra_args`` into
``client.chat.completions.create(**kwargs)``, whose signature takes no
``max_retries`` and no ``**kwargs`` — an ungated pin would be a TypeError on
every gpt-4o and every broker run.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shared.llm.provider import get_model_settings

# --------------------------------------------------------------------------
# Stub gateway: counts HTTP attempts, always 429 (a RETRYABLE status).
# --------------------------------------------------------------------------

class _Counting429Gateway:
    """OpenAI-compatible endpoint that records every POST it receives."""

    def __init__(self) -> None:
        self.attempts: list[str] = []
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                outer.attempts.append(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                body = json.dumps(
                    {"error": {"message": "rate limited", "type": "rate_limit_error"}}
                ).encode()
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    def __enter__(self) -> "_Counting429Gateway":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()


def _one_completion(base_url: str, extra: dict) -> None:
    """Issue exactly ONE logical completion; swallow the expected 429."""
    import litellm

    litellm.suppress_debug_info = True

    async def _go() -> None:
        try:
            await litellm.acompletion(
                model="openai/stub-model",
                messages=[{"role": "user", "content": "hi"}],
                api_base=base_url,
                api_key="sk-stub",
                **extra,
            )
        except Exception:
            pass

    asyncio.run(_go())


# --------------------------------------------------------------------------
# The measurement.
# --------------------------------------------------------------------------

def test_module_pin_alone_does_not_bound_http_attempts():
    """Control: `litellm.num_retries = 0` leaves the hidden client retries on.

    This documents WHY the shipped fix cannot be the module attribute. It is a
    property of litellm/openai, not of Vulture, so it asserts ">1 attempt" and
    reports the count rather than pinning an exact number.
    """
    from shared import audit_runner

    audit_runner._pin_llm_client_retries()
    import litellm

    assert litellm.num_retries == 0  # the pin is applied...

    with _Counting429Gateway() as gw:
        _one_completion(gw.base_url, {})
        observed = len(gw.attempts)

    assert observed > 1, (
        "control invalidated: this litellm/openai build already issues one "
        f"attempt with no per-call max_retries (observed {observed}); the "
        "regression this file guards can no longer be measured here"
    )


def test_shipped_model_settings_bound_a_429_to_one_http_attempt(monkeypatch):
    """RED before the fix (3 attempts), GREEN after (1).

    Drives the EXACT kwargs `get_model_settings()` ships for a LiteLLM-routed
    model, so the test fails if the pin is dropped, renamed, or moved back to a
    module attribute.
    """
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    settings = get_model_settings("qwen3:8b")  # -> litellm/ollama/qwen3:8b
    extra_args = dict(settings.get("extra_args") or {})

    with _Counting429Gateway() as gw:
        _one_completion(gw.base_url, extra_args)
        observed = len(gw.attempts)

    assert observed == 1, (
        f"a single logical LLM call made {observed} HTTP attempts; "
        f"retry_llm_call is not the only retry authority. extra_args={extra_args!r}"
    )


# --------------------------------------------------------------------------
# Gating: the pin must not reach a call surface that cannot accept it.
# --------------------------------------------------------------------------

def test_litellm_routed_model_carries_max_retries_zero(monkeypatch):
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    settings = get_model_settings("claude-sonnet")  # litellm/anthropic/...
    assert settings.get("extra_args", {}).get("max_retries") == 0


def test_native_openai_model_carries_no_max_retries(monkeypatch):
    """gpt-4o has no `litellm/` prefix: the SDK calls OpenAI directly.

    `OpenAIChatCompletionsModel` / `OpenAIResponsesModel` splat `extra_args`
    into the openai SDK's `create()`, which accepts neither `max_retries` nor
    `**kwargs` — so a pin here is a hard TypeError, not a no-op.
    """
    monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    settings = get_model_settings("gpt-4o")
    assert "max_retries" not in (settings.get("extra_args") or {})


def test_broker_run_carries_no_max_retries(monkeypatch):
    """Broker on: RunConfig swaps in an OpenAIProvider regardless of the prefix.

    broker.py already builds its AsyncOpenAI with `max_retries=0`, so the pin is
    redundant there AND unusable — same TypeError surface as gpt-4o.
    """
    monkeypatch.setenv("VULTURE_LLM_BROKER", "true")
    settings = get_model_settings("claude-sonnet")
    assert "max_retries" not in (settings.get("extra_args") or {})


def test_broker_stripper_removes_the_pin_at_runtime():
    """Defence in depth: the broker decision is made in `_run_llm_agent`.

    `get_model_settings` reads the env; the runner knows whether a per-run
    broker provider was actually built. The runner's answer wins.
    """
    from shared.audit_runner import _drop_litellm_only_settings

    pinned = {"temperature": 0.1, "extra_args": {"max_retries": 0}}
    stripped = _drop_litellm_only_settings(pinned, broker_active=True)
    assert "max_retries" not in (stripped.get("extra_args") or {})
    assert stripped["temperature"] == 0.1
    # ...and it is a no-op off the broker path.
    kept = _drop_litellm_only_settings(pinned, broker_active=False)
    assert kept["extra_args"]["max_retries"] == 0


def test_broker_stripper_leaves_other_extra_args_alone():
    src = {"extra_args": {"max_retries": 0, "reasoning_effort": "low"}}
    from shared.audit_runner import _drop_litellm_only_settings

    out = _drop_litellm_only_settings(src, broker_active=True)
    assert out["extra_args"] == {"reasoning_effort": "low"}
    # the caller's dict must not be mutated
    assert src["extra_args"]["max_retries"] == 0
