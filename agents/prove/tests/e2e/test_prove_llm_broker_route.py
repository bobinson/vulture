"""E2E: on a broker run, prove's LLM calls reach the LLM through the broker.

Broker mode withholds the provider endpoint and key from agents
(OPENAI_BASE_URL, OPENAI_API_KEY); each run instead carries a per-run broker
token. The SDK generate path and the L5 judge route through the broker with
it. Prove calls litellm directly and did not: it sent the plain model name with
no endpoint, and every call failed with "LLM Provider NOT provided" before
leaving the process. Measured live: 101 findings tested, 99 inconclusive.

Contract, driven through the REAL ``llm_json_call`` and the REAL litellm
client against a stub broker (only the broker is stubbed):

* the call reaches the broker's chat-completions endpoint with this run's
  token as the bearer credential and its task-type header, and the model goes
  as the plain name — the broker's model hint;
* the broker is the one retry authority: a rejected call costs exactly one
  HTTP request per prove attempt, never more;
* without a broker, the custom-endpoint path is unchanged.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from prove_agent import llm_helper
from shared.llm import provider
from shared.llm.broker import set_broker_task_type, set_broker_token
from shared.llm.cooldown import cooldown_manager

MODEL = "qwen3.8-flash-next-iq3_s"
RUN_TOKEN = "run-token-for-this-audit"
ANSWER = {"plan": "probe /login without a session cookie"}


class _StubBroker:
    """OpenAI-compatible endpoint that records every request it receives."""

    def __init__(self, status: int) -> None:
        self.requests: list[dict] = []
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self._reply(status, _completion(json.dumps(ANSWER)) if status == 200 else _rejection())

            def _reply(self, code: int, payload: dict) -> None:
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}/v1"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _completion(content: str) -> dict:
    return {
        "id": "cmpl-1", "object": "chat.completion", "created": 0, "model": MODEL,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def _rejection() -> dict:
    return {"error": {"message": "rate limited", "type": "rate_limit_error"}}


@pytest.fixture
def broker(monkeypatch, request):
    stub = _StubBroker(getattr(request, "param", 200))
    monkeypatch.setenv("VULTURE_LLM_BROKER", "on")
    monkeypatch.setenv("VULTURE_LLM_BROKER_URL", stub.base_url)
    monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)
    # Withheld from agents in broker mode, so absent here.
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", "")
    monkeypatch.setattr(llm_helper, "_cached_model", None)
    set_broker_token(RUN_TOKEN)
    set_broker_task_type("prove")
    yield stub
    set_broker_token(None)
    set_broker_task_type(None)
    cooldown_manager.reset()
    stub.close()


def _call() -> dict:
    return asyncio.run(llm_helper.llm_json_call("Plan a probe for: missing CSRF token."))


def test_broker_run_reaches_the_llm_through_the_broker(broker):
    assert _call() == ANSWER

    assert len(broker.requests) == 1
    sent = broker.requests[0]
    headers = {k.lower(): v for k, v in sent["headers"].items()}
    assert sent["path"] == "/v1/chat/completions"
    assert headers["authorization"] == f"Bearer {RUN_TOKEN}"
    assert headers["x-vulture-task-type"] == "prove"
    assert sent["body"]["model"] == MODEL


@pytest.mark.parametrize("broker", [429], indirect=True)
def test_broker_owns_retries(broker):
    assert _call() == {}  # handled: prove falls back, nothing raises

    assert len(broker.requests) == llm_helper._MAX_RETRIES


def test_without_a_broker_the_custom_endpoint_path_is_unchanged(monkeypatch):
    stub = _StubBroker(200)
    try:
        monkeypatch.delenv("VULTURE_LLM_BROKER", raising=False)
        monkeypatch.setenv("VULTURE_LLM_MODEL", MODEL)
        monkeypatch.setenv("OPENAI_BASE_URL", stub.base_url)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setattr(provider, "_CUSTOM_BASE_URL", stub.base_url)
        monkeypatch.setattr(llm_helper, "_cached_model", None)
        set_broker_token(None)

        assert _call() == ANSWER

        sent = stub.requests[0]
        headers = {k.lower(): v for k, v in sent["headers"].items()}
        assert sent["body"]["model"] == MODEL
        assert "x-vulture-task-type" not in headers
    finally:
        cooldown_manager.reset()
        stub.close()
