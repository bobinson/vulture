"""Feature 0089 prereqs: model-authored verdicts and URL paths are untrusted input.

P1 — the exploit-confirmation verdict failed open: `llm_result.get("reproduced")`
was copied verbatim, so the string "false" (a routine small-model answer) is
truthy and marked a finding REPRODUCED.

P6 — `staging_url.rstrip("/") + plan.url_path` let a model-authored path such as
"//evil.host/x" or "@evil.host/" pivot the probe onto a different host.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from prove_agent.protocols import jsonrpc_executor as jsonrpc_mod
from prove_agent.protocols import ws_executor as ws_mod
from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.protocols.jsonrpc_executor import execute_jsonrpc
from prove_agent.protocols.ws_executor import execute_websocket
from prove_agent.strategies import shared as shared_mod
from prove_agent.strategies.base import (
    ExecutionResult,
    FailureReason,
    ProofPlan,
)
from prove_agent.strategies.shared import (
    _as_bool,
    execute_and_analyze,
    validate_url_path,
)

_FALSE_VERDICT = {"conclusive": "false", "reproduced": "false", "evidence": "no"}


class _FakeResponse:
    """Minimal httpx.Response stand-in for execute_and_analyze."""

    def __init__(self, text: str = "plain body") -> None:
        self.status_code = 200
        self.text = text
        self.content = text.encode()
        self.headers = {"content-type": "text/plain"}


class _FakeWS:
    def __init__(self, messages: list[str]) -> None:
        self._messages = list(messages)

    async def send(self, payload):
        return None

    async def recv(self):
        if self._messages:
            return self._messages.pop(0)
        raise asyncio.TimeoutError


class _FakeConnect:
    def __init__(self, ws: _FakeWS) -> None:
        self._ws = ws

    async def __aenter__(self):
        return self._ws

    async def __aexit__(self, *exc_info):
        return False


def _plan(url_path: str = "/probe") -> ProofPlan:
    return ProofPlan(
        description="probe",
        method="GET",
        url_path=url_path,
        headers={},
        body="",
        expected_indicators=[],
    )


async def _http_result(monkeypatch, llm_result: dict) -> ExecutionResult:
    """Drive execute_and_analyze past the rule phase into the LLM verdict."""

    async def _fake_retry(_factory, **_kwargs):
        return _FakeResponse()

    async def _fake_llm(_prompt, **_kwargs):
        return llm_result

    monkeypatch.setattr(shared_mod, "retry_with_backoff", _fake_retry)
    monkeypatch.setattr(shared_mod, "analyze_response", lambda **_kw: None)
    monkeypatch.setattr(shared_mod, "llm_json_call", _fake_llm)
    return await execute_and_analyze(_plan(), "http://target", "cat", "title")


async def _ws_result(monkeypatch, llm_result: dict) -> ExecutionResult:
    async def _fake_llm(_prompt, **_kwargs):
        return llm_result

    monkeypatch.setattr(ws_mod, "llm_json_call", _fake_llm)
    fake_websockets = MagicMock()
    fake_websockets.connect.return_value = _FakeConnect(_FakeWS(["hello world"]))
    monkeypatch.setattr(ws_mod, "websockets", fake_websockets)
    return await execute_websocket(
        _plan(), "http://target", TargetCapabilities(), "cat", "title",
    )


async def _jsonrpc_result(monkeypatch, llm_result: dict) -> ExecutionResult:
    async def _fake_llm(_prompt, **_kwargs):
        return llm_result

    async def _fake_http(_envelope, _staging_url, _plan_arg):
        return ExecutionResult(conclusive=False, response_snippet="plain body")

    monkeypatch.setattr(jsonrpc_mod, "llm_json_call", _fake_llm)
    monkeypatch.setattr(jsonrpc_mod, "_jsonrpc_over_http", _fake_http)
    return await execute_jsonrpc(
        _plan(), "http://target", TargetCapabilities(), "cat", "title",
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("false", False),
        ("False", False),
        (" true ", True),
        (0, False),
        (1, True),
        (None, False),
        ("yes", True),
        (True, True),
        ([], False),
        ({}, False),
        ("0", False),
    ],
)
async def test_prereq_reproduced_bool_coercion(monkeypatch, value, expected):
    assert _as_bool(value) is expected

    # The string "false" must not survive as a REPRODUCED verdict on any of the
    # three protocol paths that copy the model's answer into ExecutionResult.
    http = await _http_result(monkeypatch, dict(_FALSE_VERDICT))
    assert http.reproduced is False
    assert http.conclusive is False

    ws = await _ws_result(monkeypatch, dict(_FALSE_VERDICT))
    assert ws.reproduced is False
    assert ws.conclusive is False

    rpc = await _jsonrpc_result(monkeypatch, dict(_FALSE_VERDICT))
    assert rpc.reproduced is False
    assert rpc.conclusive is False


_REJECT_PATHS = [
    "//evil.host/x",
    "@evil.host/",
    "https://x",
    "/a/../b",
    "",
    "/" + "a" * 3000,
]
_ACCEPT_PATHS = ["/api/v1/x?q=1", "/"]


async def test_prereq_url_path_validated(monkeypatch):
    for path in _REJECT_PATHS:
        assert validate_url_path(path) is None, path
    for path in _ACCEPT_PATHS:
        assert validate_url_path(path) == path

    for path in _REJECT_PATHS:
        # HTTP: no request is attempted.
        called = {"n": 0}

        async def _fake_retry(_factory, **_kwargs):
            called["n"] += 1
            return _FakeResponse()

        monkeypatch.setattr(shared_mod, "retry_with_backoff", _fake_retry)
        http = await execute_and_analyze(
            _plan(path), "http://target", "cat", "title",
        )
        assert called["n"] == 0, path
        assert http.reproduced is False
        assert http.failure_reason != FailureReason.NONE

        # WebSocket: no connect is attempted.
        fake_websockets = MagicMock()
        monkeypatch.setattr(ws_mod, "websockets", fake_websockets)
        ws = await execute_websocket(
            _plan(path), "http://target", TargetCapabilities(), "cat", "title",
        )
        fake_websockets.connect.assert_not_called()
        assert ws.reproduced is False
        assert ws.failure_reason != FailureReason.NONE

        # JSON-RPC: neither transport is attempted.
        fake_httpx = MagicMock()
        fake_rpc_ws = MagicMock()
        with patch.object(jsonrpc_mod, "httpx", fake_httpx), \
                patch.object(jsonrpc_mod, "websockets", fake_rpc_ws):
            rpc = await execute_jsonrpc(
                _plan(path), "http://target",
                TargetCapabilities(jsonrpc_http=True), "cat", "title",
            )
        fake_httpx.AsyncClient.assert_not_called()
        fake_rpc_ws.connect.assert_not_called()
        assert rpc.reproduced is False
        assert rpc.failure_reason != FailureReason.NONE
