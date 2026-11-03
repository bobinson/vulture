"""A judge batch whose request fails in TRANSPORT stops at that failure.

The L5 judge's fallback chain — tool loop -> plain judging, structured-output
mode -> plain mode, the base token budget -> double, then a strict-JSON nudge —
exists for MALFORMED ANSWERS: a provider that rejects ``response_format`` or
``tools=``, a reasoning model that truncates, a reply that is not JSON. It used
to run for every failure. Against a saturated broker that answered 429, one
batch issued ~9 requests, each multiplied by the SDK's own two retries: ~27
rate-limited HTTP requests in ~15 s, then "no verdict". Measured on an 8-agent
scan: 2,552 rate_limited rejections in 4.5 minutes, most judge batches on every
agent ending judge_error, while the model itself was idle.

A transport failure — rate limited, connection refused/reset/unreachable, or a
5xx other than the broker's permanent codes — is not fixed by reshaping the
request, so the batch now ends there: one logical request per batch, whose HTTP
attempts are bounded by the SDK's own retries (which honour the broker's
Retry-After). A TIMEOUT is not one: a judge request often times out because of
its size (a long tool-loop turn, a json_object request), and the smaller plain
request is what used to recover a verdict. Timeouts and format failures keep
today's whole chain.
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from shared.validate import llm_judge
from shared.validate.llm_judge import run_l5
from shared.validate.types import ValidateConfig

openai = pytest.importorskip("openai")


# ── broker / provider envelopes, as the broker writes them ──────────────────

BROKER_RATE_LIMITED = {"error": {
    "message": "rate limited", "type": "rate_limited", "code": "rate_limited",
    "x_retriable": True}}
BROKER_UNAVAILABLE = {"error": {
    "message": "provider unavailable", "type": "provider_unavailable",
    "code": "provider_unavailable", "x_retriable": True}}
BROKER_BAD_REQUEST = {"error": {
    "message": "provider rejected the request", "type": "provider_bad_request",
    "code": "provider_bad_request", "x_retriable": False}}
# A provider refusing structured output. Its text happens to contain "500"
# (inside 15000): a status-blind regex reads that as a server error.
FORMAT_REJECTED = {"error": {
    "message": "response_format json_object is not supported with max_tokens above 15000",
    "type": "invalid_request_error"}}

_VALID = json.dumps({"verdicts": [{"id": "f0", "exploitable": 0.9, "reasoning": "x"}]})


class _Stub:
    """A local HTTP endpoint answering every POST with one scripted response,
    counting what actually arrives."""

    def __init__(self, status: int, payload: dict, headers: dict | None = None,
                 delay_s: float = 0.0) -> None:
        stub = self
        self.posts = 0
        self._lock = threading.Lock()

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                self.rfile.read(length)
                with stub._lock:
                    stub.posts += 1
                if delay_s:
                    time.sleep(delay_s)
                body = json.dumps(payload).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    for k, v in (headers or {}).items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass  # the client gave up (timeout case)

            def log_message(self, *a):
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self._srv.server_address[1]}/v1"

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


def _sdk_error(status: int, payload: dict, **client_kw: Any) -> Exception:
    """The exception the REAL openai SDK raises for this response."""
    stub = _Stub(status, payload)
    try:
        client = openai.OpenAI(base_url=stub.base_url, api_key="test", max_retries=0, **client_kw)
        with pytest.raises(Exception) as ei:
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        return ei.value
    finally:
        stub.close()


def _timeout_error() -> Exception:
    stub = _Stub(200, {}, delay_s=1.0)
    try:
        client = openai.OpenAI(base_url=stub.base_url, api_key="test", max_retries=0, timeout=0.1)
        with pytest.raises(Exception) as ei:
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        return ei.value
    finally:
        stub.close()


def _connection_error() -> Exception:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    client = openai.OpenAI(base_url=f"http://127.0.0.1:{port}/v1", api_key="test", max_retries=0)
    with pytest.raises(Exception) as ei:
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
    return ei.value


def _reset_error() -> Exception:
    """The SDK's error for a connection the server RESETS mid-request."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def _reset() -> None:
        conn, _ = srv.accept()
        conn.recv(65536)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        conn.close()  # linger 0: RST, not FIN

    threading.Thread(target=_reset, daemon=True).start()
    try:
        client = openai.OpenAI(base_url=f"http://127.0.0.1:{srv.getsockname()[1]}/v1",
                               api_key="test", max_retries=0)
        with pytest.raises(Exception) as ei:
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        return ei.value
    finally:
        srv.close()


TRANSPORT_ERRORS: dict[str, Callable[[], Exception]] = {
    "rate_limited_429": lambda: _sdk_error(429, BROKER_RATE_LIMITED),
    "provider_unavailable_502": lambda: _sdk_error(502, BROKER_UNAVAILABLE),
    "connection_refused": _connection_error,
    "connection_reset": _reset_error,
}


# ── a fake client that answers from a script and records every request ─────


class _Msg:
    def __init__(self, content: str | None) -> None:
        self.content = content
        self.tool_calls = None


class _Choice:
    def __init__(self, content: str | None) -> None:
        self.message = _Msg(content)
        self.finish_reason = "stop"


class _Resp:
    def __init__(self, content: str | None) -> None:
        self.choices = [_Choice(content)]


class _ScriptedCompletions:
    """Each create() takes the next scripted step: an Exception is raised, a
    string is answered as the message content. The last step repeats."""

    def __init__(self, script: list[Any]) -> None:
        self._script = script
        self.calls: list[dict] = []

    def create(self, **kw: Any) -> _Resp:
        self.calls.append(kw)
        step = self._script[min(len(self.calls), len(self._script)) - 1]
        if isinstance(step, BaseException):
            raise step
        return _Resp(step)


def _wire(monkeypatch, script: list[Any]) -> _ScriptedCompletions:
    comp = _ScriptedCompletions(script)
    client = type("C", (), {})()
    client.chat = type("chat", (), {})()
    client.chat.completions = comp
    monkeypatch.setattr(llm_judge, "_get_client", lambda: client)
    return comp


def _finding(tmp_path) -> dict:
    (tmp_path / "handler.js").write_text(
        "function update(req, res) {\n  db.update({ where: { id: req.params.id } })\n}\n")
    return {
        "id": "f0", "severity": "high", "title": "IDOR",
        "file_path": "handler.js", "line_start": 2, "line_end": 2,
        "description": "d", "code_snippet": "2: db.update(...)",
        "check_id": "chk", "category": "CWE-639",
    }


def _cfg() -> ValidateConfig:
    return ValidateConfig(enable_l5=True, l5_model_override="test-model")


def _l5_check(finding: dict) -> dict:
    return next(c for c in finding["validation"]["checks"] if c["id"] == "llm_judge")


# ── transport failures end the batch at the first request ─────────────────


@pytest.mark.parametrize("kind", sorted(TRANSPORT_ERRORS))
def test_transport_failure_on_the_plain_path_makes_one_request(monkeypatch, tmp_path, kind):
    exc = TRANSPORT_ERRORS[kind]()
    comp = _wire(monkeypatch, [exc])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())  # no source path: no tools, the plain path

    assert len(comp.calls) == 1, (
        f"{kind}: {len(comp.calls)} requests for one batch; a transport failure must not "
        f"walk the mode/budget/strict-JSON fallbacks (each adds the SDK's own retries)"
    )
    assert _l5_check(f)["result"] == "error", "the batch still records that it got no verdict"


@pytest.mark.parametrize("kind", sorted(TRANSPORT_ERRORS))
def test_transport_failure_on_the_tool_path_does_not_fall_back(monkeypatch, tmp_path, kind):
    exc = TRANSPORT_ERRORS[kind]()
    comp = _wire(monkeypatch, [exc])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))  # tools on

    assert len(comp.calls) == 1, (
        f"{kind}: {len(comp.calls)} requests; the tool loop's failure must not fall back to "
        f"plain judging when the endpoint itself is unavailable"
    )
    assert "tools" in comp.calls[0]
    assert _l5_check(f)["result"] == "error"


def test_a_format_rejection_then_transport_failure_stops_there(monkeypatch, tmp_path):
    """The mode fallback runs for the format rejection; the 429 that answers it
    ends the batch — no doubled budget, no strict-JSON retry."""
    comp = _wire(monkeypatch, [
        _sdk_error(400, FORMAT_REJECTED),
        _sdk_error(429, BROKER_RATE_LIMITED),
        _VALID,
    ])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())

    assert len(comp.calls) == 2, [sorted(c) for c in comp.calls]
    assert "response_format" in comp.calls[0] and "response_format" not in comp.calls[1]
    assert _l5_check(f)["result"] == "error"


# ── timeouts keep the whole chain ─────────────────────────────────────────


def test_a_timeout_on_the_plain_path_walks_the_fallbacks(monkeypatch, tmp_path):
    """A json_object request that times out is retried in plain mode — which is
    what recovers the verdict when the size of the request was the problem."""
    comp = _wire(monkeypatch, [_timeout_error(), _VALID])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())

    assert len(comp.calls) == 2
    assert "response_format" in comp.calls[0] and "response_format" not in comp.calls[1]
    assert _l5_check(f)["weight"] > 0, "the plain-mode answer must become the verdict"


def test_a_timeout_on_the_tool_path_falls_back_to_plain_judging(monkeypatch, tmp_path):
    """A tool-loop turn that times out (it carries the tool results) falls back
    to the smaller plain request, as before."""
    comp = _wire(monkeypatch, [_timeout_error(), _VALID])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))

    assert "tools" in comp.calls[0] and "tools" not in comp.calls[1]
    assert _l5_check(f)["weight"] > 0


@pytest.mark.parametrize("make", [
    _timeout_error,
    lambda: _sdk_error(408, {"error": {"message": "request timeout"}}),
    lambda: _sdk_error(504, {"error": {"message": "gateway gave up waiting"}}),
], ids=["client_timeout", "http_408", "gateway_504"])
def test_timeouts_are_not_transport(make):
    assert not llm_judge._is_transport_failure(make())


# ── format failures keep the whole chain ──────────────────────────────────


def test_a_format_rejection_still_falls_back_to_plain_mode(monkeypatch, tmp_path):
    comp = _wire(monkeypatch, [_sdk_error(400, FORMAT_REJECTED), _VALID])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())

    assert len(comp.calls) == 2
    assert "response_format" in comp.calls[0] and "response_format" not in comp.calls[1]
    assert _l5_check(f)["weight"] > 0, "the plain-mode answer must become the verdict"


def test_the_brokers_permanent_bad_request_still_falls_back(monkeypatch, tmp_path):
    """The broker relays an upstream 400 as a 502 provider_bad_request with
    x_retriable false: a request-shape fault (often the response_format), not
    an outage, so plain mode must still be tried."""
    comp = _wire(monkeypatch, [_sdk_error(502, BROKER_BAD_REQUEST), _VALID])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())

    assert len(comp.calls) == 2
    assert _l5_check(f)["weight"] > 0


def test_a_rejected_tools_parameter_still_falls_back_to_plain_judging(monkeypatch, tmp_path):
    comp = _wire(monkeypatch, [_sdk_error(400, {"error": {
        "message": "unknown parameter: tools", "type": "invalid_request_error"}}), _VALID])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg(), source_path=str(tmp_path))

    assert "tools" in comp.calls[0] and "tools" not in comp.calls[1]
    assert _l5_check(f)["weight"] > 0


def test_empty_answers_still_walk_modes_budgets_and_the_strict_retry(monkeypatch, tmp_path):
    comp = _wire(monkeypatch, [""])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())

    budgets = [c["max_tokens"] for c in comp.calls]
    assert len(comp.calls) > 2, "an empty answer must still be retried in the other mode and budget"
    assert any("response_format" in c for c in comp.calls)
    assert any("response_format" not in c for c in comp.calls)
    assert max(budgets) > min(budgets), "the widened budget must still be tried"
    assert any("not valid JSON" in c["messages"][-1]["content"] for c in comp.calls), (
        "the strict-JSON nudge must still be sent"
    )


def test_an_unparseable_answer_still_gets_the_strict_json_retry(monkeypatch, tmp_path):
    comp = _wire(monkeypatch, ["this is prose, not JSON", _VALID])
    f = _finding(tmp_path)

    run_l5([f], [[]], _cfg())

    assert len(comp.calls) == 2
    assert "not valid JSON" in comp.calls[1]["messages"][-1]["content"]
    assert _l5_check(f)["weight"] > 0


# ── the classification itself ─────────────────────────────────────────────


@pytest.mark.parametrize("kind", sorted(TRANSPORT_ERRORS))
def test_transport_errors_are_classified_as_transport(kind):
    assert llm_judge._is_transport_failure(TRANSPORT_ERRORS[kind]())


@pytest.mark.parametrize("status,payload", [
    (400, FORMAT_REJECTED),
    (502, BROKER_BAD_REQUEST),
    (404, {"error": {"message": "model not found", "type": "model_not_found",
                     "code": "model_not_found", "x_retriable": False}}),
])
def test_request_shape_and_permanent_errors_are_not_transport(status, payload):
    assert not llm_judge._is_transport_failure(_sdk_error(status, payload))


def test_a_plain_exception_is_not_transport():
    """Unknown failures keep the fallback chain, as before."""
    assert not llm_judge._is_transport_failure(RuntimeError("400: unknown parameter: tools"))


@pytest.mark.parametrize("exc", [
    ConnectionResetError(104, "Connection reset by peer"),
    RuntimeError("socket hang up: read ECONNRESET"),
], ids=["reset_by_peer", "econnreset"])
def test_a_reset_connection_is_transport_however_it_is_worded(exc):
    """The shared classifier files ECONNRESET under timeout; a reset is the
    endpoint dropping the connection, not a slow answer."""
    assert llm_judge._is_transport_failure(exc)


# ── at the HTTP boundary, with the real SDK and its default retries ────────


def test_a_rate_limited_batch_costs_only_the_sdks_own_retries(monkeypatch, tmp_path):
    """What leaves the process. Before: ~9 requests x 3 SDK attempts = ~27
    rate-limited POSTs per batch. Now: one request, i.e. 1 + the SDK's 2
    retries. (retry-after-ms keeps the test fast; the broker sends Retry-After.)"""
    stub = _Stub(429, BROKER_RATE_LIMITED, headers={"retry-after-ms": "1"})
    try:
        client = openai.OpenAI(base_url=stub.base_url, api_key="test")  # SDK default retries
        monkeypatch.setattr(llm_judge, "_get_client", lambda: client)
        f = _finding(tmp_path)

        run_l5([f], [[]], _cfg(), source_path=str(tmp_path))

        assert stub.posts == 1 + client.max_retries, (
            f"{stub.posts} HTTP requests for one rate-limited batch, want "
            f"{1 + client.max_retries} (one request plus the SDK's own retries)"
        )
        assert _l5_check(f)["result"] == "error"
    finally:
        stub.close()
