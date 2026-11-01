"""Feature 0102: /run authentication and request hygiene, over a real socket.

The wrapper app is served by uvicorn on 127.0.0.1 with an ephemeral port, so
every connection really arrives on a loopback address. The engine is replaced
in-process, so nothing is scanned; each test reads the agent token from the
environment at request time, which is how the plugin must read it.

Contract (docs/spec/plugin-v1/contract.md, "Authentication and request
hygiene"):

* with ``VULTURE_AGENT_TOKEN`` set, ``/run`` needs a matching
  ``X-Vulture-Agent-Token`` (403 ``invalid or missing agent token``); with it
  unset the plugin was started by hand and ``/run`` is open;
* on a loopback connection a non-loopback ``Host`` is refused on every route
  (403 ``forbidden host``);
* ``/run`` requires a JSON Content-Type before it reads the body (415
  ``Content-Type must be application/json``), and a malformed JSON body is the
  caller's error (400 ``invalid JSON body``), not a server error.
"""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from src import wrapper

TOKEN_ENV = "VULTURE_AGENT_TOKEN"
TOKEN_HEADER = "X-Vulture-Agent-Token"
TOKEN = "e2e-plugin-run-token"

TOKEN_REFUSED = {"detail": "invalid or missing agent token"}
HOST_REFUSED = {"detail": "forbidden host"}
NOT_JSON = {"detail": "Content-Type must be application/json"}
BAD_JSON = {"detail": "invalid JSON body"}

EMPTY_SCAN = {"results": [], "errors": [], "paths": {"scanned": [], "skipped": []}}


@pytest.fixture(scope="module")
def plugin():
    """Serve the wrapper app on 127.0.0.1:<ephemeral> for this module.

    h11 hands header bytes to the app as received, so the non-ASCII token case
    reaches the token check rather than being answered by the HTTP parser.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    config = uvicorn.Config(wrapper.app, http="h11", lifespan="off", log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.01)
    yield SimpleNamespace(url=f"http://127.0.0.1:{port}", port=port)
    server.should_exit = True
    thread.join(timeout=15)
    sock.close()


@pytest.fixture
def scan(monkeypatch, tmp_path):
    """Replace the engine, confine source paths to tmp_path, start tokenless.

    ``calls`` records every engine invocation; ``body`` is a valid /run
    envelope, so a refusal can only come from the guard under test.
    """
    calls: list[list[str]] = []

    async def fake_engine(argv: list[str]) -> subprocess.CompletedProcess:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(EMPTY_SCAN), stderr="")

    root = tmp_path / "audit-inputs"
    (root / "src").mkdir(parents=True)
    monkeypatch.setattr(wrapper, "_invoke_engine", fake_engine)
    monkeypatch.setattr(wrapper, "AUDIT_INPUTS_ROOT", str(root))
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    envelope = {
        "envelope": "vulture-plugin/1.0",
        "run_id": "run-e2e-auth",
        "stage": "scan",
        "input": {"source_path": str(root / "src")},
        "config": {},
    }
    return SimpleNamespace(calls=calls, body=json.dumps(envelope).encode())


def _post_run(plugin, body: bytes, headers: dict) -> httpx.Response:
    return httpx.post(f"{plugin.url}/run", content=body, headers=headers, timeout=30)


def _json_run(plugin, scan, headers: dict | None = None) -> httpx.Response:
    return _post_run(plugin, scan.body, {"Content-Type": "application/json", **(headers or {})})


def _sse_event_names(resp: httpx.Response) -> list[str]:
    return [
        line.split(":", 1)[1].strip()
        for line in resp.text.splitlines()
        if line.startswith("event:")
    ]


def _assert_streamed_run(resp: httpx.Response) -> None:
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text[:200]}"
    assert resp.headers["content-type"].startswith("text/event-stream")
    names = _sse_event_names(resp)
    assert names and names[-1] == "run_finished", names


def test_run_requires_token_when_set(plugin, scan, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    presented = {
        "no header": {},
        "wrong header": {TOKEN_HEADER: "not-the-run-token"},
        "non-ASCII header": {TOKEN_HEADER: "tökén".encode()},
    }
    for case, headers in presented.items():
        resp = _json_run(plugin, scan, headers)
        assert resp.status_code == 403, f"{case}: got {resp.status_code}"
        assert resp.json() == TOKEN_REFUSED, case
    assert scan.calls == [], "the engine ran for an unauthenticated /run"


def test_run_accepts_token_and_streams(plugin, scan, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    _assert_streamed_run(_json_run(plugin, scan, {TOKEN_HEADER: TOKEN}))
    assert len(scan.calls) == 1


def test_foreign_host_on_loopback_refused(plugin, scan, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    foreign = {"Host": "evil.example"}

    run = _json_run(plugin, scan, {TOKEN_HEADER: TOKEN, **foreign})
    assert run.status_code == 403, f"/run: got {run.status_code}"
    assert run.json() == HOST_REFUSED

    info = httpx.get(f"{plugin.url}/info", headers=foreign, timeout=30)
    assert info.status_code == 403, f"/info: got {info.status_code}"
    assert info.json() == HOST_REFUSED
    assert scan.calls == [], "the engine ran for a foreign Host"


def test_localhost_host_health_ok(plugin):
    resp = httpx.get(
        f"{plugin.url}/health", headers={"Host": f"localhost:{plugin.port}"}, timeout=30
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_non_json_content_types_415(plugin, scan):
    # Every case carries the same valid JSON envelope: only the declared
    # media type is wrong, and it must be refused before the body is read.
    content_types = {
        "text/plain": "text/plain",
        "form": "application/x-www-form-urlencoded",
        "multipart": "multipart/form-data; boundary=vulture-e2e",
        "missing": None,
    }
    for case, ctype in content_types.items():
        headers = {} if ctype is None else {"Content-Type": ctype}
        resp = _post_run(plugin, scan.body, headers)
        assert resp.status_code == 415, f"{case}: got {resp.status_code}"
        assert resp.json() == NOT_JSON, case
    assert scan.calls == [], "the engine ran for a non-JSON request"


def test_hand_run_without_token_allows_run(plugin, scan):
    # No VULTURE_AGENT_TOKEN: a plugin started by hand. Under the backend's
    # supervisor a token is always injected, so this path is hand-run only.
    _assert_streamed_run(_json_run(plugin, scan))
    assert len(scan.calls) == 1


def test_invalid_json_400(plugin, scan):
    resp = _post_run(plugin, b'{"envelope": "vulture-plugin/1.0", ', {"Content-Type": "application/json"})
    assert resp.status_code == 400, f"got {resp.status_code}"
    assert resp.json() == BAD_JSON
    assert scan.calls == []
