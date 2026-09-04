"""Feature 0089 prereqs — adversarial pass over the P1/P6 guards.

The guards themselves live in strategies/shared.py and are exercised by
test_0089_prereqs.py. This file attacks them:

  * the affirmative set must be EXACT — "1.0" is not "1", and a float 1.0
    stringifies to "1.0", so neither may confirm an exploit.
  * a path is untrusted model output, and the seven rejection rules shipped
    with the guard all test PRINTABLE structure. Two classes slip past them:
    a raw backslash (a WHATWG parser folds "/\\evil" to "//evil", the case
    row 4 already refuses) and raw control characters (httpx raises on them,
    turning a rejectable plan into a misleading transport failure, while
    websockets 16.0 silently DELETES them — "/x\\r\\nHost: evil" is probed as
    "/xHost: evil", so the path probed is not the path planned).
  * grpc_executor._try_grpc_http2 joins plan.url_path onto the origin with
    no guard at all; dispatcher.execute_plan routes to it, so it is a live
    fourth site, not dead code.
"""

import asyncio
import sys
from unittest.mock import MagicMock

import httpx
import pytest
from prove_agent.protocols import jsonrpc_executor as jsonrpc_mod
from prove_agent.protocols import ws_executor as ws_mod
from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.protocols.grpc_executor import execute_grpc
from prove_agent.protocols.jsonrpc_executor import execute_jsonrpc
from prove_agent.protocols.ws_executor import execute_websocket
from prove_agent.strategies import shared as shared_mod
from prove_agent.strategies.base import FailureReason, ProofPlan
from prove_agent.strategies.shared import (
    _as_bool,
    execute_and_analyze,
    validate_url_path,
)

_STAGING = "http://target.local"

# Every value the affirmative set may admit, and every attack value it may not.
_AS_BOOL_CASES = [
    (True, True),
    (" true ", True),
    ("TRUE", True),
    ("Yes", True),
    (1, True),
    ("FALSE", False),
    ("0", False),
    ([], False),
    ({}, False),
    (1.0, False),
    ("1.0", False),
]

# Paths the guard must refuse. The reason column is documentation, not asserted
# text — it records WHY each one is refused so a later relaxation is deliberate.
_MUST_REJECT = [
    ("//evil.host/x", "protocol-relative"),
    ("//", "protocol-relative, degenerate"),
    ("@evil.host/", "userinfo — the one case that genuinely repoints httpx"),
    ("https://evil.host/x", "absolute URL"),
    ("/a/../b", "literal '..' segment"),
    ("/..", "'..' as the only segment"),
    ("/x/..", "trailing '..' segment"),
    (" /x", "leading space — not rooted"),
    ("", "empty"),
    ("/" + "a" * 2048, "2049 chars, one over the ceiling"),
    ("/\\evil.host/x", "backslash folds to '//' under a WHATWG parser"),
    ("/x\n", "raw LF"),
    ("/x\r\nHost: evil", "raw CRLF"),
    ("/x\ty", "raw tab"),
    ("/x\x00y", "raw NUL"),
]

# Paths the guard must ADMIT. Percent-encoded traversal is deliberate: it cannot
# change the connection host, and refusing it would blind the agent to the
# path-traversal findings it exists to verify.
_MUST_ACCEPT = [
    "/",
    "/api/v1/x?q=1",
    "/%2e%2e/x",
    "/a/..%2fb",
    "/x?a=//evil",
    "/x#//e",
    "/" + "a" * 2047,
]


@pytest.mark.parametrize(("value", "expected"), _AS_BOOL_CASES)
def test_red_as_bool_affirmative_set_is_exact(value, expected):
    assert _as_bool(value) is expected


@pytest.mark.parametrize(("path", "reason"), _MUST_REJECT)
def test_red_url_path_rejects_host_repoint_and_control_chars(path, reason):
    assert validate_url_path(path) is None, reason


@pytest.mark.parametrize("path", _MUST_ACCEPT)
def test_red_url_path_admits_on_origin_paths(path):
    assert validate_url_path(path) == path


@pytest.mark.parametrize("path", _MUST_ACCEPT)
def test_red_admitted_path_cannot_move_the_host(path):
    """Whatever the guard admits must still resolve to the staging host."""
    assert httpx.URL(_STAGING + path).host == "target.local"


def _plan(path: str) -> ProofPlan:
    return ProofPlan(description="red", method="GET", url_path=path)


def _explode(*_a, **_kw):
    raise AssertionError("outbound call attempted for a rejected path")


@pytest.mark.parametrize(("path", "reason"), _MUST_REJECT)
def test_red_rejected_path_makes_no_http_call(monkeypatch, path, reason):
    monkeypatch.setattr(shared_mod, "retry_with_backoff", _explode)
    result = asyncio.run(execute_and_analyze(_plan(path), _STAGING, "cwe", "t"))
    assert result.reproduced is False
    assert result.conclusive is False
    assert result.failure_reason is FailureReason.FORMAT_ERROR


@pytest.mark.parametrize(("path", "reason"), _MUST_REJECT)
def test_red_rejected_path_makes_no_ws_call(monkeypatch, path, reason):
    fake = MagicMock()
    fake.connect = _explode
    monkeypatch.setattr(ws_mod, "websockets", fake)
    result = asyncio.run(execute_websocket(
        _plan(path), _STAGING, TargetCapabilities(), "cwe", "t",
    ))
    assert result.reproduced is False
    assert result.failure_reason is FailureReason.FORMAT_ERROR


@pytest.mark.parametrize(("path", "reason"), _MUST_REJECT)
@pytest.mark.parametrize("ws_capable", [True, False])
def test_red_rejected_path_makes_no_jsonrpc_call(monkeypatch, path, reason, ws_capable):
    """Both transports, since execute_jsonrpc picks between them."""
    fake_ws = MagicMock()
    fake_ws.connect = _explode
    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _explode
    monkeypatch.setattr(jsonrpc_mod, "websockets", fake_ws)
    monkeypatch.setattr(jsonrpc_mod, "httpx", fake_httpx)
    caps = TargetCapabilities(jsonrpc_ws=ws_capable, jsonrpc_http=not ws_capable)
    result = asyncio.run(execute_jsonrpc(_plan(path), _STAGING, caps, "cwe", "t"))
    assert result.reproduced is False
    assert result.failure_reason is FailureReason.FORMAT_ERROR


@pytest.mark.parametrize(("path", "reason"), _MUST_REJECT)
def test_red_rejected_path_makes_no_grpc_call(monkeypatch, path, reason):
    """The fourth join site: grpc_executor._try_grpc_http2, reached from
    dispatcher.execute_plan when the target advertises gRPC.

    Both transports import their client INSIDE the function, so the patches go
    on the real modules — patching a grpc_executor attribute would miss them.
    """
    monkeypatch.setattr(httpx, "AsyncClient", _explode)
    monkeypatch.setitem(sys.modules, "grpc", None)
    result = asyncio.run(execute_grpc(
        _plan(path), _STAGING, TargetCapabilities(), "cwe", "t",
    ))
    assert result.reproduced is False
    assert result.conclusive is False
    assert result.failure_reason is FailureReason.FORMAT_ERROR


@pytest.mark.parametrize("path", ["/ok", "/api/v1/probe"])
def test_red_grpc_guard_does_not_block_a_legitimate_path(monkeypatch, path):
    """The guard must gate only bad paths — an accepted one still dispatches."""
    monkeypatch.setattr(httpx, "AsyncClient", _explode)
    monkeypatch.setitem(sys.modules, "grpc", None)
    result = asyncio.run(execute_grpc(
        _plan(path), _STAGING, TargetCapabilities(), "cwe", "t",
    ))
    assert result.failure_reason is not FailureReason.FORMAT_ERROR
