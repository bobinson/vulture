"""Feature 0101 E2E: proof evidence and the prove stream carry no repository
or server information.

Business contract. Proof evidence is persisted (prove_results.evidence) and
an ``ERROR:`` stream line becomes the audit's stored error message, so both
reach whoever reads the audit. They may say what KIND of failure happened
(a fixed category, the exception class, an HTTP status the target returned)
and the target URL the user configured. They may not carry:

- raw exception text: a resolver error names an internal host, a refused
  connection names an internal address, and an exception raised while
  handling a finding can name a source path;
- the strings the agent showed the model about the finding (its source path
  and code excerpt), which a model echoes back into plans and verdicts;
- secret-shaped values.

A leaked path is also SENT TO THE TARGET: every ``/word`` in attempt
evidence is crawled on the staging host by incremental discovery.

All fixtures are synthetic. Nothing here touches the network: every
transport is stubbed to raise.
"""

import json
import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.protocols.grpc_executor import execute_grpc
from prove_agent.protocols.jsonrpc_executor import execute_jsonrpc
from prove_agent.protocols.ws_executor import _classify_ws_failure, execute_websocket
from prove_agent.runner import prove_finding_with_timeout
from prove_agent.strategies.base import (
    ExecutionResult,
    FailureReason,
    ProbeProtocol,
    ProofPlan,
    ReflectionResult,
    ReviewResult,
)
from prove_agent.strategies.shared import execute_and_analyze
from shared.transport.event_emitter import AgUiEventEmitter

STAGING = "https://staging.example"
SOURCE_ROOT = "/srv/fake-repo"
TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE1234"
MSG = (
    f"open {SOURCE_ROOT}/src/billing/ledger.py failed; token={TOKEN} "
    "via db.corp.internal:5432"
)
SNIPPET_LINE = 'raise LedgerError(f"settle failed for {account.iban}")'
LEAKS = (SOURCE_ROOT, "fake-repo", "ledger.py", "ghp_FAKE", "db.corp.internal", "LedgerError")
FINDING = {
    "id": "f-ledger-1",
    "title": "Error detail exposure",
    "category": "CWE-209",
    "agent_type": "cwe",
    "file_path": "src/billing/ledger.py",
    "line_start": 42,
    "code_snippet": f"41: def settle(account):\n42:     {SNIPPET_LINE}\n43: ",
}
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _leaks(text: str) -> list[str]:
    return [leak for leak in LEAKS if leak in text]


def _plan(protocol: ProbeProtocol = ProbeProtocol.HTTP, **kw) -> ProofPlan:
    return ProofPlan(description="probe", method="GET", url_path="/api/orders",
                     protocol=protocol, **kw)


def _raising_client(exc: BaseException):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    def factory(*_a, **_kw):
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(handler))
    return factory


def _connect_error() -> httpx.ConnectError:
    try:
        try:
            raise ConnectionRefusedError(MSG)
        except ConnectionRefusedError as cause:
            raise httpx.ConnectError(MSG) from cause
    except httpx.ConnectError as exc:
        return exc


def _events(raw: list[str]) -> list[tuple[str, dict]]:
    out = []
    for event in raw:
        name = event.split("\n", 1)[0].removeprefix("event: ")
        out.append((name, json.loads(event.split("data: ", 1)[1])))
    return out


# --- 1. Executors: failure evidence is a category, never the exception text ---


class TestExecutorFailureEvidence:
    async def test_websocket(self):
        with patch("prove_agent.protocols.ws_executor.websockets.connect",
                   side_effect=ConnectionRefusedError(MSG)):
            r = await execute_websocket(
                _plan(ProbeProtocol.WEBSOCKET), STAGING,
                TargetCapabilities(websocket=True), "CWE-209", "t",
            )
        assert _leaks(r.evidence) == []
        assert r.evidence == "WebSocket error: connection refused (ConnectionRefusedError)"
        assert r.failure_reason == FailureReason.CONNECTION_ERROR

    async def test_http(self):
        client = _raising_client(_connect_error())()
        with patch("asyncio.sleep", new=AsyncMock()):
            r = await execute_and_analyze(_plan(), STAGING, "CWE-209", "t", client=client)
        assert _leaks(r.evidence) == []
        assert r.evidence == "Connection failed: connection refused (ConnectError)"
        assert r.failure_reason == FailureReason.CONNECTION_ERROR

    async def test_jsonrpc_over_websocket(self):
        with patch("prove_agent.protocols.jsonrpc_executor.websockets.connect",
                   side_effect=OSError(MSG)):
            r = await execute_jsonrpc(
                _plan(ProbeProtocol.JSONRPC), STAGING,
                TargetCapabilities(jsonrpc_ws=True), "CWE-209", "t",
            )
        assert _leaks(r.evidence) == []
        assert r.evidence == "JSON-RPC/WS error: connection failed (OSError)"
        assert r.failure_reason == FailureReason.CONNECTION_ERROR

    async def test_jsonrpc_over_http(self):
        with patch("prove_agent.protocols.jsonrpc_executor.httpx.AsyncClient",
                   side_effect=_raising_client(_connect_error())):
            r = await execute_jsonrpc(
                _plan(ProbeProtocol.JSONRPC), STAGING,
                TargetCapabilities(jsonrpc_http=True), "CWE-209", "t",
            )
        assert _leaks(r.evidence) == []
        assert r.evidence == "JSON-RPC/HTTP connection failed: connection refused (ConnectError)"
        assert r.failure_reason == FailureReason.CONNECTION_ERROR

    async def test_grpc_http2_fallback(self):
        with patch("prove_agent.protocols.grpc_executor._try_grpc_native",
                   new=AsyncMock(return_value=None)), \
             patch("httpx.AsyncClient", side_effect=_raising_client(ssl.SSLError(MSG))):
            r = await execute_grpc(_plan(ProbeProtocol.GRPC), STAGING, None, "CWE-209", "t")
        assert _leaks(r.evidence) == []
        assert r.evidence == "gRPC HTTP/2 probe failed: TLS handshake failed (SSLError)"
        assert r.failure_reason == FailureReason.CONNECTION_ERROR

    @pytest.mark.parametrize(("exc", "expected"), [
        (socket.gaierror(MSG), "name resolution failed (gaierror)"),
        (TimeoutError(MSG), "timed out (TimeoutError)"),
        (InvalidStatus(Response(403, "Forbidden", Headers(), b"")),
         "handshake rejected (InvalidStatus, HTTP 403)"),
        (RuntimeError(MSG), "internal error (RuntimeError)"),
    ])
    async def test_category_table(self, exc, expected):
        with patch("prove_agent.protocols.ws_executor.websockets.connect", side_effect=exc):
            r = await execute_websocket(
                _plan(ProbeProtocol.WEBSOCKET), STAGING,
                TargetCapabilities(websocket=True), "CWE-209", "t",
            )
        assert r.evidence == f"WebSocket error: {expected}"
        # The failure_reason classifier is unchanged: it drives protocol fallback.
        assert r.failure_reason == _classify_ws_failure(exc)


# --- 2. Runner stream: model echoes of the finding are scrubbed at emit time ---


class _EchoStrategy:
    """Stands in for an LLM strategy that repeats what it was shown."""

    def __init__(self, *, confidence: int = 40, conclusive_first: bool = False):
        self.confidence = confidence
        self.conclusive_first = conclusive_first
        self.calls = 0

    async def plan(self, finding, staging_url, iteration, **_kw):
        return ProofPlan(
            description=f"Probe {finding['file_path']} where `{SNIPPET_LINE}` uses {TOKEN}",
            method="GET", url_path="/api/orders", protocol=ProbeProtocol.WEBSOCKET,
        )

    async def review(self, plan, staging_url):
        return ReviewResult(safe=True, concerns=[f"reads {SOURCE_ROOT}/src/billing/ledger.py"])

    async def execute(self, plan, staging_url, capabilities=None):
        self.calls += 1
        if self.calls == 1:
            return ExecutionResult(
                conclusive=self.conclusive_first,
                evidence=f"/api/orders replied; source {SOURCE_ROOT}/src/billing/ledger.py "
                         f"line `{SNIPPET_LINE}`",
                status_code=200, protocol_used="websocket",
            )
        with patch("prove_agent.protocols.ws_executor.websockets.connect",
                   side_effect=ConnectionRefusedError(MSG)):
            return await execute_websocket(plan, staging_url, TargetCapabilities(), "c", "t")

    async def reflect(self, finding, attempts):
        return ReflectionResult(
            analysis=f"{finding['file_path']} raises with {TOKEN}",
            suggested_approach=f"trigger `{SNIPPET_LINE}`",
            confidence=self.confidence,
        )


async def _run_finding(strategy, **kw) -> list[str]:
    with patch("prove_agent.runner.stepped_backoff_delay_adaptive", return_value=0):
        return [e async for e in prove_finding_with_timeout(
            FINDING, strategy, STAGING, 3, AgUiEventEmitter("run-0101"), **kw,
        )]


class TestRunnerStream:
    async def test_unreachable_path(self):
        raw = await _run_finding(_EchoStrategy())
        joined = "\n".join(raw)
        assert _leaks(joined) == []
        assert "[source file]" in joined and "[source excerpt]" in joined
        results = [d for n, d in _events(raw) if n == "proof_result"]
        assert results[-1]["evidence"] == (
            "Target unreachable: WebSocket error: connection refused (ConnectionRefusedError)"
        )
        assert results[-1]["finding_id"] == "f-ledger-1"
        assert results[-1]["staging_url"] == STAGING

    async def test_high_confidence_verdict(self):
        raw = await _run_finding(_EchoStrategy(confidence=95))
        results = [d for n, d in _events(raw) if n == "proof_result"]
        assert results[-1]["evidence"].startswith("High confidence (95%)")
        assert _leaks("\n".join(raw)) == []

    async def test_timeout_synthesis(self):
        class _Slow(_EchoStrategy):
            async def reflect(self, finding, attempts):
                import asyncio
                await asyncio.sleep(5)

        raw = await _run_finding(_Slow(), timeout=0.2)
        results = [d for n, d in _events(raw) if n == "proof_result"]
        assert results[-1]["evidence"].startswith("Timed out after")
        assert _leaks("\n".join(raw)) == []


# --- 3. Agent-level error lines (an ERROR: line is stored as the audit error) ---


def _caps() -> TargetCapabilities:
    return TargetCapabilities(http=True)


def _run_prove(config_findings=None, **patches) -> list[str]:
    from prove_agent.agent import run_prove

    defaults = {
        "prove_agent.agent.validate_staging_url": MagicMock(return_value=None),
        "shared.llm.provider.get_model": MagicMock(return_value="test-model"),
        "prove_agent.agent.detect_capabilities": AsyncMock(return_value=(_caps(), "HTTP ok")),
        "prove_agent.agent.load_cached_discovery": MagicMock(return_value=None),
        "prove_agent.agent.call_discover": MagicMock(return_value=(None, "", [])),
        "prove_agent.agent.probe_api_endpoints": AsyncMock(return_value=[]),
        "prove_agent.agent._get_findings": MagicMock(return_value=config_findings or []),
    }
    defaults.update(patches)
    started = [patch(target, new=value) for target, value in defaults.items()]
    for p in started:
        p.start()
    try:
        return list(run_prove(
            run_id="run-0101", source_path=SOURCE_ROOT,
            config={"staging_url": STAGING, "types": ["cwe"], "max_iterations": 1},
        ))
    finally:
        for p in started:
            p.stop()


def _thinking(raw: list[str]) -> list[str]:
    return [d["content"] for n, d in _events(raw) if n == "thinking"]


class TestAgentErrorLines:
    @pytest.fixture(autouse=True)
    def _llm_on(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")

    def test_model_unavailable(self):
        raw = _run_prove(**{"shared.llm.provider.get_model": MagicMock(side_effect=RuntimeError(MSG))})
        errors = [t for t in _thinking(raw) if t.startswith("ERROR:")]
        assert errors and _leaks("\n".join(raw)) == []
        assert "internal error (RuntimeError)" in errors[0]

    def test_staging_unreachable(self):
        raw = _run_prove(**{"prove_agent.agent.detect_capabilities": AsyncMock(side_effect=OSError(MSG))})
        errors = [t for t in _thinking(raw) if t.startswith("ERROR:")]
        assert errors[0].startswith("ERROR: Staging URL unreachable: connection failed (OSError)")
        assert _leaks("\n".join(raw)) == []

    def test_probe_only_api_probing(self):
        site = MagicMock(api_endpoints=["/api/orders"], forms=[])
        raw = _run_prove(**{
            "prove_agent.agent.load_cached_discovery": MagicMock(return_value=site),
            "prove_agent.agent.probe_api_endpoints": AsyncMock(side_effect=OSError(MSG)),
        })
        assert "API probing skipped: connection failed (OSError)" in _thinking(raw)
        assert _leaks("\n".join(raw)) == []

    def test_discovery_and_verification_errors(self):
        async def _boom(*_a, **_kw):
            raise RuntimeError(MSG)
            yield  # pragma: no cover - makes this an async generator

        raw = _run_prove(
            config_findings=[FINDING],
            **{
                "prove_agent.agent.call_discover": MagicMock(side_effect=OSError(MSG)),
                "prove_agent.agent.prove_finding_with_timeout": _boom,
            },
        )
        texts = _thinking(raw)
        assert "Verification error: internal error (RuntimeError)" in texts
        assert _leaks("\n".join(raw)) == []

    def test_api_probing_after_verification(self):
        site = MagicMock(api_endpoints=["/api/orders"], forms=[], urls=[])
        site.summary.return_value = "site"
        raw = _run_prove(
            config_findings=[FINDING],
            **{
                "prove_agent.agent.load_cached_discovery": MagicMock(return_value=site),
                "prove_agent.agent.probe_api_endpoints": AsyncMock(side_effect=OSError(MSG)),
                "prove_agent.agent.prove_finding_with_timeout": _no_events,
            },
        )
        assert "API probing skipped: connection failed (OSError)" in _thinking(raw)
        assert _leaks("\n".join(raw)) == []


async def _no_events(*_a, **_kw):
    return
    yield  # pragma: no cover


# --- 4. Reverse direction: no repository path is crawled on the target ---


class TestNoRepoPathSentToTarget:
    def test_incremental_discovery_never_receives_a_repo_path(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        crawled: list[str] = []

        async def _record(staging_url, urls):
            crawled.extend(urls)
            return MagicMock(urls=[])

        findings = [dict(FINDING, id=f"f-{i}") for i in range(4)]
        strategy = _EchoStrategy(conclusive_first=True)
        with patch("prove_agent.agent.STRATEGY_MAP", {"cwe": lambda: strategy}):
            _run_prove(config_findings=findings, **{
                "prove_agent.agent.discover_incremental": _record,
            })
        assert crawled, "incremental discovery should still run on target paths"
        assert "/api/orders" in crawled  # target routes the model probed are kept
        assert [u for u in crawled if _leaks(u)] == []
