"""Tests for multi-protocol support: detection, dispatcher, executors, fallback."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prove_agent.protocols.detection import (
    TargetCapabilities,
    detect_capabilities,
    is_ws_rpc_target,
    to_ws_url,
)
from prove_agent.protocols.dispatcher import _resolve_protocol, execute_plan
from prove_agent.protocols.fallback import _build_fallback_chain, execute_with_fallback
from prove_agent.protocols.jsonrpc_executor import (
    SUBSTRATE_METHODS,
    _rule_analyze_rpc,
    execute_jsonrpc,
)
from prove_agent.protocols.ws_executor import (
    _classify_ws_failure,
    execute_websocket,
)
from prove_agent.strategies.base import (
    AttemptRecord,
    ExecutionResult,
    FailureReason,
    ProbeProtocol,
    ProofPlan,
)


# ---------- ProbeProtocol enum tests ----------


class TestProbeProtocol:
    def test_enum_values(self):
        assert ProbeProtocol.HTTP.value == "http"
        assert ProbeProtocol.WEBSOCKET.value == "websocket"
        assert ProbeProtocol.JSONRPC.value == "jsonrpc"

    def test_proof_plan_default_protocol(self):
        plan = ProofPlan(description="test", method="GET", url_path="/")
        assert plan.protocol == ProbeProtocol.HTTP
        assert plan.rpc_method == ""
        assert plan.rpc_params is None

    def test_proof_plan_jsonrpc_fields(self):
        plan = ProofPlan(
            description="test rpc",
            method="POST",
            url_path="/",
            protocol=ProbeProtocol.JSONRPC,
            rpc_method="system_health",
            rpc_params=[],
        )
        assert plan.protocol == ProbeProtocol.JSONRPC
        assert plan.rpc_method == "system_health"
        assert plan.rpc_params == []

    def test_protocol_error_in_failure_reason(self):
        assert FailureReason.PROTOCOL_ERROR.value == "protocol_error"


# ---------- AttemptRecord protocol field ----------


class TestAttemptRecordProtocol:
    def test_default_protocol(self):
        record = AttemptRecord(
            iteration=1, method="GET", url_path="/",
            status_code=200, response_snippet="", response_headers={},
            evidence="", conclusive=False, reproduced=False,
            plan_description="test",
        )
        assert record.protocol == "http"

    def test_custom_protocol(self):
        record = AttemptRecord(
            iteration=1, method="POST", url_path="/",
            status_code=200, response_snippet="", response_headers={},
            evidence="", conclusive=False, reproduced=False,
            plan_description="test",
            protocol="jsonrpc",
        )
        assert record.protocol == "jsonrpc"

    def test_execution_result_protocol_used(self):
        result = ExecutionResult(conclusive=False, protocol_used="websocket")
        assert result.protocol_used == "websocket"


# ---------- URL conversion tests ----------


class TestToWsUrl:
    def test_http_to_ws(self):
        assert to_ws_url("http://example.com") == "ws://example.com"

    def test_https_to_wss(self):
        assert to_ws_url("https://example.com") == "wss://example.com"

    def test_with_port(self):
        assert to_ws_url("http://example.com:9944") == "ws://example.com:9944"

    def test_with_path(self):
        assert to_ws_url("http://example.com:8080", "/ws") == "ws://example.com:8080/ws"

    def test_https_with_port_and_path(self):
        assert to_ws_url("https://example.com:443", "/api/ws") == "wss://example.com:443/api/ws"


# ---------- Port heuristic tests ----------


class TestIsWsRpcTarget:
    def test_substrate_port_9944(self):
        assert is_ws_rpc_target("http://node.example.com:9944") is True

    def test_substrate_port_9933(self):
        assert is_ws_rpc_target("http://node.example.com:9933") is True

    def test_ethereum_port_8546(self):
        assert is_ws_rpc_target("http://geth.local:8546") is True

    def test_ethereum_port_8545(self):
        assert is_ws_rpc_target("http://geth.local:8545") is True

    def test_tendermint_port_26657(self):
        assert is_ws_rpc_target("http://cosmos.local:26657") is True

    def test_standard_http_port(self):
        assert is_ws_rpc_target("http://example.com:8080") is False

    def test_no_port(self):
        assert is_ws_rpc_target("http://example.com") is False


# ---------- Validate staging URL (ws/wss) ----------


class TestValidateStagingUrl:
    def test_ws_accepted(self):
        from prove_agent.runner import validate_staging_url
        assert validate_staging_url("ws://example.com:9944") is None

    def test_wss_accepted(self):
        from prove_agent.runner import validate_staging_url
        assert validate_staging_url("wss://example.com:9944") is None

    def test_http_still_accepted(self):
        from prove_agent.runner import validate_staging_url
        assert validate_staging_url("http://example.com") is None

    def test_ftp_rejected(self):
        from prove_agent.runner import validate_staging_url
        result = validate_staging_url("ftp://example.com")
        assert result is not None
        assert "Invalid scheme" in result


# ---------- Protocol detection tests ----------


class TestProtocolDetection:
    @pytest.mark.asyncio
    async def test_http_only_target(self):
        with patch("prove_agent.protocols.detection._probe_http", return_value=True), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(False, [])):
            caps, summary = await detect_capabilities("http://example.com")
            assert caps.http is True
            assert caps.websocket is False
            assert caps.jsonrpc_http is False
            assert caps.jsonrpc_ws is False
            assert caps.primary == ProbeProtocol.HTTP
            assert "HTTP" in summary

    @pytest.mark.asyncio
    async def test_jsonrpc_ws_target(self):
        with patch("prove_agent.protocols.detection._probe_http", return_value=True), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=True), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(True, ["system_health"])):
            caps, summary = await detect_capabilities("http://node.local:9944")
            assert caps.websocket is True
            assert caps.jsonrpc_ws is True
            assert caps.primary == ProbeProtocol.JSONRPC
            assert caps.rpc_methods == ["system_health"]

    @pytest.mark.asyncio
    async def test_jsonrpc_http_target(self):
        with patch("prove_agent.protocols.detection._probe_http", return_value=True), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(True, ["rpc_methods"])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(False, [])):
            caps, summary = await detect_capabilities("http://rpc.local")
            assert caps.jsonrpc_http is True
            assert caps.primary == ProbeProtocol.JSONRPC

    @pytest.mark.asyncio
    async def test_ws_only_target(self):
        with patch("prove_agent.protocols.detection._probe_http", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=True), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(False, [])):
            caps, summary = await detect_capabilities("http://ws.local")
            assert caps.websocket is True
            assert caps.primary == ProbeProtocol.WEBSOCKET

    @pytest.mark.asyncio
    async def test_rpc_port_heuristic_fallback(self):
        """When WS probe fails but port heuristic matches, try WS JSON-RPC directly."""
        with patch("prove_agent.protocols.detection._probe_http", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(True, ["system_health"])):
            caps, summary = await detect_capabilities("http://node.local:9944")
            assert caps.jsonrpc_ws is True
            assert caps.websocket is True
            assert caps.primary == ProbeProtocol.JSONRPC

    @pytest.mark.asyncio
    async def test_no_protocols_detected(self):
        with patch("prove_agent.protocols.detection._probe_http", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(False, [])):
            caps, summary = await detect_capabilities("http://dead.host")
            assert caps.primary == ProbeProtocol.HTTP
            assert "none" in summary

    @pytest.mark.asyncio
    async def test_exception_from_gather_treated_as_false(self):
        """When a probe raises BaseException (e.g. CancelledError), treat as not detected."""
        with patch("prove_agent.protocols.detection._probe_http", side_effect=asyncio.CancelledError()), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(False, [])):
            caps, summary = await detect_capabilities("http://example.com")
            assert caps.http is False
            assert "none" in summary

    @pytest.mark.asyncio
    async def test_sse_only_still_detected(self):
        """Server supporting only SSE should still be detected as having protocols."""
        with patch("prove_agent.protocols.detection._probe_http", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_http", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_websocket", return_value=False), \
             patch("prove_agent.protocols.detection._probe_jsonrpc_ws", return_value=(False, [])), \
             patch("prove_agent.protocols.detection._probe_grpc", return_value=False), \
             patch("prove_agent.protocols.detection._probe_sse", return_value=True), \
             patch("prove_agent.protocols.detection._probe_mqtt_ws", return_value=False):
            caps, summary = await detect_capabilities("http://sse.local")
            assert caps.sse is True
            assert "SSE" in summary


# ---------- Dispatcher tests ----------


class TestDispatcher:
    def test_resolve_explicit_protocol(self):
        caps = TargetCapabilities(http=True, websocket=True)
        plan = ProofPlan(
            description="ws test", method="GET", url_path="/ws",
            protocol=ProbeProtocol.WEBSOCKET,
        )
        assert _resolve_protocol(plan, caps) == ProbeProtocol.WEBSOCKET

    def test_resolve_rpc_method_hint(self):
        caps = TargetCapabilities(http=True, jsonrpc_http=True)
        plan = ProofPlan(
            description="rpc test", method="POST", url_path="/",
            rpc_method="system_health",
        )
        assert _resolve_protocol(plan, caps) == ProbeProtocol.JSONRPC

    def test_resolve_falls_to_primary(self):
        caps = TargetCapabilities(http=True, primary=ProbeProtocol.HTTP)
        plan = ProofPlan(description="test", method="GET", url_path="/")
        assert _resolve_protocol(plan, caps) == ProbeProtocol.HTTP

    def test_resolve_unsupported_explicit_falls_to_primary(self):
        caps = TargetCapabilities(http=True, websocket=False, primary=ProbeProtocol.HTTP)
        plan = ProofPlan(
            description="ws test", method="GET", url_path="/",
            protocol=ProbeProtocol.WEBSOCKET,
        )
        assert _resolve_protocol(plan, caps) == ProbeProtocol.HTTP

    @pytest.mark.asyncio
    async def test_dispatch_to_http(self):
        caps = TargetCapabilities(http=True, primary=ProbeProtocol.HTTP)
        plan = ProofPlan(description="test", method="GET", url_path="/health")
        with patch("prove_agent.strategies.shared.execute_and_analyze") as mock_exec:
            mock_exec.return_value = ExecutionResult(
                conclusive=False, status_code=200, protocol_used="",
            )
            result = await execute_plan(plan, "http://example.com", caps, "test", "test")
            assert result.protocol_used == "http"
            mock_exec.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_to_jsonrpc(self):
        caps = TargetCapabilities(
            http=True, jsonrpc_http=True, primary=ProbeProtocol.JSONRPC,
        )
        plan = ProofPlan(
            description="rpc test", method="POST", url_path="/",
            rpc_method="system_health",
        )
        with patch("prove_agent.protocols.jsonrpc_executor.execute_jsonrpc") as mock_exec:
            mock_exec.return_value = ExecutionResult(
                conclusive=False, protocol_used="jsonrpc",
            )
            result = await execute_plan(plan, "http://rpc.local", caps, "test", "test")
            assert result.protocol_used == "jsonrpc"

    @pytest.mark.asyncio
    async def test_dispatch_to_websocket(self):
        caps = TargetCapabilities(
            websocket=True, primary=ProbeProtocol.WEBSOCKET,
        )
        plan = ProofPlan(
            description="ws test", method="GET", url_path="/ws",
            protocol=ProbeProtocol.WEBSOCKET,
        )
        with patch("prove_agent.protocols.ws_executor.execute_websocket") as mock_exec:
            mock_exec.return_value = ExecutionResult(
                conclusive=False, protocol_used="websocket",
            )
            result = await execute_plan(plan, "http://ws.local", caps, "test", "test")
            assert result.protocol_used == "websocket"


# ---------- WebSocket executor tests ----------


class TestExecuteWebSocket:
    @pytest.mark.asyncio
    async def test_ws_success_with_indicator_match(self):
        mock_ws = AsyncMock()
        mock_ws.recv = AsyncMock(
            side_effect=[json.dumps({"error": "test_indicator"}), asyncio.TimeoutError],
        )
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        caps = TargetCapabilities(websocket=True)
        plan = ProofPlan(
            description="test", method="GET", url_path="/ws",
            body="hello", expected_indicators=["test_indicator"],
            protocol=ProbeProtocol.WEBSOCKET,
        )

        with patch("prove_agent.protocols.ws_executor.websockets") as mock_lib:
            mock_lib.connect.return_value = mock_ws
            result = await execute_websocket(plan, "http://example.com", caps, "test", "test")
            assert result.protocol_used == "websocket"
            assert result.conclusive is True
            assert result.reproduced is True

    @pytest.mark.asyncio
    async def test_ws_connection_refused(self):
        caps = TargetCapabilities(websocket=True)
        plan = ProofPlan(
            description="test", method="GET", url_path="/ws",
            protocol=ProbeProtocol.WEBSOCKET,
        )
        with patch("prove_agent.protocols.ws_executor.websockets") as mock_lib:
            mock_lib.connect.side_effect = ConnectionRefusedError("refused")
            result = await execute_websocket(plan, "http://example.com", caps, "test", "test")
            assert result.failure_reason == FailureReason.CONNECTION_ERROR

    @pytest.mark.asyncio
    async def test_ws_no_messages(self):
        mock_ws = AsyncMock()
        mock_ws.recv = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        caps = TargetCapabilities(websocket=True)
        plan = ProofPlan(
            description="test", method="GET", url_path="/ws",
            protocol=ProbeProtocol.WEBSOCKET,
        )
        with patch("prove_agent.protocols.ws_executor.websockets") as mock_lib:
            mock_lib.connect.return_value = mock_ws
            result = await execute_websocket(plan, "http://example.com", caps, "test", "test")
            assert result.conclusive is False
            assert "no messages" in result.evidence


# ---------- JSON-RPC executor tests ----------


class TestExecuteJsonRpc:
    @pytest.mark.asyncio
    async def test_jsonrpc_http_success(self):
        caps = TargetCapabilities(jsonrpc_http=True, primary=ProbeProtocol.JSONRPC)
        plan = ProofPlan(
            description="rpc test", method="POST", url_path="/",
            protocol=ProbeProtocol.JSONRPC,
            rpc_method="system_health",
            expected_indicators=["isSyncing"],
        )
        rpc_response = json.dumps({
            "jsonrpc": "2.0",
            "result": {"isSyncing": False, "peers": 5},
            "id": 1,
        })
        with patch("prove_agent.protocols.jsonrpc_executor.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.text = rpc_response
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await execute_jsonrpc(plan, "http://node.local:9944", caps, "test", "test")
            assert result.protocol_used == "jsonrpc"
            # Should match indicator
            assert result.conclusive is True

    @pytest.mark.asyncio
    async def test_jsonrpc_ws_success(self):
        caps = TargetCapabilities(jsonrpc_ws=True, primary=ProbeProtocol.JSONRPC)
        plan = ProofPlan(
            description="rpc test", method="POST", url_path="/",
            protocol=ProbeProtocol.JSONRPC,
            rpc_method="rpc_methods",
            expected_indicators=["system_health"],
        )
        rpc_response = json.dumps({
            "jsonrpc": "2.0",
            "result": ["system_health", "system_name"],
            "id": 1,
        })

        mock_ws = AsyncMock()
        mock_ws.recv = AsyncMock(return_value=rpc_response)
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        with patch("prove_agent.protocols.jsonrpc_executor.websockets") as mock_lib:
            mock_lib.connect.return_value = mock_ws
            result = await execute_jsonrpc(plan, "http://node.local:9944", caps, "test", "test")
            assert result.protocol_used == "jsonrpc"
            assert result.conclusive is True

    def test_substrate_methods_catalog(self):
        assert "system_health" in SUBSTRATE_METHODS
        assert "chain_getHeader" in SUBSTRATE_METHODS
        assert "rpc_methods" in SUBSTRATE_METHODS


class TestRuleAnalyzeRpc:
    def test_indicator_match(self):
        plan = ProofPlan(
            description="test", method="POST", url_path="/",
            expected_indicators=["version"],
        )
        snippet = '{"jsonrpc":"2.0","result":{"version":"1.0"},"id":1}'
        result = _rule_analyze_rpc(snippet, "system_version", "test", "test", plan)
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is True

    def test_method_enumeration_info_disclosure(self):
        plan = ProofPlan(
            description="test", method="POST", url_path="/",
            expected_indicators=[],
        )
        snippet = json.dumps({
            "jsonrpc": "2.0",
            "result": ["system_health", "system_name", "chain_getHeader"],
            "id": 1,
        })
        result = _rule_analyze_rpc(
            snippet, "rpc_methods", "test", "Information Disclosure via RPC", plan,
        )
        assert result is not None
        assert result.conclusive is True

    def test_error_disclosure(self):
        plan = ProofPlan(
            description="test", method="POST", url_path="/",
            expected_indicators=[],
        )
        snippet = json.dumps({
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": "Method not found: detailed stack trace at line 42 in module.rs which is very long error message blah blah",
            },
            "id": 1,
        })
        result = _rule_analyze_rpc(
            snippet, "invalid_method", "test", "Error Information Disclosure", plan,
        )
        assert result is not None
        assert result.conclusive is True

    def test_no_match_returns_none(self):
        plan = ProofPlan(
            description="test", method="POST", url_path="/",
            expected_indicators=["nope"],
        )
        snippet = '{"jsonrpc":"2.0","result":null,"id":1}'
        result = _rule_analyze_rpc(snippet, "test", "test", "test", plan)
        assert result is None


# ---------- Fallback tests ----------


class TestFallback:
    def test_build_fallback_chain(self):
        caps = TargetCapabilities(http=True, websocket=True, jsonrpc_ws=True)
        chain = _build_fallback_chain(caps, "http")
        assert ProbeProtocol.HTTP not in chain
        assert ProbeProtocol.JSONRPC in chain
        assert ProbeProtocol.WEBSOCKET in chain

    def test_build_fallback_chain_no_alternatives(self):
        caps = TargetCapabilities(http=True)
        chain = _build_fallback_chain(caps, "http")
        assert chain == []

    @pytest.mark.asyncio
    async def test_no_fallback_on_success(self):
        caps = TargetCapabilities(http=True, websocket=True, primary=ProbeProtocol.HTTP)
        plan = ProofPlan(description="test", method="GET", url_path="/")

        with patch("prove_agent.protocols.fallback.execute_plan") as mock_exec:
            mock_exec.return_value = ExecutionResult(
                conclusive=True, reproduced=True, evidence="found",
                protocol_used="http",
            )
            result = await execute_with_fallback(
                plan, "http://example.com", caps, "test", "test",
            )
            assert result.conclusive is True
            assert mock_exec.call_count == 1  # No fallback attempted

    @pytest.mark.asyncio
    async def test_fallback_on_connection_error(self):
        caps = TargetCapabilities(
            http=True, websocket=True, jsonrpc_ws=True,
            primary=ProbeProtocol.HTTP,
        )
        plan = ProofPlan(description="test", method="GET", url_path="/")

        call_count = 0

        async def mock_exec(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ExecutionResult(
                    conclusive=False, evidence="connection refused",
                    failure_reason=FailureReason.CONNECTION_ERROR,
                    protocol_used="http",
                )
            return ExecutionResult(
                conclusive=True, reproduced=True, evidence="found via ws",
                protocol_used="jsonrpc",
            )

        with patch("prove_agent.protocols.fallback.execute_plan", side_effect=mock_exec):
            result = await execute_with_fallback(
                plan, "http://example.com", caps, "test", "test",
            )
            assert result.conclusive is True
            assert result.protocol_used == "jsonrpc"
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_no_fallback_on_auth_error(self):
        caps = TargetCapabilities(http=True, websocket=True, primary=ProbeProtocol.HTTP)
        plan = ProofPlan(description="test", method="GET", url_path="/")

        with patch("prove_agent.protocols.fallback.execute_plan") as mock_exec:
            mock_exec.return_value = ExecutionResult(
                conclusive=False, evidence="401 unauthorized",
                failure_reason=FailureReason.AUTH_REQUIRED,
                protocol_used="http",
            )
            result = await execute_with_fallback(
                plan, "http://example.com", caps, "test", "test",
            )
            assert result.failure_reason == FailureReason.AUTH_REQUIRED
            assert mock_exec.call_count == 1  # No fallback


# ---------- WS failure classification tests ----------


class TestClassifyWsFailure:
    def test_timeout(self):
        exc = TimeoutError("connection timed out")
        assert _classify_ws_failure(exc) == FailureReason.TIMEOUT

    def test_connection_refused(self):
        exc = ConnectionRefusedError("connection refused")
        assert _classify_ws_failure(exc) == FailureReason.CONNECTION_ERROR

    def test_protocol_error(self):
        exc = Exception("invalid handshake: protocol mismatch")
        assert _classify_ws_failure(exc) == FailureReason.PROTOCOL_ERROR

    def test_generic_error(self):
        exc = Exception("some unknown error")
        assert _classify_ws_failure(exc) == FailureReason.CONNECTION_ERROR
