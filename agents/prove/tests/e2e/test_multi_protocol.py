"""E2E tests for multi-protocol probe support.

Tests WebSocket probing, JSON-RPC probing, and protocol fallback
using mock servers. These tests verify the full protocol pipeline
from detection through execution.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import pytest

from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.protocols.dispatcher import execute_plan
from prove_agent.protocols.fallback import execute_with_fallback
from prove_agent.strategies.base import (
    ExecutionResult,
    FailureReason,
    ProbeProtocol,
    ProofPlan,
)


class TestWebSocketProbe:
    """Verify WebSocket probing against a mock WS server."""

    @pytest.mark.asyncio
    async def test_ws_probe_with_echo(self):
        """WS probe sends payload and receives echo response."""
        mock_ws = AsyncMock()
        mock_ws.recv = AsyncMock(
            side_effect=["echo: test payload", asyncio.TimeoutError],
        )
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        caps = TargetCapabilities(websocket=True, primary=ProbeProtocol.WEBSOCKET)
        plan = ProofPlan(
            description="WS echo test",
            method="GET",
            url_path="/ws",
            body="test payload",
            expected_indicators=["echo"],
            protocol=ProbeProtocol.WEBSOCKET,
        )

        with patch("prove_agent.protocols.ws_executor.websockets") as mock_lib:
            mock_lib.connect.return_value = mock_ws
            result = await execute_plan(
                plan, "http://example.com", caps, "test", "WS echo test",
            )
            assert result.protocol_used == "websocket"
            assert result.conclusive is True
            assert result.reproduced is True
            mock_ws.send.assert_called_once_with("test payload")

    @pytest.mark.asyncio
    async def test_ws_probe_binary_response(self):
        """WS probe handles binary messages."""
        mock_ws = AsyncMock()
        mock_ws.recv = AsyncMock(
            side_effect=[b"binary response data", asyncio.TimeoutError],
        )
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        caps = TargetCapabilities(websocket=True, primary=ProbeProtocol.WEBSOCKET)
        plan = ProofPlan(
            description="binary test",
            method="GET",
            url_path="/ws",
            expected_indicators=["binary"],
            protocol=ProbeProtocol.WEBSOCKET,
        )

        with patch("prove_agent.protocols.ws_executor.websockets") as mock_lib:
            mock_lib.connect.return_value = mock_ws
            result = await execute_plan(
                plan, "http://example.com", caps, "test", "Binary WS test",
            )
            assert result.protocol_used == "websocket"
            assert "binary" in result.response_snippet.lower() or result.conclusive


class TestJsonRpcProbe:
    """Verify JSON-RPC probing against a mock RPC server."""

    @pytest.mark.asyncio
    async def test_jsonrpc_http_substrate_health(self):
        """JSON-RPC over HTTP returns Substrate health."""
        caps = TargetCapabilities(jsonrpc_http=True, primary=ProbeProtocol.JSONRPC)
        plan = ProofPlan(
            description="substrate health",
            method="POST",
            url_path="/",
            protocol=ProbeProtocol.JSONRPC,
            rpc_method="system_health",
            expected_indicators=["peers"],
        )

        rpc_response = json.dumps({
            "jsonrpc": "2.0",
            "result": {"peers": 5, "isSyncing": False, "shouldHavePeers": True},
            "id": 1,
        })

        with patch("prove_agent.protocols.jsonrpc_executor.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.text = rpc_response
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient.return_value = mock_client

            result = await execute_plan(
                plan, "http://node.local:9944", caps, "CWE", "substrate test",
            )
            assert result.protocol_used == "jsonrpc"
            assert result.conclusive is True

    @pytest.mark.asyncio
    async def test_jsonrpc_ws_method_enumeration(self):
        """JSON-RPC over WS returns method list."""
        caps = TargetCapabilities(jsonrpc_ws=True, primary=ProbeProtocol.JSONRPC)
        plan = ProofPlan(
            description="method enumeration",
            method="POST",
            url_path="/",
            protocol=ProbeProtocol.JSONRPC,
            rpc_method="rpc_methods",
            expected_indicators=["system_health"],
        )

        rpc_response = json.dumps({
            "jsonrpc": "2.0",
            "result": ["system_health", "system_name", "chain_getHeader"],
            "id": 1,
        })

        mock_ws = AsyncMock()
        mock_ws.recv = AsyncMock(return_value=rpc_response)
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        with patch("prove_agent.protocols.jsonrpc_executor.websockets") as mock_lib:
            mock_lib.connect.return_value = mock_ws
            result = await execute_plan(
                plan, "http://node.local:9944", caps, "CWE", "Method enum",
            )
            assert result.protocol_used == "jsonrpc"
            assert result.conclusive is True

    @pytest.mark.asyncio
    async def test_jsonrpc_error_response(self):
        """JSON-RPC error response is properly handled."""
        caps = TargetCapabilities(jsonrpc_http=True, primary=ProbeProtocol.JSONRPC)
        plan = ProofPlan(
            description="bad method",
            method="POST",
            url_path="/",
            protocol=ProbeProtocol.JSONRPC,
            rpc_method="nonexistent_method",
            expected_indicators=[],
        )

        rpc_response = json.dumps({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": 1,
        })

        with patch("prove_agent.protocols.jsonrpc_executor.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.text = rpc_response
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.AsyncClient.return_value = mock_client

            # Mock llm_json_call for the LLM analysis phase
            with patch("prove_agent.protocols.jsonrpc_executor.llm_json_call") as mock_llm:
                mock_llm.return_value = {
                    "conclusive": False,
                    "reproduced": False,
                    "evidence": "Method not found — expected",
                }
                result = await execute_plan(
                    plan, "http://node.local:9944", caps, "CWE", "bad method",
                )
                assert result.protocol_used == "jsonrpc"
                assert result.conclusive is False


class TestProtocolFallback:
    """Test HTTP→WS fallback when HTTP fails."""

    @pytest.mark.asyncio
    async def test_http_to_ws_fallback(self):
        """HTTP fails with CONNECTION_ERROR, falls back to WS which succeeds."""
        caps = TargetCapabilities(
            http=True, websocket=True, jsonrpc_ws=True,
            primary=ProbeProtocol.HTTP,
        )
        plan = ProofPlan(
            description="test probe",
            method="GET",
            url_path="/health",
        )

        call_count = 0

        async def mock_exec(plan, url, caps, cat, title):
            nonlocal call_count
            call_count += 1
            if plan.protocol == ProbeProtocol.HTTP or call_count == 1:
                return ExecutionResult(
                    conclusive=False,
                    evidence="HTTP connection refused",
                    failure_reason=FailureReason.CONNECTION_ERROR,
                    protocol_used="http",
                )
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence="Verified via JSON-RPC/WS",
                protocol_used="jsonrpc",
            )

        with patch("prove_agent.protocols.fallback.execute_plan", side_effect=mock_exec):
            result = await execute_with_fallback(
                plan, "http://node.local:9944", caps, "test", "test",
            )
            assert result.conclusive is True
            assert result.protocol_used == "jsonrpc"
            assert call_count >= 2

    @pytest.mark.asyncio
    async def test_no_fallback_on_timeout(self):
        """Timeout errors do NOT trigger fallback."""
        caps = TargetCapabilities(
            http=True, websocket=True,
            primary=ProbeProtocol.HTTP,
        )
        plan = ProofPlan(description="test", method="GET", url_path="/")

        with patch("prove_agent.protocols.fallback.execute_plan") as mock_exec:
            mock_exec.return_value = ExecutionResult(
                conclusive=False,
                evidence="timed out",
                failure_reason=FailureReason.TIMEOUT,
                protocol_used="http",
            )
            result = await execute_with_fallback(
                plan, "http://example.com", caps, "test", "test",
            )
            assert result.failure_reason == FailureReason.TIMEOUT
            assert mock_exec.call_count == 1

    @pytest.mark.asyncio
    async def test_fallback_on_protocol_error(self):
        """PROTOCOL_ERROR triggers fallback."""
        caps = TargetCapabilities(
            http=True, websocket=True,
            primary=ProbeProtocol.WEBSOCKET,
        )
        plan = ProofPlan(
            description="test", method="GET", url_path="/",
            protocol=ProbeProtocol.WEBSOCKET,
        )

        call_count = 0

        async def mock_exec(plan, url, caps, cat, title):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ExecutionResult(
                    conclusive=False,
                    evidence="handshake failed",
                    failure_reason=FailureReason.PROTOCOL_ERROR,
                    protocol_used="websocket",
                )
            return ExecutionResult(
                conclusive=False,
                evidence="HTTP 200 OK",
                status_code=200,
                protocol_used="http",
            )

        with patch("prove_agent.protocols.fallback.execute_plan", side_effect=mock_exec):
            result = await execute_with_fallback(
                plan, "http://example.com", caps, "test", "test",
            )
            assert result.protocol_used == "http"
            assert call_count == 2
