"""JSON-RPC protocol executor for prove agent verification probes.

Supports both HTTP and WebSocket transports, auto-selecting based on
target capabilities. Includes a Substrate/Polkadot method catalog.
"""

import asyncio
import json
import logging

import httpx
import websockets

from prove_agent.llm_helper import llm_json_call
from prove_agent.protocols.detection import TargetCapabilities, to_ws_url
from prove_agent.strategies.base import (
    ExecutionResult,
    FailureReason,
    ProbeProtocol,
    ProofPlan,
)

logger = logging.getLogger(__name__)

_RPC_TIMEOUT = 10.0

# Common Substrate/Polkadot RPC methods for blockchain targets
SUBSTRATE_METHODS: dict[str, str] = {
    "system_health": "Node health status",
    "system_name": "Node implementation name",
    "system_version": "Node version",
    "system_chain": "Chain name",
    "system_properties": "Chain properties (SS58 prefix, token decimals, etc.)",
    "system_peers": "Connected peer count and info",
    "system_nodeRoles": "Node roles (Full, Authority, Light)",
    "chain_getHeader": "Latest block header",
    "chain_getBlockHash": "Block hash by number",
    "chain_getFinalizedHead": "Finalized block hash",
    "state_getRuntimeVersion": "Runtime version info",
    "state_getMetadata": "Runtime metadata (type info, pallets)",
    "rpc_methods": "List all available RPC methods",
}

_ANALYZE_PROMPT = """Did this JSON-RPC response confirm the vulnerability?

Finding: {title} ({category})
RPC method: {method}
Response: {response}
Expected indicators: {expected_indicators}

Reply with JSON only:
{{"conclusive":true,"reproduced":true,"evidence":"explanation"}}"""


async def execute_jsonrpc(
    plan: ProofPlan,
    staging_url: str,
    capabilities: TargetCapabilities,
    finding_category: str,
    finding_title: str,
) -> ExecutionResult:
    """Execute a JSON-RPC probe, auto-selecting transport."""
    rpc_method = plan.rpc_method or "rpc_methods"
    rpc_params = plan.rpc_params if plan.rpc_params is not None else []

    envelope = {
        "jsonrpc": "2.0",
        "method": rpc_method,
        "params": rpc_params,
        "id": 1,
    }

    # Pick transport: prefer WS for RPC if available
    if capabilities.jsonrpc_ws:
        result = await _jsonrpc_over_websocket(envelope, staging_url, plan)
    elif capabilities.jsonrpc_http:
        result = await _jsonrpc_over_http(envelope, staging_url, plan)
    else:
        # No detected RPC support — try HTTP as fallback
        result = await _jsonrpc_over_http(envelope, staging_url, plan)

    if result.failure_reason != FailureReason.NONE:
        return result

    # Analyze the RPC response
    return await _analyze_rpc_response(
        result, rpc_method, finding_category, finding_title, plan,
    )


async def _jsonrpc_over_http(
    envelope: dict,
    staging_url: str,
    plan: ProofPlan,
) -> ExecutionResult:
    """Send JSON-RPC over HTTP POST."""
    url = staging_url.rstrip("/") + (plan.url_path if plan.url_path != "/" else "")
    try:
        async with httpx.AsyncClient(timeout=_RPC_TIMEOUT) as client:
            headers = {"Content-Type": "application/json"}
            for k, v in plan.headers.items():
                headers[k] = v
            resp = await client.post(url, json=envelope, headers=headers)
            snippet = resp.text[:500]
            return ExecutionResult(
                conclusive=False,  # analysis happens in caller
                status_code=resp.status_code,
                response_snippet=snippet,
                response_headers=dict(resp.headers),
                protocol_used=ProbeProtocol.JSONRPC.value,
            )
    except httpx.TimeoutException:
        return ExecutionResult(
            conclusive=False, evidence="JSON-RPC/HTTP timed out",
            failure_reason=FailureReason.TIMEOUT,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )
    except httpx.ConnectError as exc:
        return ExecutionResult(
            conclusive=False, evidence=f"JSON-RPC/HTTP connection failed: {exc}",
            failure_reason=FailureReason.CONNECTION_ERROR,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )


async def _jsonrpc_over_websocket(
    envelope: dict,
    staging_url: str,
    plan: ProofPlan,
) -> ExecutionResult:
    """Send JSON-RPC over WebSocket."""
    ws_url = to_ws_url(staging_url, plan.url_path if plan.url_path != "/" else "")
    try:
        async with websockets.connect(
            ws_url, open_timeout=_RPC_TIMEOUT, close_timeout=2,
        ) as ws:
            await ws.send(json.dumps(envelope))
            raw = await asyncio.wait_for(ws.recv(), timeout=_RPC_TIMEOUT)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            snippet = raw[:500]
            return ExecutionResult(
                conclusive=False,
                response_snippet=snippet,
                protocol_used=ProbeProtocol.JSONRPC.value,
            )
    except asyncio.TimeoutError:
        return ExecutionResult(
            conclusive=False, evidence="JSON-RPC/WS timed out",
            failure_reason=FailureReason.TIMEOUT,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )
    except Exception as exc:
        exc_str = str(exc).lower()
        if any(kw in exc_str for kw in ("refused", "connect", "dns")):
            reason = FailureReason.CONNECTION_ERROR
        elif "protocol" in exc_str or "handshake" in exc_str:
            reason = FailureReason.PROTOCOL_ERROR
        else:
            reason = FailureReason.CONNECTION_ERROR
        return ExecutionResult(
            conclusive=False, evidence=f"JSON-RPC/WS error: {exc}",
            failure_reason=reason,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )


async def _analyze_rpc_response(
    result: ExecutionResult,
    rpc_method: str,
    finding_category: str,
    finding_title: str,
    plan: ProofPlan,
) -> ExecutionResult:
    """Analyze a JSON-RPC response for vulnerability indicators."""
    snippet = result.response_snippet

    # Phase 1: Rule-based analysis
    rule = _rule_analyze_rpc(snippet, rpc_method, finding_category, finding_title, plan)
    if rule:
        rule.status_code = result.status_code
        rule.response_headers = result.response_headers
        return rule

    # Phase 2: LLM analysis
    try:
        llm_result = await llm_json_call(_ANALYZE_PROMPT.format(
            title=finding_title,
            category=finding_category,
            method=rpc_method,
            response=snippet,
            expected_indicators=json.dumps(plan.expected_indicators),
        ))
        return ExecutionResult(
            conclusive=llm_result.get("conclusive", False),
            reproduced=llm_result.get("reproduced", False),
            evidence=llm_result.get("evidence", f"RPC {rpc_method}"),
            status_code=result.status_code,
            response_snippet=snippet,
            response_headers=result.response_headers,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )
    except Exception:
        return ExecutionResult(
            conclusive=False,
            evidence=f"RPC {rpc_method}: response received, LLM analysis failed",
            status_code=result.status_code,
            response_snippet=snippet,
            response_headers=result.response_headers,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )


def _rule_analyze_rpc(
    snippet: str,
    rpc_method: str,
    finding_category: str,
    finding_title: str,
    plan: ProofPlan,
) -> ExecutionResult | None:
    """Rule-based analysis of JSON-RPC responses."""
    lower = snippet.lower()

    # Check expected indicators
    matched = [ind for ind in plan.expected_indicators if ind.lower() in lower]
    if matched:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"RPC {rpc_method} matched indicators: {', '.join(matched)}",
            response_snippet=snippet,
            protocol_used=ProbeProtocol.JSONRPC.value,
        )

    # Parse JSON-RPC response
    try:
        data = json.loads(snippet)
    except (json.JSONDecodeError, ValueError):
        return None

    # rpc_methods response → info disclosure (method enumeration)
    if rpc_method == "rpc_methods" and "result" in data:
        methods = data["result"]
        if isinstance(methods, list) and len(methods) > 0:
            lower_title = finding_title.lower()
            if any(kw in lower_title for kw in ("info", "disclos", "expos", "enum")):
                return ExecutionResult(
                    conclusive=True,
                    reproduced=True,
                    evidence=f"RPC method enumeration: {len(methods)} methods exposed",
                    response_snippet=snippet,
                    protocol_used=ProbeProtocol.JSONRPC.value,
                )

    # Error with detailed message → error disclosure
    if "error" in data:
        err = data["error"]
        if isinstance(err, dict):
            msg = err.get("message", "")
            if len(msg) > 50:
                lower_title = finding_title.lower()
                if any(kw in lower_title for kw in ("error", "info", "disclos", "stack")):
                    return ExecutionResult(
                        conclusive=True,
                        reproduced=True,
                        evidence=f"RPC error disclosure: {msg[:200]}",
                        response_snippet=snippet,
                        protocol_used=ProbeProtocol.JSONRPC.value,
                    )

    return None
