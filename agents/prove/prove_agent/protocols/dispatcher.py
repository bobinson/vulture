"""Protocol dispatcher — routes probes to the correct executor."""

import logging

from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.strategies.base import ExecutionResult, ProbeProtocol, ProofPlan

logger = logging.getLogger(__name__)


async def execute_plan(
    plan: ProofPlan,
    staging_url: str,
    capabilities: TargetCapabilities,
    finding_category: str,
    finding_title: str,
) -> ExecutionResult:
    """Dispatch a proof plan to the correct protocol executor.

    Resolution order:
      1. plan.protocol if explicitly set and target supports it
      2. plan.rpc_method hint → JSONRPC
      3. capabilities.primary
    """
    protocol = _resolve_protocol(plan, capabilities)

    if protocol == ProbeProtocol.GRPC:
        from prove_agent.protocols.grpc_executor import execute_grpc
        result = await execute_grpc(
            plan, staging_url, capabilities, finding_category, finding_title,
        )
    elif protocol == ProbeProtocol.JSONRPC:
        from prove_agent.protocols.jsonrpc_executor import execute_jsonrpc
        result = await execute_jsonrpc(
            plan, staging_url, capabilities, finding_category, finding_title,
        )
    elif protocol == ProbeProtocol.WEBSOCKET:
        from prove_agent.protocols.ws_executor import execute_websocket
        result = await execute_websocket(
            plan, staging_url, capabilities, finding_category, finding_title,
        )
    else:
        from prove_agent.strategies.shared import execute_and_analyze
        result = await execute_and_analyze(
            plan, staging_url, finding_category, finding_title,
        )
        result.protocol_used = ProbeProtocol.HTTP.value

    if not result.protocol_used:
        result.protocol_used = protocol.value
    return result


def _resolve_protocol(
    plan: ProofPlan,
    capabilities: TargetCapabilities,
) -> ProbeProtocol:
    """Determine which protocol to use for a plan."""
    # Explicit protocol on plan takes precedence if target supports it
    if plan.protocol != ProbeProtocol.HTTP:
        if _supports(capabilities, plan.protocol):
            return plan.protocol

    # RPC method hint → use JSON-RPC
    if plan.rpc_method and (capabilities.jsonrpc_ws or capabilities.jsonrpc_http):
        return ProbeProtocol.JSONRPC

    # Fall back to detected primary
    return capabilities.primary


def _supports(caps: TargetCapabilities, protocol: ProbeProtocol) -> bool:
    """Check if target supports a given protocol."""
    if protocol == ProbeProtocol.HTTP:
        return caps.http
    if protocol == ProbeProtocol.WEBSOCKET:
        return caps.websocket
    if protocol == ProbeProtocol.JSONRPC:
        return caps.jsonrpc_ws or caps.jsonrpc_http
    if protocol == ProbeProtocol.GRPC:
        return caps.grpc
    return False
