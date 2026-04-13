"""Protocol fallback — retry with alternative protocol on transport failures."""

import logging

from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.protocols.dispatcher import execute_plan
from prove_agent.strategies.base import (
    ExecutionResult,
    FailureReason,
    ProbeProtocol,
    ProofPlan,
)

logger = logging.getLogger(__name__)

# Only fall back on transport-level failures, NOT on application errors
_FALLBACK_REASONS = frozenset({
    FailureReason.CONNECTION_ERROR,
    FailureReason.PROTOCOL_ERROR,
})


async def execute_with_fallback(
    plan: ProofPlan,
    staging_url: str,
    capabilities: TargetCapabilities,
    finding_category: str,
    finding_title: str,
) -> ExecutionResult:
    """Execute a plan with automatic protocol fallback on transport errors.

    Tries the primary protocol first. On CONNECTION_ERROR or PROTOCOL_ERROR,
    falls back to the next supported protocol. Does NOT fall back on
    auth/rate-limit/timeout/server errors (target responded on that protocol).
    """
    result = await execute_plan(
        plan, staging_url, capabilities, finding_category, finding_title,
    )

    if result.failure_reason not in _FALLBACK_REASONS:
        return result

    # Build fallback chain: all supported protocols except the one that failed
    failed_proto = result.protocol_used
    chain = _build_fallback_chain(capabilities, failed_proto)

    for proto in chain:
        logger.info(
            "Protocol fallback: %s failed, trying %s",
            failed_proto, proto.value,
        )
        fallback_plan = ProofPlan(
            description=plan.description,
            method=plan.method,
            url_path=plan.url_path,
            headers=plan.headers,
            body=plan.body,
            expected_indicators=plan.expected_indicators,
            is_multipart=plan.is_multipart,
            filename=plan.filename,
            protocol=proto,
            rpc_method=plan.rpc_method,
            rpc_params=plan.rpc_params,
        )
        fb_result = await execute_plan(
            fallback_plan, staging_url, capabilities,
            finding_category, finding_title,
        )
        if fb_result.failure_reason not in _FALLBACK_REASONS:
            # Fallback succeeded (or got an application-level error)
            if fb_result.failure_reason == FailureReason.NONE:
                capabilities.primary = proto
            return fb_result

    # All protocols failed
    return result


def _build_fallback_chain(
    caps: TargetCapabilities,
    failed_proto: str,
) -> list[ProbeProtocol]:
    """Build ordered list of fallback protocols, excluding the failed one."""
    chain: list[ProbeProtocol] = []
    candidates = [
        (ProbeProtocol.JSONRPC, caps.jsonrpc_ws or caps.jsonrpc_http),
        (ProbeProtocol.WEBSOCKET, caps.websocket),
        (ProbeProtocol.HTTP, caps.http),
    ]
    for proto, supported in candidates:
        if supported and proto.value != failed_proto:
            chain.append(proto)
    return chain
