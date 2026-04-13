"""WebSocket protocol executor for prove agent verification probes."""

import asyncio
import json
import logging

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

_WS_CONNECT_TIMEOUT = 10.0
_WS_RECV_TIMEOUT = 5.0
_MAX_MESSAGES = 5

_ANALYZE_PROMPT = """Did this WebSocket response confirm the vulnerability?

Finding: {title} ({category})
Request: WebSocket message to {url}
Messages received: {messages}
Expected indicators: {expected_indicators}

Reply with JSON only:
{{"conclusive":true,"reproduced":true,"evidence":"explanation"}}"""


async def execute_websocket(
    plan: ProofPlan,
    staging_url: str,
    capabilities: TargetCapabilities,
    finding_category: str,
    finding_title: str,
) -> ExecutionResult:
    """Execute a WebSocket probe — connect, send, collect messages, analyze."""
    ws_url = to_ws_url(staging_url, plan.url_path)

    try:
        messages: list[str] = []

        extra_headers = {}
        for k, v in plan.headers.items():
            if k.lower() not in ("upgrade", "connection", "sec-websocket-version", "sec-websocket-key"):
                extra_headers[k] = v

        async with websockets.connect(
            ws_url,
            open_timeout=_WS_CONNECT_TIMEOUT,
            close_timeout=2,
            additional_headers=extra_headers or None,
        ) as ws:
            # Send probe payload
            payload = plan.body or ""
            if payload:
                await ws.send(payload)

            # Collect responses
            for _ in range(_MAX_MESSAGES):
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=_WS_RECV_TIMEOUT)
                    if isinstance(msg, bytes):
                        msg = msg.decode("utf-8", errors="replace")
                    messages.append(msg[:500])
                except asyncio.TimeoutError:
                    break

        if not messages:
            return ExecutionResult(
                conclusive=False,
                evidence="WebSocket connected but no messages received",
                protocol_used=ProbeProtocol.WEBSOCKET.value,
            )

        # Phase 1: rule-based check on messages
        rule_result = _analyze_ws_messages(messages, plan, finding_category, finding_title)
        if rule_result:
            return rule_result

        # Phase 2: LLM analysis
        combined = "\n".join(f"[{i+1}] {m}" for i, m in enumerate(messages))
        snippet = combined[:500]
        try:
            llm_result = await llm_json_call(_ANALYZE_PROMPT.format(
                title=finding_title,
                category=finding_category,
                url=ws_url,
                messages=snippet,
                expected_indicators=json.dumps(plan.expected_indicators),
            ))
            return ExecutionResult(
                conclusive=llm_result.get("conclusive", False),
                reproduced=llm_result.get("reproduced", False),
                evidence=llm_result.get("evidence", f"WS: {len(messages)} messages"),
                response_snippet=snippet,
                protocol_used=ProbeProtocol.WEBSOCKET.value,
            )
        except Exception:
            return ExecutionResult(
                conclusive=False,
                evidence=f"WS probe: {len(messages)} messages, LLM analysis failed",
                response_snippet=snippet,
                protocol_used=ProbeProtocol.WEBSOCKET.value,
            )

    except Exception as exc:
        failure = _classify_ws_failure(exc)
        return ExecutionResult(
            conclusive=False,
            evidence=f"WebSocket error: {exc}",
            failure_reason=failure,
            protocol_used=ProbeProtocol.WEBSOCKET.value,
        )


def _analyze_ws_messages(
    messages: list[str],
    plan: ProofPlan,
    finding_category: str,
    finding_title: str,
) -> ExecutionResult | None:
    """Rule-based analysis of WebSocket messages."""
    combined = " ".join(messages).lower()

    # Check expected indicators
    matched = [ind for ind in plan.expected_indicators if ind.lower() in combined]
    if matched:
        snippet = "\n".join(f"[{i+1}] {m}" for i, m in enumerate(messages))[:500]
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"WebSocket response matched indicators: {', '.join(matched)}",
            response_snippet=snippet,
            protocol_used=ProbeProtocol.WEBSOCKET.value,
        )

    # Check for error patterns that indicate vulnerability probing worked
    error_patterns = ["error", "exception", "traceback", "stack trace"]
    if any(p in combined for p in error_patterns):
        # Error disclosure via WebSocket = potential info leak
        lower_title = finding_title.lower()
        if any(kw in lower_title for kw in ("info", "disclos", "error", "expos", "leak")):
            snippet = "\n".join(f"[{i+1}] {m}" for i, m in enumerate(messages))[:500]
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence="WebSocket error disclosure detected",
                response_snippet=snippet,
                protocol_used=ProbeProtocol.WEBSOCKET.value,
            )

    return None


def _classify_ws_failure(exc: Exception) -> FailureReason:
    """Map websockets exceptions to FailureReason."""
    exc_str = str(exc).lower()
    exc_type = type(exc).__name__.lower()

    if "timeout" in exc_str or "timeout" in exc_type:
        return FailureReason.TIMEOUT
    if any(kw in exc_str for kw in ("refused", "connect", "dns", "resolve", "unreachable")):
        return FailureReason.CONNECTION_ERROR
    if any(kw in exc_str for kw in ("403", "401", "forbidden", "unauthorized")):
        return FailureReason.AUTH_REQUIRED
    if "protocol" in exc_str or "upgrade" in exc_str or "handshake" in exc_str:
        return FailureReason.PROTOCOL_ERROR
    return FailureReason.CONNECTION_ERROR
