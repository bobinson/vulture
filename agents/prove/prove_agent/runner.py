"""Self-learning Plan-Review-Execute loop for finding verification.

Inspired by production experience with the RLM Self-Refine pattern:
  evaluate → score → reflect → refine → loop until confident

Each attempt feeds rich feedback (response data, LLM analysis, reflection)
back into the next plan. The agent adapts its strategy based on what it
learns from each attempt rather than blindly repeating.
"""

import asyncio
import logging
import os
from collections.abc import AsyncGenerator
from enum import Enum
from urllib.parse import urlparse

from shared.llm.loop_detector import LoopAction, LoopDetector, hash_result
from shared.transport.event_emitter import AgUiEventEmitter

from prove_agent.protocols.detection import TargetCapabilities
from prove_agent.strategies.base import (
    AttemptRecord,
    BaseStrategy,
    FailureReason,
    ProbeProtocol,
    ReflectionResult,
)
from prove_agent.strategies.shared import stepped_backoff_delay_adaptive

logger = logging.getLogger(__name__)

_MAX_CONSECUTIVE_FAILURES = 3
_CONFIDENCE_THRESHOLD = 80  # Stop when LLM is >=80% confident
_FINDING_TIMEOUT = float(os.environ.get("VULTURE_PROVE_FINDING_TIMEOUT", "120"))

# Loop detection thresholds for probe dedup
_PROVE_LOOP_WARN = 3
_PROVE_LOOP_KILL = 5
_PROVE_GLOBAL_LIMIT = 15


class ProvePhase(str, Enum):
    """Observable phases of the prove loop."""

    PLANNING = "planning"
    REVIEWING = "reviewing"
    EXECUTING = "executing"
    REFLECTING = "reflecting"

_BLOCKED_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
})


def validate_staging_url(staging_url: str, *, allow_local: bool = False) -> str | None:
    """Validate staging URL. Returns error message or None if valid."""
    parsed = urlparse(staging_url)
    if parsed.scheme not in ("http", "https", "ws", "wss"):
        return f"Invalid scheme: {parsed.scheme}. Only http/https/ws/wss allowed."
    if not parsed.hostname:
        return "Missing hostname in staging URL."
    if not allow_local and parsed.hostname in _BLOCKED_HOSTS:
        return (
            f"Refusing to target {parsed.hostname}. "
            "Use --allow-local to override."
        )
    return None


def _synthesize_timeout_evidence(
    title: str,
    timeout: float,
    attempts: list[AttemptRecord],
) -> str:
    """Build rich timeout evidence from partial attempts.

    Instead of a generic "Timed out after Xs", synthesizes forensics
    from whatever attempts completed before the timeout.
    """
    if not attempts:
        return f"Timed out after {timeout:.0f}s with no completed attempts"
    last = attempts[-1]
    parts = [
        f"Timed out after {timeout:.0f}s with {len(attempts)} attempt(s).",
        f"Last: {last.method} {last.url_path} -> HTTP {last.status_code}.",
    ]
    if last.evidence:
        parts.append(f"Evidence: {last.evidence[:200]}")
    statuses = sorted({a.status_code for a in attempts})
    parts.append(f"Status codes seen: {statuses}")
    return " ".join(parts)


async def prove_finding_with_timeout(
    finding: dict,
    strategy: BaseStrategy,
    staging_url: str,
    max_iterations: int,
    emitter: AgUiEventEmitter,
    *,
    site_context: str = "",
    cross_learnings: list[str] | None = None,
    capabilities: TargetCapabilities | None = None,
    timeout: float = _FINDING_TIMEOUT,
):
    """Wrapper around prove_finding that enforces a per-finding timeout.

    Yields SSE events from prove_finding, emitting a timeout result
    with synthesized evidence from partial attempts if exceeded.
    """
    finding_id = finding.get("id", "unknown")
    title = finding.get("title", "Unknown finding")
    events: list[str] = []
    timed_out = False
    # Shared attempt sink so timeout wrapper can inspect partial progress
    attempt_sink: list[AttemptRecord] = []

    async def _collect():
        nonlocal timed_out
        async for event in prove_finding(
            finding, strategy, staging_url, max_iterations, emitter,
            site_context=site_context, cross_learnings=cross_learnings,
            capabilities=capabilities,
            _attempt_sink=attempt_sink,
        ):
            events.append(event)

    try:
        await asyncio.wait_for(_collect(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        logger.warning("finding_timeout id=%s title=%s timeout=%.0fs", finding_id, title, timeout)

    for event in events:
        yield event

    if timed_out:
        evidence = _synthesize_timeout_evidence(title, timeout, attempt_sink)
        yield emitter.text_message(
            f"Timeout ({timeout:.0f}s) reached for {title}"
        )
        yield emitter.proof_result_event(
            finding_id, "inconclusive",
            evidence,
            max_iterations,
            staging_url=staging_url,
        )


async def prove_finding(
    finding: dict,
    strategy: BaseStrategy,
    staging_url: str,
    max_iterations: int,
    emitter: AgUiEventEmitter,
    *,
    site_context: str = "",
    cross_learnings: list[str] | None = None,
    capabilities: TargetCapabilities | None = None,
    _attempt_sink: list[AttemptRecord] | None = None,
) -> AsyncGenerator[str, None]:
    """Run self-learning Plan-Review-Execute loop for a single finding.

    Yields SSE event strings. Learnings are accumulated via the mutable
    cross_learnings list passed by the caller.
    """
    finding_id = finding.get("id", "unknown")
    title = finding.get("title", "Unknown finding")
    consecutive_failures = 0
    attempts: list[AttemptRecord] = []
    reflection: ReflectionResult | None = None
    # Use the caller's list directly (mutable reference) so learnings
    # accumulated here propagate back to the caller for cross-finding use.
    all_learnings: list[str] = cross_learnings if cross_learnings is not None else []

    # Loop detection: prevent wasting LLM+HTTP calls on repeated probes
    probe_detector = LoopDetector(
        window=20,
        warn_threshold=_PROVE_LOOP_WARN,
        kill_threshold=_PROVE_LOOP_KILL,
        global_limit=_PROVE_GLOBAL_LIMIT,
    )

    for iteration in range(1, max_iterations + 1):
        # Phase 1: PLAN — informed by reflection + rich attempt history
        yield emitter.proof_phase_event(finding_id, ProvePhase.PLANNING.value, iteration)
        try:
            plan = await strategy.plan(
                finding, staging_url, iteration,
                site_context=site_context,
                prior_attempts=attempts,
                reflection=reflection,
                cross_learnings=all_learnings,
            )
        except Exception as exc:
            logger.warning("Plan failed for %s: %s", finding_id, exc)
            consecutive_failures += 1
            if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                break
            continue

        plan_desc = plan.description or f"{plan.method} {plan.url_path}"
        yield emitter.proof_plan_event(
            finding_id, title, plan_desc, iteration,
            protocol=plan.protocol.value,
        )

        # Phase 2: REVIEW — safety check
        yield emitter.proof_phase_event(finding_id, ProvePhase.REVIEWING.value, iteration)
        review = await strategy.review(plan, staging_url)
        yield emitter.proof_review_event(
            finding_id, review.safe, review.concerns, iteration,
        )
        if not review.safe:
            yield emitter.text_message(
                f"Plan deemed unsafe for {title}, skipping"
            )
            continue

        # Phase 3: EXECUTE
        yield emitter.proof_phase_event(finding_id, ProvePhase.EXECUTING.value, iteration)
        try:
            result = await strategy.execute(plan, staging_url, capabilities=capabilities)
        except Exception as exc:
            logger.warning("Execute failed for %s: %s", finding_id, exc)
            consecutive_failures += 1
            if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                break
            continue

        consecutive_failures = 0

        # Record rich attempt data for self-learning
        proto_used = result.protocol_used or plan.protocol.value
        attempt = AttemptRecord(
            iteration=iteration,
            method=plan.method,
            url_path=plan.url_path,
            status_code=result.status_code,
            response_snippet=result.response_snippet,
            response_headers=result.response_headers,
            evidence=result.evidence,
            conclusive=result.conclusive,
            reproduced=result.reproduced,
            plan_description=plan_desc,
            failure_reason=result.failure_reason,
            protocol=proto_used,
        )
        attempts.append(attempt)
        # Feed attempt sink for timeout forensics (J: Synthetic Result Synthesis)
        if _attempt_sink is not None:
            _attempt_sink.append(attempt)

        # F: Loop detection — prevent repeated identical probes
        sig = f"{proto_used}:{plan.method}:{plan.url_path}:{result.status_code}"
        action = probe_detector.record("http_probe", result_hash=hash_result(sig))
        if action == LoopAction.KILL:
            yield emitter.text_message(
                f"Probe loop detected for {title}: repeated {plan.method} {plan.url_path}"
            )
            yield emitter.proof_result_event(
                finding_id, "inconclusive",
                f"Probe loop detected: repeated {plan.method} {plan.url_path} → HTTP {result.status_code}",
                iteration, staging_url=staging_url,
            )
            return

        yield emitter.proof_attempt_event(
            finding_id, result.reproduced, result.evidence, iteration,
            protocol=proto_used,
        )

        # Smart early-exit: if all attempts hit auth_required, stop early
        if result.failure_reason == FailureReason.AUTH_REQUIRED:
            auth_attempts = sum(
                1 for a in attempts if a.failure_reason == FailureReason.AUTH_REQUIRED
            )
            if auth_attempts >= 2:
                yield emitter.text_message(
                    f"Target requires authentication for {title} — "
                    "cannot verify without credentials"
                )
                yield emitter.proof_result_event(
                    finding_id, "inconclusive",
                    f"Endpoint requires authentication (HTTP {result.status_code}) — "
                    "cannot verify without valid credentials",
                    iteration,
                    staging_url=staging_url,
                )
                return

        # Smart early-exit: connection failures — try protocol fallback first
        if result.failure_reason in (FailureReason.CONNECTION_ERROR, FailureReason.PROTOCOL_ERROR):
            if capabilities and _has_alternative_protocol(capabilities, result.protocol_used):
                # Don't exit yet — let next iteration try a different protocol
                logger.info(
                    "Protocol %s failed, alternative protocols available — continuing",
                    result.protocol_used,
                )
            else:
                yield emitter.proof_result_event(
                    finding_id, "inconclusive",
                    f"Target unreachable: {result.evidence}",
                    iteration,
                    staging_url=staging_url,
                )
                return

        # If conclusive, we're done
        if result.conclusive:
            status = "verified" if result.reproduced else "not_reproduced"
            yield emitter.proof_result_event(
                finding_id, status, result.evidence, iteration,
                staging_url=staging_url,
            )
            # Extract learnings from this successful verification
            if reflection:
                all_learnings.extend(reflection.learnings)
            return

        # Phase 4: REFLECT — analyze WHY inconclusive, adapt strategy
        # (skip reflection on last iteration since we won't loop again)
        if iteration < max_iterations:
            yield emitter.proof_phase_event(finding_id, ProvePhase.REFLECTING.value, iteration)
            try:
                reflection = await strategy.reflect(finding, attempts)
                yield emitter.proof_reflection_event(
                    finding_id,
                    reflection.analysis,
                    reflection.suggested_approach,
                    reflection.confidence,
                    iteration,
                )

                # If confidence is high enough, LLM is sure it can't be proven
                if reflection.confidence >= _CONFIDENCE_THRESHOLD:
                    yield emitter.text_message(
                        f"High confidence ({reflection.confidence}%) reached "
                        f"after {iteration} attempts"
                    )
                    # Confidence in vulnerability existing vs not
                    # If high confidence + not reproduced = likely false positive
                    yield emitter.proof_result_event(
                        finding_id, "not_reproduced",
                        f"High confidence ({reflection.confidence}%) after "
                        f"{iteration} attempts: {reflection.analysis}",
                        iteration,
                        staging_url=staging_url,
                    )
                    all_learnings.extend(reflection.learnings)
                    return

                # Collect learnings for cross-finding use
                all_learnings.extend(reflection.learnings)

            except Exception as exc:
                logger.warning("Reflection failed for %s: %s", finding_id, exc)
                # Continue without reflection — next plan uses attempt history

            # G: Adaptive backoff — reset on progress (2xx), slow down otherwise
            last_status = attempts[-1].status_code if attempts else 0
            delay = stepped_backoff_delay_adaptive(iteration, last_status)
            await asyncio.sleep(delay)

    # Exhausted iterations or circuit breaker
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
        reason = "Circuit breaker: too many consecutive failures"
    else:
        reason = f"Inconclusive after {max_iterations} attempts"
        if reflection:
            reason += f" (last confidence: {reflection.confidence}%)"
    yield emitter.proof_result_event(
        finding_id, "inconclusive", reason, max_iterations,
        staging_url=staging_url,
    )


def _has_alternative_protocol(caps: TargetCapabilities, failed_proto: str) -> bool:
    """Check if target has an alternative protocol to the one that failed."""
    alternatives = [
        ("jsonrpc", caps.jsonrpc_ws or caps.jsonrpc_http),
        ("websocket", caps.websocket),
        ("http", caps.http),
    ]
    return any(supported and proto != failed_proto for proto, supported in alternatives)
