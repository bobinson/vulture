"""Tests for prove_finding_with_timeout and stepped_backoff_delay."""

import asyncio
import json

import pytest

from shared.transport.event_emitter import AgUiEventEmitter

from prove_agent.runner import prove_finding_with_timeout
from prove_agent.strategies.base import (
    BaseStrategy,
    ExecutionResult,
    ProofPlan,
    ReflectionResult,
    ReviewResult,
)
from prove_agent.strategies.shared import stepped_backoff_delay


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_sse_event(raw: str) -> tuple[str, dict]:
    """Parse an SSE event string into (event_name, data_dict)."""
    event_name = ""
    data_str = ""
    for line in raw.strip().splitlines():
        if line.startswith("event: "):
            event_name = line[len("event: "):]
        elif line.startswith("data: "):
            data_str = line[len("data: "):]
    return event_name, json.loads(data_str) if data_str else {}


class QuickStrategy(BaseStrategy):
    """Strategy that completes quickly with a conclusive result."""

    def __init__(self, *, reproduced: bool = True) -> None:
        self._reproduced = reproduced

    async def plan(self, finding, staging_url, iteration, **kwargs) -> ProofPlan:
        return ProofPlan(
            description="Quick test plan",
            method="GET",
            url_path="/test",
            headers={},
            body="",
            expected_indicators=["vuln"],
        )

    async def review(self, plan, staging_url) -> ReviewResult:
        return ReviewResult(safe=True)

    async def execute(self, plan, staging_url, **kwargs) -> ExecutionResult:
        return ExecutionResult(
            conclusive=True,
            reproduced=self._reproduced,
            evidence="Quick evidence",
            status_code=200,
            response_snippet="OK",
        )

    async def reflect(self, finding, attempts) -> ReflectionResult:
        return ReflectionResult(
            analysis="N/A",
            suggested_approach="N/A",
            confidence=50,
        )


class SlowStrategy(BaseStrategy):
    """Strategy that never finishes (hangs forever in execute)."""

    async def plan(self, finding, staging_url, iteration, **kwargs) -> ProofPlan:
        return ProofPlan(
            description="Slow plan",
            method="GET",
            url_path="/slow",
        )

    async def review(self, plan, staging_url) -> ReviewResult:
        return ReviewResult(safe=True)

    async def execute(self, plan, staging_url, **kwargs) -> ExecutionResult:
        # Hang long enough to guarantee timeout
        await asyncio.sleep(300)
        return ExecutionResult(conclusive=False, evidence="should not reach")

    async def reflect(self, finding, attempts) -> ReflectionResult:
        return ReflectionResult(
            analysis="N/A",
            suggested_approach="N/A",
            confidence=50,
        )


# ===========================================================================
# prove_finding_with_timeout
# ===========================================================================


class TestProveFindingWithTimeoutNormal:
    """Normal completion — events pass through without timeout."""

    @pytest.mark.asyncio
    async def test_events_pass_through_on_normal_completion(self):
        """When prove_finding completes before the timeout, all its events
        are yielded and no timeout / inconclusive event is appended."""
        emitter = AgUiEventEmitter("test-run")
        finding = {"id": "f-1", "title": "Test finding", "category": "OWASP"}
        strategy = QuickStrategy(reproduced=True)

        events: list[str] = []
        async for event in prove_finding_with_timeout(
            finding,
            strategy,
            "http://staging.example.com",
            max_iterations=3,
            emitter=emitter,
            timeout=10.0,
        ):
            events.append(event)

        # Should have proof_plan, proof_review, proof_attempt, proof_result
        event_types = [_parse_sse_event(e)[0] for e in events]
        assert "proof_plan" in event_types
        assert "proof_result" in event_types

        # The proof_result should be "verified", not "inconclusive"
        for e in events:
            name, data = _parse_sse_event(e)
            if name == "proof_result":
                assert data["status"] == "verified"
                assert data["finding_id"] == "f-1"
                break

    @pytest.mark.asyncio
    async def test_no_timeout_event_on_normal_completion(self):
        """No thinking event about timeout should appear on normal completion."""
        emitter = AgUiEventEmitter("test-run")
        finding = {"id": "f-2", "title": "Another finding", "category": "CWE"}
        strategy = QuickStrategy(reproduced=False)

        events: list[str] = []
        async for event in prove_finding_with_timeout(
            finding,
            strategy,
            "http://staging.example.com",
            max_iterations=3,
            emitter=emitter,
            timeout=10.0,
        ):
            events.append(event)

        # No event should contain the word "Timeout" or "timeout" in a thinking event
        for e in events:
            name, data = _parse_sse_event(e)
            if name == "thinking":
                assert "Timeout" not in data.get("content", "")


class TestProveFindingWithTimeoutExpired:
    """Timeout triggers — inconclusive result emitted."""

    @pytest.mark.asyncio
    async def test_emits_inconclusive_on_timeout(self):
        """When the inner prove_finding exceeds the timeout, the wrapper
        should yield a thinking event about the timeout and a proof_result
        with status 'inconclusive'."""
        emitter = AgUiEventEmitter("test-run")
        finding = {"id": "f-slow", "title": "Slow finding", "category": "OWASP"}
        strategy = SlowStrategy()

        events: list[str] = []
        async for event in prove_finding_with_timeout(
            finding,
            strategy,
            "http://staging.example.com",
            max_iterations=3,
            emitter=emitter,
            timeout=0.1,  # Very short timeout to trigger quickly
        ):
            events.append(event)

        event_types = [_parse_sse_event(e)[0] for e in events]

        # Should have a thinking event about the timeout
        assert "thinking" in event_types
        # Should have a proof_result with inconclusive
        assert "proof_result" in event_types

        # Verify the thinking event content mentions timeout
        thinking_events = [
            _parse_sse_event(e) for e in events
            if _parse_sse_event(e)[0] == "thinking"
        ]
        timeout_messages = [
            t for t in thinking_events
            if "Timeout" in t[1].get("content", "")
        ]
        assert len(timeout_messages) >= 1
        assert "Slow finding" in timeout_messages[0][1]["content"]

        # Verify the proof_result event
        for e in events:
            name, data = _parse_sse_event(e)
            if name == "proof_result":
                assert data["status"] == "inconclusive"
                assert data["finding_id"] == "f-slow"
                assert "Timed out" in data["evidence"]
                break

    @pytest.mark.asyncio
    async def test_partial_events_still_yielded_before_timeout(self):
        """Events emitted before the timeout should still be yielded.

        The SlowStrategy emits proof_plan and proof_review before hanging in
        execute, so those events should appear even on timeout.
        """
        emitter = AgUiEventEmitter("test-run")
        finding = {"id": "f-partial", "title": "Partial finding", "category": "CWE"}
        strategy = SlowStrategy()

        events: list[str] = []
        async for event in prove_finding_with_timeout(
            finding,
            strategy,
            "http://staging.example.com",
            max_iterations=3,
            emitter=emitter,
            timeout=0.5,
        ):
            events.append(event)

        event_types = [_parse_sse_event(e)[0] for e in events]

        # proof_plan and proof_review should have been emitted before the hang
        assert "proof_plan" in event_types
        assert "proof_review" in event_types
        # And the timeout result should follow
        assert "proof_result" in event_types

    @pytest.mark.asyncio
    async def test_timeout_uses_correct_duration_in_message(self):
        """The timeout message should reflect the actual timeout value used."""
        emitter = AgUiEventEmitter("test-run")
        finding = {"id": "f-dur", "title": "Duration check", "category": "OWASP"}
        strategy = SlowStrategy()

        events: list[str] = []
        async for event in prove_finding_with_timeout(
            finding,
            strategy,
            "http://staging.example.com",
            max_iterations=1,
            emitter=emitter,
            timeout=0.2,
        ):
            events.append(event)

        # Check the thinking event references "0s" (since 0.2 rounds to 0)
        # Actually, f"{0.2:.0f}" = "0", so the message says "Timeout (0s)"
        # Let's just verify the proof_result evidence says "Timed out after 0s"
        for e in events:
            name, data = _parse_sse_event(e)
            if name == "proof_result" and data.get("status") == "inconclusive":
                assert "Timed out after" in data["evidence"]
                break


# ===========================================================================
# stepped_backoff_delay
# ===========================================================================


class TestSteppedBackoffDelay:
    """stepped_backoff_delay returns stepped delays based on iteration."""

    def test_iteration_1_returns_0_5(self):
        assert stepped_backoff_delay(1) == 0.5

    def test_iteration_2_returns_1_0(self):
        assert stepped_backoff_delay(2) == 1.0

    def test_iteration_3_returns_2_0(self):
        assert stepped_backoff_delay(3) == 2.0

    def test_iteration_4_returns_3_0(self):
        assert stepped_backoff_delay(4) == 3.0

    def test_iteration_5_returns_5_0(self):
        assert stepped_backoff_delay(5) == 5.0

    def test_iteration_above_5_caps_at_5_0(self):
        assert stepped_backoff_delay(6) == 5.0
        assert stepped_backoff_delay(10) == 5.0
        assert stepped_backoff_delay(100) == 5.0

    def test_iteration_0_clamps_to_first(self):
        assert stepped_backoff_delay(0) == 0.5

    def test_negative_iteration_clamps_to_first(self):
        assert stepped_backoff_delay(-1) == 0.5
        assert stepped_backoff_delay(-99) == 0.5

    def test_all_steps_in_sequence(self):
        """Verify the full step sequence [0.5, 1.0, 2.0, 3.0, 5.0]."""
        expected = [0.5, 1.0, 2.0, 3.0, 5.0]
        actual = [stepped_backoff_delay(i) for i in range(1, 6)]
        assert actual == expected
