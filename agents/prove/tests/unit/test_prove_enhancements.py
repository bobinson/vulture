"""Unit tests for prove agent enhancements — timeout evidence, adaptive backoff, enums."""

import pytest

from prove_agent.runner import ProvePhase, _synthesize_timeout_evidence
from prove_agent.strategies.base import AttemptRecord, FailureReason
from prove_agent.strategies.shared import (
    _STEP_DELAYS,
    stepped_backoff_delay,
    stepped_backoff_delay_adaptive,
)


# ---------------------------------------------------------------------------
# _synthesize_timeout_evidence
# ---------------------------------------------------------------------------

class TestSynthesizeTimeoutEvidence:
    """Test _synthesize_timeout_evidence with and without attempts."""

    def test_no_attempts(self):
        result = _synthesize_timeout_evidence("SQL Injection", 120.0, [])
        assert "Timed out after 120s" in result
        assert "no completed attempts" in result

    def test_with_single_attempt(self):
        attempt = AttemptRecord(
            iteration=1,
            method="GET",
            url_path="/api/login",
            status_code=200,
            response_snippet="OK",
            response_headers={},
            evidence="Found login form",
            conclusive=False,
            reproduced=False,
            plan_description="Probe login",
        )
        result = _synthesize_timeout_evidence("Auth Bypass", 60.0, [attempt])
        assert "Timed out after 60s" in result
        assert "1 attempt(s)" in result
        assert "GET /api/login" in result
        assert "HTTP 200" in result
        assert "Found login form" in result

    def test_with_multiple_attempts(self):
        attempts = [
            AttemptRecord(
                iteration=1,
                method="GET",
                url_path="/api/users",
                status_code=401,
                response_snippet="Unauthorized",
                response_headers={},
                evidence="Auth required",
                conclusive=False,
                reproduced=False,
                plan_description="List users",
            ),
            AttemptRecord(
                iteration=2,
                method="POST",
                url_path="/api/login",
                status_code=200,
                response_snippet='{"token":"..."}',
                response_headers={},
                evidence="Got token",
                conclusive=False,
                reproduced=False,
                plan_description="Try login",
            ),
            AttemptRecord(
                iteration=3,
                method="GET",
                url_path="/api/admin",
                status_code=403,
                response_snippet="Forbidden",
                response_headers={},
                evidence="Access denied",
                conclusive=False,
                reproduced=False,
                plan_description="Access admin",
            ),
        ]
        result = _synthesize_timeout_evidence("Privilege Escalation", 120.0, attempts)
        assert "3 attempt(s)" in result
        # Should reference the last attempt
        assert "GET /api/admin" in result
        assert "HTTP 403" in result
        # Should include status codes seen
        assert "401" in result
        assert "200" in result
        assert "403" in result

    def test_last_attempt_evidence_included(self):
        attempt = AttemptRecord(
            iteration=1,
            method="POST",
            url_path="/api/data",
            status_code=500,
            response_snippet="Internal Server Error",
            response_headers={},
            evidence="Server crashed on malformed input",
            conclusive=False,
            reproduced=False,
            plan_description="Fuzz endpoint",
        )
        result = _synthesize_timeout_evidence("Server Error", 30.0, [attempt])
        assert "Server crashed on malformed input" in result

    def test_evidence_truncated_to_200_chars(self):
        long_evidence = "X" * 500
        attempt = AttemptRecord(
            iteration=1,
            method="GET",
            url_path="/api/test",
            status_code=200,
            response_snippet="OK",
            response_headers={},
            evidence=long_evidence,
            conclusive=False,
            reproduced=False,
            plan_description="Test",
        )
        result = _synthesize_timeout_evidence("Test", 60.0, [attempt])
        # The evidence should be truncated at 200 chars
        assert "X" * 200 in result
        assert "X" * 201 not in result


# ---------------------------------------------------------------------------
# stepped_backoff_delay_adaptive
# ---------------------------------------------------------------------------

class TestSteppedBackoffDelayAdaptive:
    """Test adaptive backoff resets on 2xx and steps up on 4xx/5xx."""

    def test_resets_on_200(self):
        delay = stepped_backoff_delay_adaptive(5, 200)
        assert delay == _STEP_DELAYS[0]

    def test_resets_on_201(self):
        delay = stepped_backoff_delay_adaptive(3, 201)
        assert delay == _STEP_DELAYS[0]

    def test_resets_on_301(self):
        delay = stepped_backoff_delay_adaptive(4, 301)
        assert delay == _STEP_DELAYS[0]

    def test_resets_on_399(self):
        delay = stepped_backoff_delay_adaptive(4, 399)
        assert delay == _STEP_DELAYS[0]

    def test_steps_up_on_400(self):
        delay = stepped_backoff_delay_adaptive(3, 400)
        expected = stepped_backoff_delay(3)
        assert delay == expected

    def test_steps_up_on_404(self):
        delay = stepped_backoff_delay_adaptive(2, 404)
        expected = stepped_backoff_delay(2)
        assert delay == expected

    def test_steps_up_on_429(self):
        delay = stepped_backoff_delay_adaptive(4, 429)
        expected = stepped_backoff_delay(4)
        assert delay == expected

    def test_steps_up_on_500(self):
        delay = stepped_backoff_delay_adaptive(3, 500)
        expected = stepped_backoff_delay(3)
        assert delay == expected

    def test_steps_up_on_503(self):
        delay = stepped_backoff_delay_adaptive(5, 503)
        expected = stepped_backoff_delay(5)
        assert delay == expected

    def test_unknown_status_zero_uses_regular_backoff(self):
        delay = stepped_backoff_delay_adaptive(2, 0)
        expected = stepped_backoff_delay(2)
        assert delay == expected

    def test_iteration_1_delay_is_first_step(self):
        delay = stepped_backoff_delay_adaptive(1, 500)
        assert delay == _STEP_DELAYS[0]

    def test_iteration_beyond_steps_caps_at_last(self):
        delay = stepped_backoff_delay_adaptive(100, 500)
        assert delay == _STEP_DELAYS[-1]

    def test_delays_increase_monotonically_on_errors(self):
        delays = [stepped_backoff_delay_adaptive(i, 500) for i in range(1, 10)]
        for i in range(1, len(delays)):
            assert delays[i] >= delays[i - 1]


# ---------------------------------------------------------------------------
# ProvePhase enum
# ---------------------------------------------------------------------------

class TestProvePhaseEnum:
    """Test ProvePhase enum values."""

    def test_planning_value(self):
        assert ProvePhase.PLANNING.value == "planning"

    def test_reviewing_value(self):
        assert ProvePhase.REVIEWING.value == "reviewing"

    def test_executing_value(self):
        assert ProvePhase.EXECUTING.value == "executing"

    def test_reflecting_value(self):
        assert ProvePhase.REFLECTING.value == "reflecting"

    def test_enum_is_string(self):
        assert isinstance(ProvePhase.PLANNING, str)
        assert isinstance(ProvePhase.EXECUTING, str)

    def test_all_four_phases_exist(self):
        phases = list(ProvePhase)
        assert len(phases) == 4

    def test_enum_members(self):
        names = {p.name for p in ProvePhase}
        assert names == {"PLANNING", "REVIEWING", "EXECUTING", "REFLECTING"}

    def test_string_comparison(self):
        assert ProvePhase.PLANNING == "planning"
        assert ProvePhase.REFLECTING == "reflecting"


# ---------------------------------------------------------------------------
# FailureReason.PAYLOAD_TOO_LARGE exists
# ---------------------------------------------------------------------------

class TestFailureReasonPayloadTooLarge:
    """Test that FailureReason.PAYLOAD_TOO_LARGE exists and has expected value."""

    def test_payload_too_large_exists(self):
        assert hasattr(FailureReason, "PAYLOAD_TOO_LARGE")

    def test_payload_too_large_value(self):
        assert FailureReason.PAYLOAD_TOO_LARGE.value == "payload_too_large"

    def test_payload_too_large_is_enum_member(self):
        assert FailureReason.PAYLOAD_TOO_LARGE in FailureReason

    def test_all_expected_failure_reasons_exist(self):
        expected = {
            "AUTH_REQUIRED", "RATE_LIMITED", "TIMEOUT", "NOT_FOUND",
            "CONNECTION_ERROR", "SERVER_ERROR", "FORMAT_ERROR",
            "PAYLOAD_TOO_LARGE", "PROTOCOL_ERROR", "NONE",
        }
        actual = {fr.name for fr in FailureReason}
        assert expected == actual

    def test_none_is_default_no_failure(self):
        assert FailureReason.NONE.value == "none"
