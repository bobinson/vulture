"""Tests for error classification (ported from prior deployment's FailoverReason)."""


from prove_agent.strategies.base import FailureReason
from prove_agent.strategies.shared import classify_failure


class TestClassifyByStatusCode:
    """Status code → FailureReason mapping."""

    def test_401_is_auth_required(self):
        assert classify_failure(status_code=401) == FailureReason.AUTH_REQUIRED

    def test_403_is_auth_required(self):
        assert classify_failure(status_code=403) == FailureReason.AUTH_REQUIRED

    def test_429_is_rate_limited(self):
        assert classify_failure(status_code=429) == FailureReason.RATE_LIMITED

    def test_404_is_not_found(self):
        assert classify_failure(status_code=404) == FailureReason.NOT_FOUND

    def test_400_is_format_error(self):
        assert classify_failure(status_code=400) == FailureReason.FORMAT_ERROR

    def test_408_is_timeout(self):
        assert classify_failure(status_code=408) == FailureReason.TIMEOUT

    def test_504_is_timeout(self):
        assert classify_failure(status_code=504) == FailureReason.TIMEOUT

    def test_500_is_server_error(self):
        assert classify_failure(status_code=500) == FailureReason.SERVER_ERROR

    def test_502_is_server_error(self):
        assert classify_failure(status_code=502) == FailureReason.SERVER_ERROR

    def test_503_is_server_error(self):
        assert classify_failure(status_code=503) == FailureReason.SERVER_ERROR

    def test_200_is_none(self):
        assert classify_failure(status_code=200) == FailureReason.NONE

    def test_201_is_none(self):
        assert classify_failure(status_code=201) == FailureReason.NONE

    def test_301_is_none(self):
        assert classify_failure(status_code=301) == FailureReason.NONE


class TestClassifyByErrorMessage:
    """Error message pattern matching."""

    def test_rate_limit_message(self):
        assert classify_failure(error_message="rate limit exceeded") == FailureReason.RATE_LIMITED

    def test_too_many_requests_message(self):
        assert classify_failure(error_message="Too many requests") == FailureReason.RATE_LIMITED

    def test_429_in_message(self):
        assert classify_failure(error_message="got HTTP 429") == FailureReason.RATE_LIMITED

    def test_quota_message(self):
        assert classify_failure(error_message="API quota exhausted") == FailureReason.RATE_LIMITED

    def test_unauthorized_message(self):
        assert classify_failure(error_message="Unauthorized access") == FailureReason.AUTH_REQUIRED

    def test_forbidden_message(self):
        assert classify_failure(error_message="Forbidden") == FailureReason.AUTH_REQUIRED

    def test_invalid_api_key_message(self):
        assert classify_failure(error_message="invalid api key provided") == FailureReason.AUTH_REQUIRED

    def test_invalid_token_message(self):
        assert classify_failure(error_message="invalid token") == FailureReason.AUTH_REQUIRED

    def test_access_denied_message(self):
        assert classify_failure(error_message="Access Denied") == FailureReason.AUTH_REQUIRED

    def test_timeout_message(self):
        assert classify_failure(error_message="Connection timed out") == FailureReason.TIMEOUT

    def test_deadline_exceeded_message(self):
        assert classify_failure(error_message="deadline exceeded") == FailureReason.TIMEOUT

    def test_etimedout_message(self):
        assert classify_failure(error_message="ETIMEDOUT") == FailureReason.TIMEOUT

    def test_econnreset_message(self):
        assert classify_failure(error_message="ECONNRESET") == FailureReason.TIMEOUT

    def test_connection_refused_message(self):
        assert classify_failure(error_message="Connection refused") == FailureReason.CONNECTION_ERROR

    def test_dns_resolution_message(self):
        assert classify_failure(error_message="DNS resolution failed") == FailureReason.CONNECTION_ERROR

    def test_unreachable_message(self):
        assert classify_failure(error_message="Host unreachable") == FailureReason.CONNECTION_ERROR

    def test_empty_message_is_none(self):
        assert classify_failure(error_message="") == FailureReason.NONE

    def test_normal_message_is_none(self):
        assert classify_failure(error_message="File not found in repository") == FailureReason.NONE


class TestClassifyPriority:
    """Status code takes precedence over error message."""

    def test_status_code_wins_over_message(self):
        # 429 status code wins even if message says "timeout"
        result = classify_failure(status_code=429, error_message="timeout")
        assert result == FailureReason.RATE_LIMITED

    def test_no_status_falls_to_message(self):
        result = classify_failure(status_code=0, error_message="rate limit exceeded")
        assert result == FailureReason.RATE_LIMITED


class TestFailureReasonEnum:
    """FailureReason enum values."""

    def test_all_values_are_strings(self):
        for reason in FailureReason:
            assert isinstance(reason.value, str)

    def test_none_is_default(self):
        from prove_agent.strategies.base import ExecutionResult
        result = ExecutionResult(conclusive=False)
        assert result.failure_reason == FailureReason.NONE
