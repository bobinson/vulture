"""Tests for shared.llm.errors, shared.llm.cooldown, and shared.llm.loop_detector modules."""

import asyncio
import time
from unittest.mock import patch

import pytest

from shared.llm.errors import (
    LLMErrorKind, RETRYABLE_KINDS, classify_llm_error, retry_llm_call,
    _is_transient_skill_error, retry_skill,
)
from shared.llm.cooldown import CooldownManager
from shared.llm.loop_detector import LoopAction, LoopDetector, hash_result, _signature
from shared.llm.loop_guard import LoopDetectedError, create_loop_guard_hooks


# ---------------------------------------------------------------------------
# 1. Tests for shared.llm.errors — classify_llm_error
# ---------------------------------------------------------------------------

class TestClassifyLLMError:
    """Tests for classify_llm_error exception classification."""

    # -- Rate limited --

    def test_rate_limit_429(self):
        exc = Exception("HTTP 429 Too Many Requests")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED

    def test_rate_limit_phrase(self):
        exc = Exception("rate limit exceeded for this model")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED

    def test_rate_limit_quota(self):
        exc = Exception("You have exceeded your quota")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED

    def test_rate_limit_too_many_requests(self):
        exc = Exception("too many requests, please slow down")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED

    def test_rate_limit_throttle(self):
        exc = Exception("Request throttled by server")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED

    def test_rate_limit_resource_exhausted(self):
        exc = Exception("resource exhausted: tokens per minute")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED

    # -- Auth errors --

    def test_auth_401(self):
        exc = Exception("HTTP 401 Unauthorized")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_403(self):
        exc = Exception("HTTP 403 Forbidden")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_unauthorized(self):
        exc = Exception("Unauthorized: check your API key")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_invalid_api_key(self):
        exc = Exception("invalid api key provided")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_invalid_token(self):
        exc = Exception("invalid token: expired or revoked")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_forbidden(self):
        exc = Exception("forbidden: insufficient permissions")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_authentication_failed(self):
        exc = Exception("authentication failed for user")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_access_denied(self):
        exc = Exception("access denied to resource")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    def test_auth_no_credentials(self):
        exc = Exception("no credentials found in environment")
        assert classify_llm_error(exc) == LLMErrorKind.AUTH_ERROR

    # -- Context overflow --

    def test_ctx_context_length(self):
        exc = Exception("context length exceeded: 128000 tokens")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_maximum_context(self):
        exc = Exception("maximum context window is 32768")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_token_limit(self):
        exc = Exception("token limit reached")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_max_tokens(self):
        exc = Exception("max tokens exceeded for this model")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_prompt_too_long(self):
        exc = Exception("prompt too long for model context")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_maximum_length(self):
        exc = Exception("maximum length exceeded")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_gemini_payload_size_exceeds(self):
        exc = Exception("request.payload.size.exceeds the limit")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    def test_ctx_gemini_payload_too_large(self):
        exc = Exception("payload.too.large for model")
        assert classify_llm_error(exc) == LLMErrorKind.CONTEXT_OVERFLOW

    # -- Timeout --

    def test_timeout_word(self):
        exc = Exception("Request timeout after 30s")
        assert classify_llm_error(exc) == LLMErrorKind.TIMEOUT

    def test_timeout_timed_out(self):
        exc = Exception("Connection timed out to endpoint")
        assert classify_llm_error(exc) == LLMErrorKind.TIMEOUT

    def test_timeout_deadline(self):
        exc = Exception("deadline exceeded waiting for response")
        assert classify_llm_error(exc) == LLMErrorKind.TIMEOUT

    def test_timeout_etimedout(self):
        exc = TimeoutError("ETIMEDOUT")
        assert classify_llm_error(exc) == LLMErrorKind.TIMEOUT

    def test_timeout_econnreset(self):
        exc = Exception("ECONNRESET during request")
        assert classify_llm_error(exc) == LLMErrorKind.TIMEOUT

    # -- Server errors --

    def test_server_500(self):
        exc = Exception("HTTP 500 Internal Server Error")
        assert classify_llm_error(exc) == LLMErrorKind.SERVER_ERROR

    def test_server_502(self):
        exc = Exception("502 Bad Gateway from upstream")
        assert classify_llm_error(exc) == LLMErrorKind.SERVER_ERROR

    def test_server_503(self):
        exc = Exception("503 Service Unavailable")
        assert classify_llm_error(exc) == LLMErrorKind.SERVER_ERROR

    def test_server_504_plain(self):
        """504 without 'Timeout' in message classified as server error."""
        exc = Exception("HTTP 504 from upstream proxy")
        assert classify_llm_error(exc) == LLMErrorKind.SERVER_ERROR

    def test_server_504_with_timeout_matches_timeout_first(self):
        """504 Gateway Timeout contains 'Timeout' which matches timeout regex first."""
        exc = Exception("504 Gateway Timeout from proxy")
        assert classify_llm_error(exc) == LLMErrorKind.TIMEOUT

    def test_server_internal_server_error(self):
        exc = Exception("internal server error occurred")
        assert classify_llm_error(exc) == LLMErrorKind.SERVER_ERROR

    def test_server_bad_gateway(self):
        exc = Exception("bad gateway: upstream unresponsive")
        assert classify_llm_error(exc) == LLMErrorKind.SERVER_ERROR

    # -- Connection errors --

    def test_conn_refused(self):
        exc = ConnectionRefusedError("Connection refused on port 8080")
        assert classify_llm_error(exc) == LLMErrorKind.CONNECTION_ERROR

    def test_conn_dns(self):
        exc = Exception("dns resolution failed for api.openai.com")
        assert classify_llm_error(exc) == LLMErrorKind.CONNECTION_ERROR

    def test_conn_resolve(self):
        exc = Exception("Could not resolve host name")
        assert classify_llm_error(exc) == LLMErrorKind.CONNECTION_ERROR

    def test_conn_unreachable(self):
        exc = Exception("Host unreachable: 10.0.0.1")
        assert classify_llm_error(exc) == LLMErrorKind.CONNECTION_ERROR

    def test_conn_econnrefused(self):
        exc = Exception("ECONNREFUSED on localhost:11434")
        assert classify_llm_error(exc) == LLMErrorKind.CONNECTION_ERROR

    # -- Unknown --

    def test_unknown_generic(self):
        exc = Exception("something totally unexpected happened")
        assert classify_llm_error(exc) == LLMErrorKind.UNKNOWN

    def test_unknown_empty_message(self):
        exc = Exception("")
        assert classify_llm_error(exc) == LLMErrorKind.UNKNOWN

    def test_unknown_value_error(self):
        exc = ValueError("bad value")
        assert classify_llm_error(exc) == LLMErrorKind.UNKNOWN

    # -- Priority: rate_limit checked before auth (429 contains digits that might match) --

    def test_classification_priority_rate_limit_over_server(self):
        """429 matches rate_limit regex before server error regex."""
        exc = Exception("429")
        assert classify_llm_error(exc) == LLMErrorKind.RATE_LIMITED


class TestRetryableKinds:
    """Verify which error kinds are retryable."""

    def test_retryable_set(self):
        assert LLMErrorKind.RATE_LIMITED in RETRYABLE_KINDS
        assert LLMErrorKind.TIMEOUT in RETRYABLE_KINDS
        assert LLMErrorKind.SERVER_ERROR in RETRYABLE_KINDS
        assert LLMErrorKind.CONNECTION_ERROR in RETRYABLE_KINDS

    def test_non_retryable(self):
        assert LLMErrorKind.AUTH_ERROR not in RETRYABLE_KINDS
        assert LLMErrorKind.CONTEXT_OVERFLOW not in RETRYABLE_KINDS
        assert LLMErrorKind.INVALID_RESPONSE not in RETRYABLE_KINDS
        assert LLMErrorKind.UNKNOWN not in RETRYABLE_KINDS


# ---------------------------------------------------------------------------
# 2. Tests for shared.llm.errors — retry_llm_call
# ---------------------------------------------------------------------------

class TestRetryLLMCall:
    """Tests for the async retry_llm_call function."""

    def test_succeeds_on_first_try(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = asyncio.run(retry_llm_call(factory, max_attempts=3, base_delay=0.01))
        assert result == "ok"
        assert call_count == 1

    def test_retries_transient_then_succeeds(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("HTTP 500 Internal Server Error")
            return "recovered"

        result = asyncio.run(
            retry_llm_call(factory, max_attempts=3, base_delay=0.01, max_delay=0.05)
        )
        assert result == "recovered"
        assert call_count == 3

    def test_raises_immediately_on_non_retryable(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            raise Exception("HTTP 401 Unauthorized")

        with pytest.raises(Exception, match="401 Unauthorized"):
            asyncio.run(retry_llm_call(factory, max_attempts=5, base_delay=0.01))
        # Non-retryable error should not be retried at all
        assert call_count == 1

    def test_raises_auth_error_immediately(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            raise Exception("invalid api key provided")

        with pytest.raises(Exception, match="invalid api key"):
            asyncio.run(retry_llm_call(factory, max_attempts=3, base_delay=0.01))
        assert call_count == 1

    def test_raises_context_overflow_immediately(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            raise Exception("context length exceeded: 128000")

        with pytest.raises(Exception, match="context length"):
            asyncio.run(retry_llm_call(factory, max_attempts=3, base_delay=0.01))
        assert call_count == 1

    def test_raises_after_max_attempts_exhausted(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            raise Exception("Connection refused on localhost")

        with pytest.raises(Exception, match="Connection refused"):
            asyncio.run(
                retry_llm_call(factory, max_attempts=3, base_delay=0.01, max_delay=0.02)
            )
        assert call_count == 3

    def test_max_attempts_exhausted_rate_limited(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            raise Exception("rate limit exceeded")

        with pytest.raises(Exception, match="rate limit"):
            asyncio.run(
                retry_llm_call(factory, max_attempts=2, base_delay=0.01, max_delay=0.02)
            )
        assert call_count == 2

    def test_returns_tuple(self):
        """retry_llm_call return type annotation is tuple; verify tuple works."""

        async def factory():
            return ("result", 42)

        result = asyncio.run(retry_llm_call(factory, max_attempts=1))
        assert result == ("result", 42)

    def test_retry_with_timeout_error(self):
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Request timeout after 30s")
            return "done"

        result = asyncio.run(
            retry_llm_call(factory, max_attempts=3, base_delay=0.01, max_delay=0.02)
        )
        assert result == "done"
        assert call_count == 2

    def test_jitter_does_not_cause_negative_delay(self):
        """Even with max jitter, delay should always be >= 0.1."""
        call_count = 0

        async def factory():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("502 Bad Gateway")
            return "ok"

        # Use large jitter to exercise the max(0.1, ...) guard
        result = asyncio.run(
            retry_llm_call(factory, max_attempts=3, base_delay=0.01, max_delay=0.05, jitter=0.99)
        )
        assert result == "ok"


# ---------------------------------------------------------------------------
# 3. Tests for shared.llm.cooldown — CooldownManager
# ---------------------------------------------------------------------------

class TestCooldownManager:
    """Tests for the CooldownManager class."""

    def test_new_model_is_available(self):
        mgr = CooldownManager()
        assert mgr.is_available("gpt-4o") is True

    def test_new_model_zero_cooldown_remaining(self):
        mgr = CooldownManager()
        assert mgr.get_cooldown_remaining("gpt-4o") == 0.0

    def test_record_success_resets_failures(self):
        mgr = CooldownManager(failure_threshold=3, base_cooldown=60.0)
        # Record 2 failures (below threshold)
        mgr.record_failure("gpt-4o")
        mgr.record_failure("gpt-4o")
        # Record success resets
        mgr.record_success("gpt-4o")
        # Now 3 more failures needed to trigger cooldown
        mgr.record_failure("gpt-4o")
        mgr.record_failure("gpt-4o")
        assert mgr.is_available("gpt-4o") is True
        # Third failure triggers cooldown
        mgr.record_failure("gpt-4o")
        assert mgr.is_available("gpt-4o") is False

    def test_threshold_failures_triggers_cooldown(self):
        mgr = CooldownManager(failure_threshold=3, base_cooldown=60.0)
        mgr.record_failure("model-a")
        mgr.record_failure("model-a")
        # Still available after 2 failures
        assert mgr.is_available("model-a") is True
        assert mgr.get_cooldown_remaining("model-a") == 0.0
        # Third failure triggers cooldown
        mgr.record_failure("model-a")
        assert mgr.is_available("model-a") is False
        assert mgr.get_cooldown_remaining("model-a") > 0.0

    def test_cooldown_remaining_positive_during_cooldown(self):
        mgr = CooldownManager(failure_threshold=2, base_cooldown=120.0)
        mgr.record_failure("model-x")
        mgr.record_failure("model-x")
        remaining = mgr.get_cooldown_remaining("model-x")
        assert remaining > 0.0
        # Should be close to 120 seconds (base cooldown for first cooldown)
        assert remaining <= 120.0

    def test_different_models_independent(self):
        mgr = CooldownManager(failure_threshold=2, base_cooldown=60.0)
        mgr.record_failure("model-a")
        mgr.record_failure("model-a")
        # model-a in cooldown
        assert mgr.is_available("model-a") is False
        # model-b unaffected
        assert mgr.is_available("model-b") is True

    def test_reset_clears_all_state(self):
        mgr = CooldownManager(failure_threshold=2, base_cooldown=60.0)
        mgr.record_failure("model-a")
        mgr.record_failure("model-a")
        mgr.record_failure("model-b")
        mgr.record_failure("model-b")
        assert mgr.is_available("model-a") is False
        assert mgr.is_available("model-b") is False
        # Reset all
        mgr.reset()
        assert mgr.is_available("model-a") is True
        assert mgr.is_available("model-b") is True
        assert mgr.get_cooldown_remaining("model-a") == 0.0
        assert mgr.get_cooldown_remaining("model-b") == 0.0

    def test_reset_specific_model(self):
        mgr = CooldownManager(failure_threshold=2, base_cooldown=60.0)
        mgr.record_failure("model-a")
        mgr.record_failure("model-a")
        mgr.record_failure("model-b")
        mgr.record_failure("model-b")
        assert mgr.is_available("model-a") is False
        assert mgr.is_available("model-b") is False
        # Reset only model-a
        mgr.reset("model-a")
        assert mgr.is_available("model-a") is True
        assert mgr.is_available("model-b") is False

    def test_exponential_cooldown_on_repeated_failures(self):
        """Additional failures beyond threshold increase cooldown exponentially."""
        mgr = CooldownManager(failure_threshold=2, base_cooldown=10.0)
        # 2 failures -> cooldown = 10 * 2^0 = 10s
        mgr.record_failure("m")
        mgr.record_failure("m")
        r1 = mgr.get_cooldown_remaining("m")
        assert 0 < r1 <= 10.0

        # 3rd failure -> cooldown = 10 * 2^1 = 20s
        mgr.record_failure("m")
        r2 = mgr.get_cooldown_remaining("m")
        assert r2 > r1  # should be longer

    def test_cooldown_capped_at_max(self):
        """Cooldown should not exceed _MAX_COOLDOWN (300s)."""
        mgr = CooldownManager(failure_threshold=1, base_cooldown=200.0)
        # 1 failure -> cooldown = 200 * 2^0 = 200
        mgr.record_failure("m")
        r1 = mgr.get_cooldown_remaining("m")
        assert r1 <= 200.0
        # 2nd failure -> cooldown = min(200 * 2^1, 300) = 300
        mgr.record_failure("m")
        r2 = mgr.get_cooldown_remaining("m")
        assert r2 <= 300.0

    def test_record_success_clears_cooldown(self):
        mgr = CooldownManager(failure_threshold=2, base_cooldown=60.0)
        mgr.record_failure("m")
        mgr.record_failure("m")
        assert mgr.is_available("m") is False
        mgr.record_success("m")
        assert mgr.is_available("m") is True
        assert mgr.get_cooldown_remaining("m") == 0.0

    def test_is_available_after_cooldown_expires(self):
        """Model becomes available once cooldown expires (simulated via time.monotonic mock)."""
        mgr = CooldownManager(failure_threshold=1, base_cooldown=5.0)
        mgr.record_failure("m")
        assert mgr.is_available("m") is False

        # Fast-forward time past cooldown by patching time.monotonic
        future = time.monotonic() + 10.0
        with patch("time.monotonic", return_value=future):
            assert mgr.is_available("m") is True
            assert mgr.get_cooldown_remaining("m") == 0.0

    def test_failure_threshold_one(self):
        mgr = CooldownManager(failure_threshold=1, base_cooldown=30.0)
        assert mgr.is_available("x") is True
        mgr.record_failure("x")
        assert mgr.is_available("x") is False

    def test_reset_nonexistent_model(self):
        """Resetting a model that was never tracked should not raise."""
        mgr = CooldownManager()
        mgr.reset("nonexistent")  # Should not raise

    def test_auth_error_longer_cooldown(self):
        """AUTH_ERROR should trigger 1-hour cooldown cap."""
        mgr = CooldownManager(failure_threshold=1, base_cooldown=3600.0)
        mgr.record_failure("m", error_kind="auth_error")
        remaining = mgr.get_cooldown_remaining("m")
        assert remaining > 0.0
        # Auth cooldown capped at 3600s
        assert remaining <= 3600.0

    def test_rate_limited_cooldown_cap(self):
        """RATE_LIMITED should cap at 10 minutes (600s)."""
        mgr = CooldownManager(failure_threshold=1, base_cooldown=500.0)
        mgr.record_failure("m", error_kind="rate_limited")
        remaining = mgr.get_cooldown_remaining("m")
        assert remaining > 0.0
        assert remaining <= 600.0

    def test_default_error_kind_uses_standard_max(self):
        """Default error_kind uses 300s max cooldown."""
        mgr = CooldownManager(failure_threshold=1, base_cooldown=200.0)
        mgr.record_failure("m")
        remaining = mgr.get_cooldown_remaining("m")
        assert remaining > 0.0
        assert remaining <= 300.0


# ---------------------------------------------------------------------------
# 4. Tests for shared.llm.loop_detector — LoopDetector
# ---------------------------------------------------------------------------

class TestLoopDetector:
    """Tests for the LoopDetector class (v2 API with LoopAction enum)."""

    # -- LoopAction enum values --

    def test_loop_action_enum_values(self):
        assert LoopAction.CONTINUE.value == "continue"
        assert LoopAction.WARN.value == "warn"
        assert LoopAction.KILL.value == "kill"

    # -- generic_repeat pattern --

    def test_generic_repeat_continue_on_varied_calls(self):
        """Varied tool calls should all return CONTINUE."""
        det = LoopDetector(window=40, warn_threshold=10, kill_threshold=20)
        assert det.record("read_file", {"path": "a.py"}) == LoopAction.CONTINUE
        assert det.record("read_file", {"path": "b.py"}) == LoopAction.CONTINUE
        assert det.record("write_file", {"path": "c.py"}) == LoopAction.CONTINUE
        assert det.record("search", {"query": "hello"}) == LoopAction.CONTINUE

    def test_generic_repeat_warn_at_warn_threshold(self):
        """WARN returned when same call reaches warn_threshold (10)."""
        det = LoopDetector(window=40, warn_threshold=10, kill_threshold=20, global_limit=100)
        for i in range(9):
            action = det.record("read_file", {"path": "a.py"})
            assert action == LoopAction.CONTINUE, f"call {i+1} should be CONTINUE"
        action = det.record("read_file", {"path": "a.py"})
        assert action == LoopAction.WARN

    def test_generic_repeat_kill_at_kill_threshold(self):
        """KILL returned when same call reaches kill_threshold (20)."""
        det = LoopDetector(window=40, warn_threshold=10, kill_threshold=20, global_limit=100)
        for i in range(19):
            det.record("read_file", {"path": "a.py"})
        action = det.record("read_file", {"path": "a.py"})
        assert action == LoopAction.KILL

    # -- ping_pong pattern --

    def test_ping_pong_abab_triggers_kill(self):
        """A->B->A->B alternating pattern triggers KILL."""
        det = LoopDetector(window=40, warn_threshold=50, kill_threshold=100, global_limit=200)
        det.record("tool_a")
        det.record("tool_b")
        det.record("tool_a")
        action = det.record("tool_b")  # completes A->B->A->B
        assert action == LoopAction.KILL

    def test_ping_pong_aabb_does_not_trigger(self):
        """A->A->B->B is NOT a ping_pong pattern (no alternation)."""
        det = LoopDetector(window=40, warn_threshold=50, kill_threshold=100, global_limit=200)
        det.record("tool_a")
        det.record("tool_a")
        det.record("tool_b")
        action = det.record("tool_b")
        assert action == LoopAction.CONTINUE

    # -- global circuit breaker --

    def test_circuit_breaker_kills_after_global_limit(self):
        """KILL returned once total_calls reaches global_limit."""
        det = LoopDetector(window=40, warn_threshold=50, kill_threshold=100, global_limit=5)
        for i in range(4):
            action = det.record(f"tool_{i}")
            assert action == LoopAction.CONTINUE, f"call {i+1} should be CONTINUE"
        action = det.record("tool_final")
        assert action == LoopAction.KILL

    def test_global_call_limit_default_is_100(self):
        """Default GLOBAL_CALL_LIMIT should be 100 (configurable via env)."""
        from shared.llm.loop_detector import GLOBAL_CALL_LIMIT
        # Default constructor uses GLOBAL_CALL_LIMIT
        det = LoopDetector()
        assert det._global_limit == GLOBAL_CALL_LIMIT

    # -- result_hash: same args + different result = different signatures --

    def test_result_hash_different_results_are_different(self):
        """Same tool+args but different result_hash should produce different signatures."""
        det = LoopDetector(window=40, warn_threshold=2, kill_threshold=5, global_limit=100)
        det.record("read_file", {"path": "a.py"}, result_hash="aaa")
        action = det.record("read_file", {"path": "a.py"}, result_hash="bbb")
        assert action == LoopAction.CONTINUE
        # Each signature has count=1, so loop_count should be 1
        assert det.loop_count == 1

    def test_result_hash_same_results_are_same(self):
        """Same tool+args+result_hash should count as the same signature."""
        det = LoopDetector(window=40, warn_threshold=2, kill_threshold=5, global_limit=100)
        det.record("read_file", {"path": "a.py"}, result_hash="aaa")
        action = det.record("read_file", {"path": "a.py"}, result_hash="aaa")
        assert action == LoopAction.WARN
        assert det.loop_count == 2

    # -- hash_result utility function --

    def test_hash_result_string(self):
        """hash_result produces a 12-char hex string from a string input."""
        h = hash_result("hello world")
        assert isinstance(h, str)
        assert len(h) == 12
        # Deterministic
        assert hash_result("hello world") == h

    def test_hash_result_bytes(self):
        """hash_result works with bytes input."""
        h = hash_result(b"hello world")
        assert isinstance(h, str)
        assert len(h) == 12

    def test_hash_result_different_inputs_differ(self):
        assert hash_result("abc") != hash_result("xyz")

    # -- total_calls property --

    def test_total_calls_increments(self):
        det = LoopDetector()
        assert det.total_calls == 0
        det.record("a")
        assert det.total_calls == 1
        det.record("b")
        assert det.total_calls == 2
        det.record("a")
        assert det.total_calls == 3

    # -- reset clears total_calls --

    def test_reset_clears_total_calls(self):
        det = LoopDetector()
        det.record("a")
        det.record("b")
        assert det.total_calls == 2
        assert det.loop_count > 0
        det.reset()
        assert det.total_calls == 0
        assert det.loop_count == 0
        # After reset, calls don't carry over
        action = det.record("a")
        assert action == LoopAction.CONTINUE
        assert det.total_calls == 1

    # -- window sliding --

    def test_window_sliding_old_entries_expire(self):
        """When the window is full, oldest entries are evicted and counts updated."""
        det = LoopDetector(window=4, warn_threshold=3, kill_threshold=5, global_limit=100)
        # Fill window: A, A, B, B
        det.record("A")
        det.record("A")
        det.record("B")
        det.record("B")
        assert det.loop_count == 2
        # Add another B -> oldest A evicted -> [A, B, B, B], B=3 >= warn
        action = det.record("B")
        assert action == LoopAction.WARN
        # Add C -> oldest A evicted -> [B, B, B, C]
        det.record("C")
        # A fully evicted; add A twice
        det.record("A")  # [B, B, C, A]
        det.record("A")  # [B, C, A, A]
        action = det.record("A")  # [C, A, A, A] -> A=3 >= warn
        assert action == LoopAction.WARN

    # -- arg order doesn't matter --

    def test_arg_order_does_not_matter(self):
        """Args with same keys/values in different order produce same signature."""
        det = LoopDetector(window=40, warn_threshold=2, kill_threshold=5, global_limit=100)
        det.record("tool", {"b": 2, "a": 1})
        action = det.record("tool", {"a": 1, "b": 2})
        assert action == LoopAction.WARN

    # -- loop_count property --

    def test_loop_count_empty(self):
        det = LoopDetector()
        assert det.loop_count == 0

    def test_loop_count_reflects_highest_count(self):
        det = LoopDetector(window=40, warn_threshold=50, kill_threshold=100, global_limit=200)
        det.record("A")
        det.record("A")
        det.record("A")
        det.record("B")
        det.record("B")
        # A=3, B=2 -> max is 3
        assert det.loop_count == 3

    # -- _signature module-level function --

    def test_signature_no_args_no_result(self):
        """No args and no result_hash produces the simple format."""
        sig = _signature("my_tool", None, None)
        assert sig == "my_tool:()"

    def test_signature_with_args_produces_hash(self):
        """Args present -> MD5 hash signature."""
        sig = _signature("tool", {"a": 1}, None)
        assert sig != "tool:()"
        # Deterministic
        assert _signature("tool", {"a": 1}, None) == sig

    def test_signature_with_result_hash(self):
        """result_hash changes the signature."""
        sig_no_rh = _signature("tool", {"a": 1}, None)
        sig_with_rh = _signature("tool", {"a": 1}, "abc123")
        assert sig_no_rh != sig_with_rh

    # -- edge cases --

    def test_no_args_signature_repeat(self):
        det = LoopDetector(window=40, warn_threshold=2, kill_threshold=5, global_limit=100)
        action = det.record("health_check")
        assert action == LoopAction.CONTINUE
        action = det.record("health_check")
        assert action == LoopAction.WARN

    def test_none_args_same_as_no_args(self):
        det = LoopDetector(window=40, warn_threshold=2, kill_threshold=5, global_limit=100)
        det.record("ping", None)
        action = det.record("ping")
        assert action == LoopAction.WARN

    def test_empty_dict_args_same_as_no_args(self):
        """Empty dict is falsy, so signature should match no-args."""
        det = LoopDetector(window=40, warn_threshold=2, kill_threshold=5, global_limit=100)
        det.record("ping", {})
        action = det.record("ping", None)
        assert action == LoopAction.WARN

    def test_different_args_are_different_signatures(self):
        det = LoopDetector(window=40, warn_threshold=3, kill_threshold=5, global_limit=100)
        det.record("read_file", {"path": "a.py"})
        det.record("read_file", {"path": "b.py"})
        det.record("read_file", {"path": "c.py"})
        assert det.loop_count == 1

    def test_different_tool_names_are_different(self):
        det = LoopDetector(window=40, warn_threshold=3, kill_threshold=5, global_limit=100)
        det.record("read_file", {"path": "a.py"})
        det.record("write_file", {"path": "a.py"})
        det.record("search_file", {"path": "a.py"})
        assert det.loop_count == 1


# ---------------------------------------------------------------------------
# 5. Tests for shared.llm.loop_guard — LoopGuard
# ---------------------------------------------------------------------------

class TestLoopGuard:
    """Tests for LoopDetectedError and create_loop_guard_hooks."""

    def test_loop_detected_error_message(self):
        err = LoopDetectedError("stuck in a loop", total_calls=42)
        assert str(err) == "stuck in a loop"
        assert err.total_calls == 42

    def test_loop_detected_error_default_total_calls(self):
        err = LoopDetectedError("loop")
        assert err.total_calls == 0

    def test_loop_detected_error_is_exception(self):
        err = LoopDetectedError("boom", total_calls=10)
        assert isinstance(err, Exception)
        with pytest.raises(LoopDetectedError, match="boom"):
            raise err

    def test_create_loop_guard_hooks_without_sdk(self):
        """When the agents SDK is not importable, returns (None, detector)."""
        hooks, detector = create_loop_guard_hooks()
        # In test environment, agents SDK is likely not installed
        # Either way, detector should be a LoopDetector
        assert isinstance(detector, LoopDetector)

    def test_create_loop_guard_hooks_with_custom_detector(self):
        """Passing a pre-configured detector should use it, not create a new one."""
        custom = LoopDetector(window=5, warn_threshold=2, kill_threshold=3, global_limit=10)
        hooks, detector = create_loop_guard_hooks(detector=custom)
        assert detector is custom

    def test_create_loop_guard_hooks_returns_tuple(self):
        """Return value is always a 2-tuple."""
        result = create_loop_guard_hooks()
        assert isinstance(result, tuple)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# 6. Tests for shared.llm.errors — _is_transient_skill_error
# ---------------------------------------------------------------------------

class TestIsTransientSkillError:
    """Tests for _is_transient_skill_error classification."""

    def test_permission_error_is_transient(self):
        assert _is_transient_skill_error(PermissionError("File locked")) is True

    def test_timeout_error_is_transient(self):
        assert _is_transient_skill_error(TimeoutError("Timed out")) is True

    def test_oserror_eagain_is_transient(self):
        import errno
        exc = OSError(errno.EAGAIN, "Resource temporarily unavailable")
        assert _is_transient_skill_error(exc) is True

    def test_oserror_ebusy_is_transient(self):
        import errno
        exc = OSError(errno.EBUSY, "Device or resource busy")
        assert _is_transient_skill_error(exc) is True

    def test_value_error_is_not_transient(self):
        assert _is_transient_skill_error(ValueError("bad value")) is False

    def test_runtime_error_is_not_transient(self):
        assert _is_transient_skill_error(RuntimeError("crash")) is False


# ---------------------------------------------------------------------------
# 7. Tests for shared.llm.errors — retry_skill
# ---------------------------------------------------------------------------

class TestRetrySkill:
    """Tests for the synchronous retry_skill function."""

    def test_succeeds_on_first_try(self):
        call_count = 0

        def fn(path):
            nonlocal call_count
            call_count += 1
            return {"findings": []}

        result = retry_skill(fn, "/src", max_attempts=2, base_delay=0.01)
        assert result == {"findings": []}
        assert call_count == 1

    def test_retries_transient_then_succeeds(self):
        call_count = 0

        def fn(path):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise PermissionError("File locked")
            return {"findings": [{"title": "Found"}]}

        result = retry_skill(fn, "/src", max_attempts=2, base_delay=0.01)
        assert result == {"findings": [{"title": "Found"}]}
        assert call_count == 2

    def test_permanent_error_not_retried(self):
        call_count = 0

        def fn(path):
            nonlocal call_count
            call_count += 1
            raise ValueError("Invalid config")

        with pytest.raises(ValueError, match="Invalid config"):
            retry_skill(fn, "/src", max_attempts=3, base_delay=0.01)
        assert call_count == 1

    def test_transient_exhausts_retries(self):
        call_count = 0

        def fn(path):
            nonlocal call_count
            call_count += 1
            raise PermissionError("Always locked")

        with pytest.raises(PermissionError, match="Always locked"):
            retry_skill(fn, "/src", max_attempts=2, base_delay=0.01)
        assert call_count == 2

    def test_timeout_error_is_retried(self):
        call_count = 0

        def fn(path):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise TimeoutError("OS timeout")
            return {"findings": []}

        result = retry_skill(fn, "/src", max_attempts=2, base_delay=0.01)
        assert result == {"findings": []}
        assert call_count == 2
