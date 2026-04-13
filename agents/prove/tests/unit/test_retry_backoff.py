"""Tests for retry with exponential backoff + jitter."""

import asyncio

import httpx
import pytest

from prove_agent.strategies.shared import _is_retryable, retry_with_backoff


class TestIsRetryable:
    """Retryable exception detection."""

    def test_timeout_is_retryable(self):
        exc = httpx.TimeoutException("timed out")
        assert _is_retryable(exc) is True

    def test_connect_error_is_retryable(self):
        exc = httpx.ConnectError("connection refused")
        assert _is_retryable(exc) is True

    def test_generic_exception_not_retryable(self):
        exc = ValueError("bad value")
        assert _is_retryable(exc) is False

    def test_http_status_error_not_retryable(self):
        request = httpx.Request("GET", "http://example.com")
        response = httpx.Response(404, request=request)
        exc = httpx.HTTPStatusError("not found", request=request, response=response)
        assert _is_retryable(exc) is False


class TestRetryWithBackoff:
    """retry_with_backoff() function."""

    @pytest.mark.asyncio
    async def test_returns_on_first_success(self):
        call_count = 0

        async def succeed():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await retry_with_backoff(succeed, attempts=3)
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_timeout(self):
        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.TimeoutException("timed out")
            return "recovered"

        result = await retry_with_backoff(
            fail_then_succeed, attempts=3, min_delay=0.01, max_delay=0.02,
        )
        assert result == "recovered"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retries_on_connect_error(self):
        call_count = 0

        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise httpx.ConnectError("refused")
            return "connected"

        result = await retry_with_backoff(
            fail_then_succeed, attempts=3, min_delay=0.01,
        )
        assert result == "connected"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts(self):
        call_count = 0

        async def always_fail():
            nonlocal call_count
            call_count += 1
            raise httpx.TimeoutException("timed out")

        with pytest.raises(httpx.TimeoutException):
            await retry_with_backoff(
                always_fail, attempts=3, min_delay=0.01, max_delay=0.02,
            )
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_raises_immediately(self):
        call_count = 0

        async def bad_request():
            nonlocal call_count
            call_count += 1
            raise ValueError("bad input")

        with pytest.raises(ValueError):
            await retry_with_backoff(bad_request, attempts=3)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_delay_increases_exponentially(self):
        """Verify delays grow with each attempt (timing test)."""
        delays = []
        call_count = 0

        async def fail_with_timing():
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                delays.append(asyncio.get_event_loop().time())
            if call_count < 3:
                raise httpx.TimeoutException("timed out")
            return "ok"

        start = asyncio.get_event_loop().time()
        await retry_with_backoff(
            fail_with_timing, attempts=3, min_delay=0.05, max_delay=1.0, jitter=0,
        )
        assert call_count == 3
        assert len(delays) == 2
        # First retry delay ~0.05s, second ~0.10s (2x exponential)
        delay1 = delays[0] - start
        delay2 = delays[1] - delays[0]
        assert delay1 >= 0.03  # Allow some timing slack
        assert delay2 >= delay1 * 1.2  # Second delay should be larger
