"""LLM error classification and retry logic.

Based on production experience with error classification patterns. Categorizes LLM failures
into actionable types so callers can decide whether to retry, fall back, or abort.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import random
import re
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class LLMErrorKind(Enum):
    """Categorized LLM failure reasons."""
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    CONTEXT_OVERFLOW = "context_overflow"
    TIMEOUT = "timeout"
    SERVER_ERROR = "server_error"
    INVALID_RESPONSE = "invalid_response"
    CONNECTION_ERROR = "connection_error"
    UNKNOWN = "unknown"


# Errors worth retrying (transient failures).
RETRYABLE_KINDS = frozenset({
    LLMErrorKind.RATE_LIMITED,
    LLMErrorKind.TIMEOUT,
    LLMErrorKind.SERVER_ERROR,
    LLMErrorKind.CONNECTION_ERROR,
})

_RATE_LIMIT_RE = re.compile(
    r"(rate.?limit|429|too many requests|quota|resource.exhausted|throttl)",
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"(401|403|unauthorized|forbidden|invalid.?api.?key|invalid.?token|"
    r"authentication.failed|access.denied|no.credentials)",
    re.IGNORECASE,
)
_CTX_OVERFLOW_RE = re.compile(
    r"(context.length|token.limit|maximum.context|n_keep.*n_ctx|"
    r"max.tokens|context.window|prompt.{0,10}too.long|maximum.length|"
    r"request\.payload\.size\.exceeds|payload\.too\.large|"
    r"input.token.count.*exceeds|exceeds.the.maximum.number.of.tokens|"
    r"request_too_large)",
    re.IGNORECASE,
)
_TIMEOUT_RE = re.compile(
    r"(timeout|timed.out|deadline.exceeded|ETIMEDOUT|ECONNRESET)",
    re.IGNORECASE,
)
_SERVER_RE = re.compile(r"(500|502|503|504|529|internal.server.error|bad.gateway|overloaded)", re.IGNORECASE)
_CONN_RE = re.compile(r"(connect|dns|resolve|refused|unreachable|ECONNREFUSED)", re.IGNORECASE)


def classify_llm_error(exc: Exception) -> LLMErrorKind:
    """Classify an LLM exception into an actionable error kind.

    Args:
        exc: The exception raised by the LLM call.

    Returns:
        Categorized error kind for retry/fallback decisions.
    """
    msg = str(exc)
    if _RATE_LIMIT_RE.search(msg):
        return LLMErrorKind.RATE_LIMITED
    if _AUTH_RE.search(msg):
        return LLMErrorKind.AUTH_ERROR
    if _CTX_OVERFLOW_RE.search(msg):
        return LLMErrorKind.CONTEXT_OVERFLOW
    if _TIMEOUT_RE.search(msg):
        return LLMErrorKind.TIMEOUT
    if _SERVER_RE.search(msg):
        return LLMErrorKind.SERVER_ERROR
    if _CONN_RE.search(msg):
        return LLMErrorKind.CONNECTION_ERROR
    return LLMErrorKind.UNKNOWN


async def retry_llm_call(
    coro_factory: Callable[[], Awaitable[Any]],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: float = 0.5,
) -> Any:
    """Retry an async LLM call with exponential backoff on transient errors.

    Args:
        coro_factory: Zero-arg callable returning an awaitable.
        max_attempts: Maximum retry attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay cap.
        jitter: Random jitter factor (±jitter * delay).

    Returns:
        The result of the first successful call.

    Raises:
        The last exception if all attempts fail or error is non-retryable.
    """
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            kind = classify_llm_error(exc)
            logger.warning(
                "llm_call_failed attempt=%d/%d kind=%s error=%s",
                attempt + 1, max_attempts, kind.value, str(exc)[:200],
            )
            if kind not in RETRYABLE_KINDS or attempt >= max_attempts - 1:
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            offset = (random.random() * 2 - 1) * jitter  # noqa: S311
            delay = max(0.1, delay * (1 + offset))
            logger.info("llm_retry delay=%.1fs attempt=%d/%d", delay, attempt + 1, max_attempts)
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Skill-level retry (synchronous, for ThreadPoolExecutor)
# ---------------------------------------------------------------------------

_TRANSIENT_SKILL_ERRORS = (PermissionError, TimeoutError)

_TRANSIENT_ERRNOS = frozenset({
    errno.EAGAIN,
    errno.EBUSY,
    errno.ENOLCK,
})


def _is_transient_skill_error(exc: Exception) -> bool:
    """Return True if *exc* is a transient OS/filesystem error worth retrying.

    Matches PermissionError, TimeoutError, and OSError with EAGAIN/EBUSY/ENOLCK.
    """
    if isinstance(exc, _TRANSIENT_SKILL_ERRORS):
        return True
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in _TRANSIENT_ERRNOS:
        return True
    return False


def retry_skill(
    fn: Callable[..., Any],
    *args: Any,
    max_attempts: int = 2,
    base_delay: float = 0.5,
    jitter: float = 0.5,
) -> Any:
    """Retry a synchronous skill function on transient OS errors.

    Args:
        fn: The skill callable to execute.
        *args: Positional arguments forwarded to *fn*.
        max_attempts: Maximum number of attempts (default 2 = 1 retry).
        base_delay: Base delay in seconds between retries.
        jitter: Random jitter factor (±jitter * delay).

    Returns:
        The result of the first successful *fn* call.

    Raises:
        The last exception if all attempts fail or error is non-transient.
    """
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return fn(*args)
        except Exception as exc:
            last_exc = exc
            if not _is_transient_skill_error(exc) or attempt >= max_attempts - 1:
                raise
            delay = base_delay * (2 ** attempt)
            offset = (random.random() * 2 - 1) * jitter  # noqa: S311
            delay = max(0.05, delay * (1 + offset))
            logger.info(
                "skill_retry fn=%s delay=%.2fs attempt=%d/%d error=%s",
                getattr(fn, "__name__", fn), delay, attempt + 1, max_attempts,
                str(exc)[:200],
            )
            time.sleep(delay)
    raise last_exc  # type: ignore[misc]
