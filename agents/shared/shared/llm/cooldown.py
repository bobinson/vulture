"""Model cooldown manager.

Tracks LLM model failures and enforces cooldown periods to avoid hammering
failing models. Based on production experience with model rotation patterns.

NOTE: Cooldown state is per-process. Multiple agent services sharing the same
API key will have independent cooldown clocks. A future improvement could use
shared state (Redis, filesystem) for cross-process coordination.
"""

from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

_DEFAULT_COOLDOWN = 60.0    # seconds
_MAX_COOLDOWN = 300.0       # 5 minutes (default)
_AUTH_COOLDOWN = 3600.0     # 1 hour for auth errors (daily quota, revoked keys)
_RATE_LIMIT_MAX = 600.0     # 10 minutes max for rate limit errors
_FAILURE_THRESHOLD = 3      # failures before cooldown


class CooldownManager:
    """Thread-safe manager that tracks model failures and enforces cooldown.

    After ``failure_threshold`` consecutive failures for a model, the model
    is placed on cooldown for an exponentially increasing duration.

    The cooldown duration cap varies by error kind:
    - ``AUTH_ERROR``: 1-hour fixed cooldown (API key revoked / daily quota).
    - ``RATE_LIMITED``: 10-minute max (back-pressure from provider).
    - Default: 5-minute max (transient failures).
    """

    _warned_per_process: bool = False  # class-level: shared across instances

    __slots__ = (
        "_failures", "_cooldown_until", "_lock", "_failure_threshold",
        "_base_cooldown",
    )

    def __init__(
        self,
        failure_threshold: int = _FAILURE_THRESHOLD,
        base_cooldown: float = _DEFAULT_COOLDOWN,
    ) -> None:
        self._failures: dict[str, int] = {}
        self._cooldown_until: dict[str, float] = {}
        self._lock = threading.Lock()
        self._failure_threshold = failure_threshold
        self._base_cooldown = base_cooldown

    def is_available(self, model: str) -> bool:
        """Check if model is currently available (not in cooldown)."""
        with self._lock:
            until = self._cooldown_until.get(model, 0.0)
            now = time.monotonic()
            if now >= until:
                return True
            remaining = until - now
            logger.debug("model_cooldown model=%s remaining=%.1fs", model, remaining)
            return False

    def record_success(self, model: str) -> None:
        """Record a successful call, resetting failure count."""
        with self._lock:
            self._failures.pop(model, None)
            self._cooldown_until.pop(model, None)

    def record_failure(self, model: str, error_kind: str | None = None) -> None:
        """Record a failure. Triggers cooldown after threshold is reached.

        Args:
            model: The model identifier.
            error_kind: Optional LLMErrorKind value string (e.g. "auth_error",
                "rate_limited"). Adjusts cooldown ceiling based on error type.
        """
        with self._lock:
            count = self._failures.get(model, 0) + 1
            self._failures[model] = count
            if count >= self._failure_threshold:
                max_cd = _MAX_COOLDOWN
                if error_kind == "auth_error":
                    max_cd = _AUTH_COOLDOWN
                elif error_kind == "rate_limited":
                    max_cd = _RATE_LIMIT_MAX
                exponent = (count - self._failure_threshold)
                duration = min(self._base_cooldown * (2 ** exponent), max_cd)
                self._cooldown_until[model] = time.monotonic() + duration
                if not CooldownManager._warned_per_process:
                    logger.warning(
                        "cooldown_per_process_note: cooldown state is local to this process",
                    )
                    CooldownManager._warned_per_process = True
                logger.warning(
                    "model_cooldown_start model=%s failures=%d cooldown=%.0fs error_kind=%s",
                    model, count, duration, error_kind or "unknown",
                )

    def get_cooldown_remaining(self, model: str) -> float:
        """Return seconds remaining in cooldown, or 0.0 if available."""
        with self._lock:
            until = self._cooldown_until.get(model, 0.0)
            remaining = until - time.monotonic()
            return max(0.0, remaining)

    def reset(self, model: str | None = None) -> None:
        """Reset cooldown state for a model (or all models if None)."""
        with self._lock:
            if model is None:
                self._failures.clear()
                self._cooldown_until.clear()
            else:
                self._failures.pop(model, None)
                self._cooldown_until.pop(model, None)


# Module-level singleton for global cooldown tracking.
cooldown_manager = CooldownManager()
