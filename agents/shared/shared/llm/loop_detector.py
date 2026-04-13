"""Tool loop detection for LLM agent interactions.

Detects when an LLM agent is stuck in repetitive tool call patterns
and signals for early termination. Inspired by production experience with loop detection.

Patterns detected:
- **generic_repeat**: Same tool call (+ result hash) repeated N times.
  Warn at 10, kill at 20.
- **ping_pong**: Alternating A→B→A→B oscillation (2 full cycles = kill).
- **global circuit breaker**: Total tool calls exceed hard limit (default 30).
"""

import enum
import hashlib
import logging
import os
from collections import deque

logger = logging.getLogger(__name__)

# Thresholds
WARN_THRESHOLD = 10
KILL_THRESHOLD = 20
PING_PONG_CYCLES = 2  # A→B→A→B = 2 full cycles (4 calls)
def _safe_int_env(name: str, default: int) -> int:
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


GLOBAL_CALL_LIMIT = _safe_int_env("VULTURE_LOOP_GLOBAL_LIMIT", 100)


class LoopAction(enum.Enum):
    """Action to take after recording a tool call."""

    CONTINUE = "continue"
    WARN = "warn"
    KILL = "kill"


class LoopDetector:
    """Detects repetitive tool call patterns in agent execution.

    Tracks three loop patterns simultaneously:
    1. generic_repeat — same (tool, args, result) hash repeated
    2. ping_pong — alternating A→B→A→B oscillation
    3. circuit_breaker — total call count exceeds hard limit

    A tool call signature includes the result hash so that identical calls
    returning different results are not flagged as loops.
    """

    __slots__ = (
        "_window", "_warn", "_kill", "_global_limit",
        "_history", "_counts", "_total_calls",
    )

    def __init__(
        self,
        window: int = 40,
        warn_threshold: int = WARN_THRESHOLD,
        kill_threshold: int = KILL_THRESHOLD,
        global_limit: int = GLOBAL_CALL_LIMIT,
    ) -> None:
        self._window = window
        self._warn = warn_threshold
        self._kill = kill_threshold
        self._global_limit = global_limit
        self._history: deque[str] = deque(maxlen=window)
        self._counts: dict[str, int] = {}
        self._total_calls = 0

    def record(
        self,
        tool_name: str,
        args: dict | None = None,
        result_hash: str | None = None,
    ) -> LoopAction:
        """Record a tool call and check for loop patterns.

        Args:
            tool_name: Name of the tool being called.
            args: Tool call arguments (optional).
            result_hash: Hash of the tool call result (optional).
                When provided, two calls with same args but different results
                produce different signatures.

        Returns:
            LoopAction indicating whether to continue, warn, or kill.
        """
        self._total_calls += 1
        sig = _signature(tool_name, args, result_hash)

        # Evict oldest from sliding window
        if len(self._history) == self._window:
            oldest = self._history[0]
            old_count = self._counts.get(oldest, 0)
            if old_count <= 1:
                self._counts.pop(oldest, None)
            else:
                self._counts[oldest] = old_count - 1

        self._history.append(sig)
        self._counts[sig] = self._counts.get(sig, 0) + 1
        count = self._counts[sig]

        # Check patterns in priority order: kill > warn

        # 1. Global circuit breaker
        if self._total_calls >= self._global_limit:
            logger.warning(
                "circuit_breaker total_calls=%d limit=%d",
                self._total_calls, self._global_limit,
            )
            return LoopAction.KILL

        # 2. generic_repeat kill
        if count >= self._kill:
            logger.warning(
                "generic_repeat_kill tool=%s count=%d",
                tool_name, count,
            )
            return LoopAction.KILL

        # 3. ping_pong detection
        if self._detect_ping_pong():
            logger.warning("ping_pong_detected last_tool=%s", tool_name)
            return LoopAction.KILL

        # 4. generic_repeat warn
        if count >= self._warn:
            logger.warning(
                "generic_repeat_warn tool=%s count=%d",
                tool_name, count,
            )
            return LoopAction.WARN

        return LoopAction.CONTINUE

    def _detect_ping_pong(self) -> bool:
        """Check if the last calls form an A→B→A→B pattern.

        Requires at least 2 full cycles (4 calls): A,B,A,B.
        """
        n = PING_PONG_CYCLES * 2  # 4 calls minimum
        if len(self._history) < n:
            return False

        recent = list(self._history)[-n:]
        a = recent[0]
        b = recent[1]
        if a == b:
            return False
        # Check that the pattern alternates perfectly
        return all(recent[i] == (a if i % 2 == 0 else b) for i in range(n))

    def reset(self) -> None:
        """Clear all loop detection state."""
        self._history.clear()
        self._counts.clear()
        self._total_calls = 0

    @property
    def total_calls(self) -> int:
        """Total tool calls recorded since last reset."""
        return self._total_calls

    @property
    def loop_count(self) -> int:
        """Return the highest repetition count in the current window."""
        return max(self._counts.values(), default=0)


def _signature(
    tool_name: str,
    args: dict | None,
    result_hash: str | None,
) -> str:
    """Create a deterministic signature for a tool call + result."""
    if not args and not result_hash:
        return f"{tool_name}:()"
    parts = [tool_name]
    if args:
        parts.append(str(sorted(args.items())))
    if result_hash:
        parts.append(result_hash)
    content = ":".join(parts)
    return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()


def hash_result(result: str | bytes) -> str:
    """Hash a tool result for use as result_hash in record().

    Args:
        result: The tool call output (string or bytes).

    Returns:
        Short hex digest suitable for signature inclusion.
    """
    if isinstance(result, str):
        result = result.encode()
    return hashlib.md5(result, usedforsecurity=False).hexdigest()[:12]
