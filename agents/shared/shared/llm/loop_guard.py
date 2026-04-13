"""Loop guard integration for OpenAI Agents SDK.

Provides a RunHooks implementation that monitors tool calls during
agent execution and aborts when repetitive patterns are detected.
"""

import logging

from shared.llm.loop_detector import LoopAction, LoopDetector, hash_result

logger = logging.getLogger(__name__)


class LoopDetectedError(Exception):
    """Raised when the loop detector triggers a KILL action."""

    def __init__(self, message: str, total_calls: int = 0) -> None:
        super().__init__(message)
        self.total_calls = total_calls


def create_loop_guard_hooks(
    detector: LoopDetector | None = None,
) -> tuple:
    """Create an Agents SDK RunHooks instance with loop detection.

    Returns (hooks, detector) tuple. ``hooks`` is a RunHooks subclass
    that records tool calls and raises LoopDetectedError on KILL.
    If the Agents SDK is not installed, returns (None, detector).

    Args:
        detector: Optional pre-configured LoopDetector. A default one
            is created if not provided.

    Returns:
        Tuple of (hooks_instance_or_None, LoopDetector).
    """
    if detector is None:
        detector = LoopDetector()

    try:
        from agents import RunHooks  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("agents SDK not available, loop guard hooks disabled")
        return None, detector

    class _LoopGuardHooks(RunHooks):
        """RunHooks that monitors tool calls for loop patterns."""

        def __init__(self, det: LoopDetector) -> None:
            self._detector = det

        async def on_tool_end(self, context, agent, tool, result) -> None:
            tool_name = getattr(tool, "name", str(tool))
            res_hash = hash_result(str(result)) if result else None
            action = self._detector.record(tool_name, None, res_hash)

            if action == LoopAction.KILL:
                raise LoopDetectedError(
                    f"Tool loop detected: {tool_name} "
                    f"(total_calls={self._detector.total_calls}, "
                    f"max_repeat={self._detector.loop_count})",
                    total_calls=self._detector.total_calls,
                )
            if action == LoopAction.WARN:
                logger.warning(
                    "loop_guard_warn tool=%s total=%d repeat=%d",
                    tool_name, self._detector.total_calls, self._detector.loop_count,
                )

    return _LoopGuardHooks(detector), detector
