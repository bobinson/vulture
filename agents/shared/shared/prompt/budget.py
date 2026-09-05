"""TokenBudget — the numbers a prompt currently states in prose.

Feature 0089 §3.6. A prompt cannot ask a model to leave room for its own
answer; the room is arithmetic done before the call. Three quantities decide
it and each already exists somewhere in the codebase, un-shared:

* ~150 tokens per tool definition, plus ~600 for the response schema —
  ``audit_runner.py:3262`` (``sdk_overhead``), the only place either is written
  down today.
* ``profile.reasoning_overhead_tokens`` — what a reasoning family burns before
  emitting its first answer token. Subtracted, never asked for in a sentence.
* ``DEFAULT_MAX_TOOL_CALLS`` — transcribed from ``shared.validate.judge_tools``
  which owns it. A second constant here would be a second answer.

Pure arithmetic: no env reads, no I/O, no model resolution. The context window
arrives already resolved on the profile (``provider`` owns that table).
"""

from __future__ import annotations

from dataclasses import dataclass

from .profile import ModelProfile

# Transcribed, NOT imported. `from shared.validate.judge_tools import ...`
# executes `shared/validate/__init__.py`, which eagerly imports llm_judge —
# measured at 626 ms and 1520 modules against 35 ms and 120 for the rest of the
# library, and it inverts the dependency this package exists to establish (the
# prompt library must not pull in the audit runtime; Phase 2 has audit_runner
# import US). `test_budget_tool_call_default_matches_code` imports the real
# constant and fails if these drift, which is the same guard schema.py uses for
# `_MODEL_VISIBLE_FIELDS`.
DEFAULT_MAX_TOOL_CALLS = 4

# Per-tool cost of a tool definition the SDK serialises into every request.
# ``audit_runner.py:3262``: ``150 * len(all_tools) + 600``.
TOOL_SCHEMA_TOKENS = 150

# The response schema (``AuditOutput``) the SDK sends alongside the tools.
RESPONSE_SCHEMA_TOKENS = 600

# Floor on the SDK overhead, mirroring ``max(512, ...)`` at the same site: even
# a toolless, schemaless call carries framing this arithmetic must not ignore.
MIN_SDK_OVERHEAD_TOKENS = 512

# 4 chars/token — the same crude ratio ``render._budget`` uses. Deliberately
# crude: a tokeniser dependency for a headroom estimate is not worth it.
CHARS_PER_TOKEN = 4


@dataclass(frozen=True)
class TokenBudget:
    """What one call may spend, and what it has left to answer with."""

    # Floor on the answer. Matches ``render._budget`` and ``lint.check_10_budget``,
    # which reports a finding below exactly this value.
    MIN_OUTPUT_TOKENS = 512

    ctx_window: int
    prompt_tokens: int
    tool_schema_tokens: int
    reasoning_overhead_tokens: int
    tool_call_budget: int

    @property
    def sdk_overhead(self) -> int:
        """Tool definitions + response schema, floored as the runtime floors it."""
        return max(MIN_SDK_OVERHEAD_TOKENS,
                   self.tool_schema_tokens + RESPONSE_SCHEMA_TOKENS)

    @property
    def headroom(self) -> int:
        """Window left after the prompt and everything the SDK adds to it."""
        return max(0, self.ctx_window - self.prompt_tokens - self.sdk_overhead)

    @property
    def max_output(self) -> int:
        """Headroom the model may actually answer in, floored.

        The reasoning overhead comes off HERE rather than off the headroom, so
        two profiles at the same window and prompt size have an identical
        headroom and differ only in what they may emit.
        """
        return max(self.MIN_OUTPUT_TOKENS,
                   self.headroom - self.reasoning_overhead_tokens)


def budget_for(profile: ModelProfile, prompt_chars: int,
               n_tools: int = 0) -> TokenBudget:
    """The budget for one call: this profile, this prompt size, these tools."""
    tools = max(0, n_tools)
    return TokenBudget(
        ctx_window=profile.ctx_window,
        prompt_tokens=max(0, prompt_chars) // CHARS_PER_TOKEN,
        tool_schema_tokens=TOOL_SCHEMA_TOKENS * tools,
        reasoning_overhead_tokens=profile.reasoning_overhead_tokens,
        tool_call_budget=DEFAULT_MAX_TOOL_CALLS if tools else 0,
    )


__all__ = [
    "CHARS_PER_TOKEN", "DEFAULT_MAX_TOOL_CALLS", "MIN_SDK_OVERHEAD_TOKENS",
    "RESPONSE_SCHEMA_TOKENS", "TOOL_SCHEMA_TOKENS", "TokenBudget", "budget_for",
]
