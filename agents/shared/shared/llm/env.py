"""One reader for integer environment knobs.

`_safe_int_env` existed in four copies before 0093 (audit_runner, loop_detector,
memory_client, and inline elsewhere). A fifth copy was the obvious thing to
write for W1 and is exactly what CLAUDE.md's DRY rule forbids, so new code
imports this instead. The existing copies are behaviourally identical and are
left alone here rather than refactored blind; consolidating them is a separate,
test-covered change.
"""

from __future__ import annotations

import os


def safe_int_env(name: str, default: int) -> int:
    """Read `name` as an int, falling back to `default` on absent/unparseable.

    Never raises and never returns a partially-parsed value: a knob an operator
    typo'd must degrade to the documented default, not to zero, because zero is
    a meaningful (and usually catastrophic) value for a timeout or a limit.
    """
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        return int(raw.strip())
    except (ValueError, TypeError, AttributeError):
        return default


# ── the per-call LLM budget ─────────────────────────────────────────────────
#
# `VULTURE_LLM_CALL_TIMEOUT_SEC` shipped at 120 while
# `VULTURE_LLM_MAX_OUTPUT_TOKENS` shipped at 16384. Those two defaults were
# mutually impossible: no provider emits 16384 tokens in 120 seconds. A fast
# cloud model at ~100 tok/s needs 164s; a local 27B measured at ~50 tok/s needs
# ~327s. So on DEFAULTS any model that used its output budget was cut off
# mid-answer, on every provider, and the only escape was for each operator to
# discover the interaction and hand-tune it.
#
# That tuning is what went wrong in the incident behind feature 0093: lowering
# the output cap to make runs finish faster took one target's LLM tier from 14
# findings to 1, because the cap does not shorten an answer — it truncates the
# JSON array, and the salvage path then recovers only the whole rows that
# survived.
#
# So the default is DERIVED from the budget it must accommodate. The two cannot
# drift apart again, an operator who resizes the output budget gets a matching
# timeout without knowing this interaction exists, and an explicit
# VULTURE_LLM_CALL_TIMEOUT_SEC still wins outright.
#
# ONE resolver, read by both the batch budget (audit_runner) and the socket
# read timeout (llm.broker). Two numbers that must agree are one function.
#
# The rate is deliberately pessimistic. A too-generous timeout costs latency on
# a hung model, which the whole-audit deadline still bounds; a too-tight one
# silently destroys findings. Those costs are not symmetric.
_CONSERVATIVE_TOK_PER_SEC = 40.0  # measured 46.5-50.3 on a local 27B; cloud is faster
_CALL_TIMEOUT_OVERHEAD_S = 30     # prompt processing, network, tool round-trips
_CALL_TIMEOUT_FLOOR_S = 120       # never below the historical default
_CALL_TIMEOUT_CEILING_S = 3600    # a single call beyond an hour is a hang, not a budget

# Kept in step with backend/internal/service/agent_proxy_service.go's
# defaultLLMCallTimeoutSec, which needs the same number to judge whether the
# shipped timeout margin is safe. test_0093_transport_diagnostics.py pins them
# together, because a drift there makes the backend call an unsafe
# configuration safe.
DEFAULT_MAX_OUTPUT_TOKENS = 16384


def resolve_call_timeout() -> int:
    """The per-call LLM budget in seconds: explicit env value, else derived."""
    explicit = safe_int_env("VULTURE_LLM_CALL_TIMEOUT_SEC", 0)
    if explicit > 0:
        return explicit
    tokens = safe_int_env("VULTURE_LLM_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS)
    if tokens <= 0:
        tokens = DEFAULT_MAX_OUTPUT_TOKENS
    derived = int(tokens / _CONSERVATIVE_TOK_PER_SEC) + _CALL_TIMEOUT_OVERHEAD_S
    return max(_CALL_TIMEOUT_FLOOR_S, min(derived, _CALL_TIMEOUT_CEILING_S))
