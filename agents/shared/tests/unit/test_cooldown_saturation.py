"""The cooldown backoff saturates at its ceiling; it never overflows.

`record_failure` computed `base * 2 ** (count - threshold)` before capping it,
and `2 ** n` is an int that no longer converts to float once n reaches 1024. A
long-lived agent process whose model kept failing hit that after ~1,027
failures: from then on every `record_failure` raised
"OverflowError: int too large to convert to float". Callers record the failure
inside their own error handling, so the OverflowError replaced the handled LLM
failure. Measured live: prove logged 652 "Plan failed" lines this way, its
non-LLM fallback plan never ran, and 99 of 101 findings came back inconclusive.
"""

import pytest

from shared.llm.cooldown import _AUTH_COOLDOWN, _MAX_COOLDOWN, _RATE_LIMIT_MAX, CooldownManager


@pytest.mark.parametrize(
    ("error_kind", "ceiling"),
    [(None, _MAX_COOLDOWN), ("auth_error", _AUTH_COOLDOWN), ("rate_limited", _RATE_LIMIT_MAX)],
)
def test_long_failure_streak_saturates_at_the_ceiling(error_kind, ceiling):
    mgr = CooldownManager(failure_threshold=3, base_cooldown=60.0)
    for _ in range(1100):  # past the ~1,027th failure that overflowed
        mgr.record_failure("m", error_kind)
    remaining = mgr.get_cooldown_remaining("m")
    assert ceiling - 5 < remaining <= ceiling
    assert mgr.is_available("m") is False


def test_success_after_a_long_streak_still_resets():
    mgr = CooldownManager(failure_threshold=3, base_cooldown=60.0)
    for _ in range(1100):
        mgr.record_failure("m")
    mgr.record_success("m")
    assert mgr.is_available("m") is True
    mgr.record_failure("m")
    assert mgr.is_available("m") is True  # the streak restarted from one
