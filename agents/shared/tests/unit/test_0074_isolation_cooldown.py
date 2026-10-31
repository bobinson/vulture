"""Feature 0074 test hygiene — model cooldowns must not leak between tests.

``shared.llm.cooldown.cooldown_manager`` is process-global production state. A
test that drives the LLM sweep into failures (``test_0070_p5_llm_transport``'s
consecutive-failure abort records three for ``gpt-4o``) left that model in
cooldown, so every later test asking for ``gpt-4o`` silently resolved to the
fallback chain's Anthropic model. On that model the batch source moves into the
SYSTEM turn, every user turn reads the same, and
``test_0057_llm_on_bundle::TestT12BatchSweep`` saw one distinct window instead
of six. The isolation fixture now starts every test with no cooldowns.
"""

from __future__ import annotations

import pytest

from shared.llm.cooldown import cooldown_manager
from shared.llm.provider import get_model, get_model_with_fallback
from tests.support.isolation import isolate


def test_isolate_clears_model_cooldowns(tmp_path) -> None:
    resolved = get_model("gpt-4o")
    try:
        for _ in range(5):
            cooldown_manager.record_failure(resolved)
        assert get_model_with_fallback("gpt-4o") != resolved  # precondition: poisoned
        with pytest.MonkeyPatch.context() as mp:
            isolate(mp, tmp_path)
            assert get_model_with_fallback("gpt-4o") == resolved
    finally:
        cooldown_manager.reset()
