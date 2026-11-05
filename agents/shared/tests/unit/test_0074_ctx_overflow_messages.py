"""Feature 0074 re-audit R6 — the agent's overflow vocabulary IS the broker's.

``backend/internal/broker/provider/testdata/ctx_overflow_messages_0074.json`` is
read by the broker's ``contextOverflowBody`` test and here. Only size/overflow
phrasing counts: a 4xx that merely names a size-related parameter
(``max_tokens``, ``context_size``, a field's maximum length) is a different
fault, and calling it an overflow costs a pointless halve-and-retry. Before the
fix the agent's ``_CTX_OVERFLOW_RE`` matched ``max.tokens`` / ``maximum.length``
/ ``context.window`` alone, and missed three real overflow phrasings the broker
already knew.

All fixtures are synthetic or provider-published messages.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.llm.errors import _CTX_OVERFLOW_RE, LLMErrorKind, classify_llm_error

_FIXTURE = (Path(__file__).resolve().parents[4] / "backend" / "internal" / "broker"
            / "provider" / "testdata" / "ctx_overflow_messages_0074.json")
_MESSAGES = json.loads(_FIXTURE.read_text())["messages"]


@pytest.mark.parametrize("case", _MESSAGES, ids=lambda c: repr(c["text"][:48]))
def test_overflow_vocabulary_matches_the_broker(case) -> None:
    assert bool(_CTX_OVERFLOW_RE.search(case["text"])) is case["overflow"]


@pytest.mark.parametrize("case", [c for c in _MESSAGES if c["overflow"]],
                         ids=lambda c: repr(c["text"][:48]))
def test_every_overflow_message_classifies_as_overflow(case) -> None:
    """The regex is reached: no earlier classifier hides an overflow."""
    assert classify_llm_error(RuntimeError(case["text"])) is LLMErrorKind.CONTEXT_OVERFLOW
