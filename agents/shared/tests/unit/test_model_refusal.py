"""A model that declines a request is neither a malformed answer nor a network fault.

Claude's safety classifiers answer some requests with stop_reason "refusal"
(HTTP 200, no text, tokens billed). The broker and LiteLLM both hand that on in
OpenAI's shape — finish_reason "content_filter" plus message.refusal — and the
agents SDK raises ModelRefusalError on it. Before this, that error's text
("Model refused to produce output") matched the connection-error pattern, so a
refusal was retried as a network fault, re-billed on every attempt, and
reported as one; the L5 judge, which reads the response itself, saw an empty
answer and walked every format fallback, each refused again.
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import pytest
from agents.exceptions import ModelRefusalError

from shared.llm.errors import (
    RETRYABLE_KINDS,
    LLMErrorKind,
    classify_llm_error,
    llm_failure_message,
    retry_llm_call,
)

REASON = "the model declined the request (refusal category: cyber)"


def test_a_refusal_is_its_own_kind_and_never_retried() -> None:
    kind = classify_llm_error(ModelRefusalError(REASON))
    assert kind is LLMErrorKind.REFUSED
    assert kind not in RETRYABLE_KINDS


def test_a_refused_connection_is_still_a_connection_error() -> None:
    assert classify_llm_error(ConnectionError("Connection refused")) is LLMErrorKind.CONNECTION_ERROR


def test_retry_llm_call_makes_one_attempt_for_a_refusal() -> None:
    calls = 0

    async def refuse():
        nonlocal calls
        calls += 1
        raise ModelRefusalError(REASON)

    with pytest.raises(ModelRefusalError):
        asyncio.run(retry_llm_call(refuse, max_attempts=3, base_delay=0))
    assert calls == 1


def test_the_persisted_reason_names_the_refusal() -> None:
    msg = llm_failure_message(LLMErrorKind.REFUSED, ModelRefusalError(REASON))
    assert msg.startswith("LLM analysis failed (refused): ")
    assert "cyber" in msg


# ── the L5 judge ──────────────────────────────────────────────────────────────

def _refusal_response():
    message = SimpleNamespace(content=None, refusal=REASON, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="content_filter")])


class _RefusingClient:
    def __init__(self) -> None:
        self.calls = 0
        outer = self

        class _Completions:
            @staticmethod
            def create(**_kw):
                outer.calls += 1
                return _refusal_response()

        self.chat = SimpleNamespace(completions=_Completions())


def test_plain_judging_stops_at_the_first_refusal(monkeypatch) -> None:
    """No second response mode, no doubled budget: each would be refused too."""
    from shared.validate import llm_judge

    client = _RefusingClient()
    monkeypatch.setattr(llm_judge, "_get_client", lambda: client)
    with pytest.raises(llm_judge._ModelRefused):
        llm_judge._call_llm("sys", "user", "claude-sonnet-5-5", 5.0)
    assert client.calls == 1


def test_the_tool_loop_does_not_fall_back_after_a_refusal(monkeypatch) -> None:
    from shared.validate import llm_judge

    client = _RefusingClient()
    monkeypatch.setattr(llm_judge, "_get_client", lambda: client)
    with pytest.raises(llm_judge._ModelRefused):
        llm_judge._call_llm_with_tools(
            "user", "claude-sonnet-5-5", 5.0, executor=object(), max_calls=2, batch_size=1)
    assert client.calls == 1


def test_a_refused_batch_gets_no_verdict_and_says_why(monkeypatch, caplog) -> None:
    from shared.validate import llm_judge

    def refuse(*_a, **_k):
        raise llm_judge._ModelRefused(REASON)

    monkeypatch.setattr(llm_judge, "_judge_uncached", refuse)
    batch = [(0, {"id": "f1", "title": "t", "file_path": "a.py"}, "key-1")]
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        verdicts = llm_judge._judge_batch(
            batch_idx=7, batch=batch, audit_id="a", system_prompt="s",
            model="claude-sonnet-5-5", per_batch_timeout_s=5.0)
    assert verdicts == {}
    assert any("batch 7" in r.message and "declined" in r.message for r in caplog.records)
