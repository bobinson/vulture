"""§32.1 #6: the broker owns retries, and the agent must honor the broker's
authoritative x_retriable flag rather than re-deriving retryability from a
status string (a permanent 502 like provider_bad_request must NOT be retried).
"""
from __future__ import annotations

import sys
import types

import pytest

from shared.llm.errors import RETRYABLE_KINDS, classify_llm_error


def test_default_client_factory_disables_sdk_retries(monkeypatch):
    """The SDK client must be built with max_retries=0 so the broker is the
    single retry authority (no broker×SDK×agent amplification)."""
    captured: dict = {}

    class FakeAsyncOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    fake = types.ModuleType("openai")
    fake.AsyncOpenAI = FakeAsyncOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake)

    from shared.llm import broker

    broker._default_client_factory(base_url="http://broker", api_key="tok")
    assert captured.get("max_retries") == 0, "SDK client-side retries must be disabled"


@pytest.mark.parametrize(
    "msg",
    [
        'Error code: 502 - {"error":{"code":"provider_bad_request","message":"provider rejected the request","x_retriable":false}}',
        'Error code: 502 - {"error":{"code":"provider_auth_error","x_retriable":false}}',
        'Error code: 502 - {"error":{"code":"model_not_found","x_retriable":false}}',
        '{"error":{"type":"provider_unavailable","x_retriable":false}}',
    ],
)
def test_broker_permanent_errors_not_retried(msg):
    """A broker error carrying a permanent code / x_retriable:false must classify
    as non-retryable EVEN THOUGH the HTTP status is 502 (which the server regex
    would otherwise treat as retryable)."""
    kind = classify_llm_error(Exception(msg))
    assert kind not in RETRYABLE_KINDS, f"{msg!r} classified retryable ({kind})"


def test_plain_502_still_retryable():
    """A genuine transient 502 (no permanent marker) stays retryable."""
    assert classify_llm_error(Exception("Error code: 502 - bad gateway")) in RETRYABLE_KINDS


def test_retriable_502_with_x_retriable_true_still_retryable():
    msg = 'Error code: 502 - {"error":{"code":"provider_unavailable","x_retriable":true}}'
    assert classify_llm_error(Exception(msg)) in RETRYABLE_KINDS
