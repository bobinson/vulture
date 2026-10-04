"""Feature 0074 review item 5 — a broker-mode context overflow is halved, not
given up on.

The broker answers an upstream context overflow / 413 ``request_too_large``
with the code ``provider_context_overflow`` (HTTP 413, static secret-free
message, ``x_retriable: false``). The classifier must call that — and the
size/overflow codes generally — ``CONTEXT_OVERFLOW``, checked BEFORE the
broker-permanent pattern, so the generate path's one halved retry runs. Before
the fix ``x_retriable: false`` won and the batch was classified
``PROVIDER_BAD_REQUEST``: no halving, and repeated failures aborted the sweep.

The renderings are the openai SDK's repr of the broker's decoded envelope.
All fixtures are synthetic.
"""

from __future__ import annotations

import pytest

from shared.llm.errors import LLMErrorKind, classify_llm_error
from tests.unit.test_0070_p5_llm_transport import (  # noqa: F401 — autouse fixture
    _collect,
    _FakeResult,
    _hermetic,
    _install_runner,
    _source_context,
    _SpyRunner,
)

_OVERFLOW_CODE = (
    "Error code: 413 - {'code': 'provider_context_overflow', "
    "'message': 'upstream rejected the request as too large for the model context', "
    "'type': 'provider_context_overflow', 'x_retriable': False}"
)
_TOO_LARGE_CODE = (
    "Error code: 413 - {'code': 'request_too_large', "
    "'message': 'request body too large', 'x_retriable': False}"
)
_BAD_REQUEST = (
    "Error code: 502 - {'code': 'provider_bad_request', "
    "'message': 'upstream rejected the request', 'x_retriable': False}"
)
_NOT_FOUND = "Error code: 404 - {'code': 'model_not_found', 'x_retriable': False}"


@pytest.mark.parametrize(("message", "kind"), [
    (_OVERFLOW_CODE, LLMErrorKind.CONTEXT_OVERFLOW),
    (_TOO_LARGE_CODE, LLMErrorKind.CONTEXT_OVERFLOW),
    (_BAD_REQUEST, LLMErrorKind.PROVIDER_BAD_REQUEST),
    (_NOT_FOUND, LLMErrorKind.PROVIDER_BAD_REQUEST),
], ids=["provider_context_overflow", "request_too_large", "bad_request", "model_not_found"])
def test_broker_codes_classify(message, kind) -> None:
    assert classify_llm_error(RuntimeError(message)) is kind


@pytest.mark.parametrize("message", [_OVERFLOW_CODE, _TOO_LARGE_CODE])
def test_broker_overflow_is_halved_once(message, monkeypatch, tmp_path) -> None:
    """The broker-mode halving path: one smaller retry, which succeeds."""
    from shared.llm import provider

    # The model must not be swapped by a cooldown another test left behind: a
    # fallback model would move the source into the system turn, out of `input`.
    monkeypatch.setattr(provider, "get_model_with_fallback", provider.get_model)
    prompts: list[str] = []

    async def _behaviour(attempt, agent, kwargs):
        prompts.append(kwargs.get("input", ""))
        if attempt == 1:
            raise RuntimeError(message)
        return _FakeResult()

    runner = _SpyRunner(_behaviour)
    _install_runner(monkeypatch, runner)
    _findings, error, _in, _out = _collect(
        monkeypatch, tmp_path, source_context=_source_context(8),
    )
    assert (error, len(runner.calls)) == (None, 2)
    assert len(prompts[1]) < len(prompts[0])
