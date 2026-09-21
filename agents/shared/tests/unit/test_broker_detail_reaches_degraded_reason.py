"""The curated broker diagnosis must reach the DURABLE surfaces, not just logs.

`_broker_detail` was built for one caller — the L5 judge's log line. But the
generate path turns its exception into `llm_error`, and that string is not a
log: it is emitted on the SSE `thinking` stream, carried in the `result`
snapshot, and persisted as `audits.degraded_reason` in both Postgres and
SQLite. It was built with `str(exc)[:200]`.

For a broker error that is the worst of both worlds. The openai SDK builds its
message as `Error code: 404 - {whole body dict}`, so the operator-facing,
persisted field got a Python repr of the entire envelope, truncated mid-dict at
200 characters — while the one field written to name the rejected model
(`upstream.message`) is the LAST key in it and is what the truncation cuts off.
"""

from __future__ import annotations

import pytest

from shared.llm.errors import LLMErrorKind, broker_detail, llm_failure_message


class _FakeSDKError(Exception):
    """Shaped like openai's APIStatusError: `body` is the UNWRAPPED inner
    object (the SDK strips the `error` envelope), and `str()` is the SDK's
    'Error code: N - {body}' rendering."""

    def __init__(self, status: int, body: dict) -> None:
        super().__init__(f"Error code: {status} - {body}")
        self.body = body
        self.status_code = status


def _broker_404() -> _FakeSDKError:
    return _FakeSDKError(
        404,
        {
            "message": "model not found or not routable",
            "type": "model_not_found",
            "code": "model_not_found",
            "x_retriable": False,
            "upstream": {
                "provider": "gemini",
                "status": 404,
                "message": (
                    "models/gemini-pro is not found for API version v1beta, "
                    "or is not supported for generateContent. Call "
                    "ListModels to see the list of available models."
                ),
            },
        },
    )


def test_the_degraded_message_names_the_rejected_model() -> None:
    msg = llm_failure_message(LLMErrorKind.PROVIDER_BAD_REQUEST, _broker_404())
    assert "gemini-pro" in msg, (
        "the rejected model id is the entire diagnostic value of a 404, and it is "
        f"what the operator sees in the UI and in audits.degraded_reason: {msg!r}"
    )
    assert "model_not_found" in msg


def test_the_degraded_message_is_not_a_raw_dict_repr() -> None:
    msg = llm_failure_message(LLMErrorKind.PROVIDER_BAD_REQUEST, _broker_404())
    for leak in ("{'message'", "x_retriable':", "Error code: 404 - {"):
        assert leak not in msg, f"a Python dict repr reached a user-facing field: {msg!r}"


def test_the_degraded_message_stays_bounded() -> None:
    huge = _FakeSDKError(404, {
        "code": "model_not_found", "message": "m", "x_retriable": False,
        "upstream": {"provider": "gemini", "status": 404, "message": "A" * 5000},
    })
    assert len(llm_failure_message(LLMErrorKind.PROVIDER_BAD_REQUEST, huge)) <= 320


def test_a_non_broker_failure_keeps_the_existing_rendering() -> None:
    """No broker marker → no claim of broker provenance, and the old text."""
    plain = ValueError("connection reset by peer")
    msg = llm_failure_message(LLMErrorKind.CONNECTION_ERROR, plain)
    assert "broker says" not in msg
    assert "connection reset by peer" in msg
    assert LLMErrorKind.CONNECTION_ERROR.value in msg


def test_broker_detail_is_one_implementation() -> None:
    """L5 and the generate path must not drift into two dialects of this."""
    from shared.validate import llm_judge

    assert llm_judge._broker_detail is broker_detail


@pytest.mark.parametrize("body", [None, {}, {"message": "x"}, {"error": "plain"}, "notadict"])
def test_broker_detail_never_raises_and_never_guesses(body: object) -> None:
    exc = _FakeSDKError(500, {})
    exc.body = body
    assert broker_detail(exc) == ""


# ── WIRE-5: the litellm path ────────────────────────────────────────────────
#
# broker_detail reads `exc.body`, which is an openai-SDK attribute. Most agent
# traffic is LiteLLM-routed, and litellm raises its own exception carrying the
# response on `.response` (and the body text in the message). On that path the
# envelope the broker went to the trouble of writing was discarded whole, so
# the pass-through worked for the one client that was tested with and for no
# other — silently, as an ordinary "no diagnosis".


class _FakeLiteLLMError(Exception):
    class _Resp:
        def __init__(self, text: str) -> None:
            self.text = text
            self.status_code = 404

        def json(self) -> dict:
            import json as _json

            return _json.loads(self.text)

    def __init__(self, text: str) -> None:
        super().__init__(f"litellm.NotFoundError: GeminiException - {text}")
        self.response = self._Resp(text)
        self.status_code = 404


_ENVELOPE = (
    '{"error":{"message":"model not found or not routable","type":"model_not_found",'
    '"code":"model_not_found","x_retriable":false,'
    '"upstream":{"provider":"gemini","status":404,'
    '"message":"models/gemini-pro is not found for API version v1beta"}}}'
)


def test_the_litellm_shape_is_understood() -> None:
    detail = broker_detail(_FakeLiteLLMError(_ENVELOPE))
    assert "model_not_found" in detail
    assert "gemini-pro" in detail, f"the litellm path lost the envelope: {detail!r}"


def test_an_envelope_only_in_the_message_text_is_still_found() -> None:
    """Some wrappers keep no response object at all and only stringify it."""

    class _StringOnly(Exception):
        pass

    detail = broker_detail(_StringOnly(f"upstream error: {_ENVELOPE} (after 1 attempt)"))
    assert "gemini-pro" in detail, f"envelope embedded in the message was lost: {detail!r}"


def test_a_providers_own_json_in_a_message_is_not_claimed_as_ours() -> None:
    """The marker gate still applies to text-scraped JSON: a direct provider
    error has no x_retriable and no upstream, and must not be attributed."""

    class _StringOnly(Exception):
        pass

    direct = '{"error":{"message":"models/x not found","code":404,"status":"NOT_FOUND"}}'
    assert broker_detail(_StringOnly(f"GeminiException - {direct}")) == ""
