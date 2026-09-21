"""The broker names the real cause; the L5 judge must not discard it.

The broker returns a typed envelope (`broker/server/dto.go::writeErr`):

    {"error": {"message": ..., "type": <code>, "code": <code>, "x_retriable": bool}}

with codes that already distinguish the causes that matter — `model_not_found`,
`token_revoked`, `token_expired`, `provider_auth_error`, `budget_exceeded`.
Several are served with 5xx (`model_not_found` is 502, because the broker IS a
gateway reporting an upstream fault), so the OpenAI SDK raises
`InternalServerError` and `_log_call_failure` printed only the class name:

    [validate.l5] tool-loop call could not reach the LLM endpoint
    http://localhost:8090/v1 (InternalServerError) — ... Check
    VULTURE_VALIDATE_LLM_MODEL and the resolved base URL

Measured live: 33 upstream 404s from Google for the retired id `gemini-pro`,
surfaced to the operator as a generic endpoint/base-URL problem. The broker log
said `model not found: upstream status 404` — the actionable half existed and
was dropped at the boundary.
"""

import logging

import pytest

from shared.validate import llm_judge


def _exc(name: str, body):
    """An openai-SDK-shaped error: class name + parsed `.body`."""
    cls = type(name, (Exception,), {})
    e = cls("upstream failure")
    e.body = body
    return e


BROKER_ENVELOPE = {
    "error": {
        "message": "model not found or not routable",
        "type": "model_not_found",
        "code": "model_not_found",
        "x_retriable": False,
    }
}


def test_broker_error_code_reaches_the_operator(caplog):
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("InternalServerError", BROKER_ENVELOPE), "tool-loop")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "model_not_found" in text, (
        "the broker named the cause and the judge dropped it; the operator is told to "
        f"check a base URL that is correct. got: {text!r}"
    )


def test_non_retriable_is_stated(caplog):
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("InternalServerError", BROKER_ENVELOPE), "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "retry" in text.lower() or "retriable" in text.lower(), (
        f"x_retriable=false means retrying cannot help; say so. got: {text!r}"
    )


def test_revoked_token_is_named_rather_than_called_an_auth_misconfiguration(caplog):
    """A cancelled run's revoked token carries its own code."""
    env = {"error": {"message": "token revoked", "type": "token_revoked",
                     "code": "token_revoked", "x_retriable": False}}
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("AuthenticationError", env), "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "token_revoked" in text, (
        f"the broker distinguishes token_revoked from unauthorized; surface it. got: {text!r}"
    )


@pytest.mark.parametrize("body", [None, {}, {"error": "a bare string"}, {"nope": 1}, "not json"])
def test_a_non_broker_error_is_unchanged(caplog, body):
    """A plain upstream failure with no broker envelope keeps the old message —
    the detail is additive, never a replacement."""
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("APIConnectionError", body), "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "could not reach the LLM endpoint" in text, text


def test_detail_extraction_never_raises():
    """A malformed body must not turn a logged failure into a crash inside the
    failure handler."""
    class Hostile:
        @property
        def body(self):
            raise RuntimeError("boom")

    llm_judge._log_call_failure(Hostile(), "plain")  # must not raise


# ── the provider's OWN words, now that the broker forwards them ──────────────
#
# The broker's envelope gained an `upstream` block for the one class whose body
# cannot echo request content (model_not_found). Before it, the operator was
# told "model not found or not routable" — true, and useless: it never said
# WHICH model. Google's text names the id and the remedy.

BROKER_WITH_UPSTREAM = {
    "error": {
        "message": "model not found or not routable",
        "type": "model_not_found",
        "code": "model_not_found",
        "x_retriable": False,
        "upstream": {
            "provider": "gemini",
            "status": 404,
            "message": ("models/gemini-pro is not found for API version v1beta, or is not "
                        "supported for generateContent. Call ModelService.ListModels"),
        },
    }
}


def test_the_providers_own_message_reaches_the_operator(caplog):
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("InternalServerError", BROKER_WITH_UPSTREAM), "tool-loop")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "gemini-pro" in text, (
        f"WHICH model was rejected is the whole point; got {text!r}"
    )
    assert "ListModels" in text, "the provider's own remedy must survive"
    assert "gemini" in text and "404" in text, "name the provider and the upstream status"


def test_upstream_is_additive_not_a_replacement(caplog):
    """The broker's own code still appears — it is the stable machine-readable
    half, and the upstream text is free-form provider prose."""
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("InternalServerError", BROKER_WITH_UPSTREAM), "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "model_not_found" in text


def test_missing_upstream_block_falls_back_to_the_code(caplog):
    """Every other class has no upstream block and must read as before."""
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_exc("InternalServerError", BROKER_ENVELOPE), "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "model_not_found" in text and "broker says" in text


def test_a_malformed_upstream_block_cannot_break_the_handler(caplog):
    for bad in ({"upstream": "a string"}, {"upstream": {"message": None}}, {"upstream": {}}):
        env = {"error": {"code": "model_not_found", "message": "m", **bad}}
        llm_judge._log_call_failure(_exc("InternalServerError", env), "plain")  # must not raise
