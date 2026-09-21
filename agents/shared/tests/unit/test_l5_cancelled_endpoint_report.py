"""A cancelled run must not be reported as an endpoint misconfiguration.

Cancelling an audit revokes its per-run broker lease. The L5 judge runs its
batches in a thread pool, so calls already in flight reach the broker after the
revocation and come back 401. `_log_call_failure` classified that as
`_is_endpoint_error` and emitted, at WARNING, per in-flight batch:

    [validate.l5] plain call could not reach the LLM endpoint
    http://localhost:8090/v1 (AuthenticationError) — no verdicts will be
    produced. Check VULTURE_VALIDATE_LLM_MODEL and the resolved base URL...

Measured live: 13 of them inside a 45-second window, every one in the interval
immediately after three audits were cancelled, and zero in three earlier logs
of runs that were never cancelled. The advice is actionable and wrong — the
model and base URL were correct, the run had simply been cancelled — and it
cost a real debugging session chasing mint keys and contextvar propagation.

A cancelled run's failed call is expected, not a fault to escalate.
"""

import logging

import pytest

from shared.cancellation import CancelToken, set_cancel_token
from shared.validate import llm_judge


class _Auth(Exception):
    """Stands in for openai.AuthenticationError, matched by name."""


_Auth.__name__ = "AuthenticationError"


@pytest.fixture
def cancel_token():
    token = CancelToken()
    handle = set_cancel_token(token)
    yield token
    try:
        import contextvars  # noqa: F401

        from shared.cancellation import _current_token

        _current_token.reset(handle)
    except Exception:
        pass


def test_uncancelled_endpoint_failure_still_warns(caplog, cancel_token):
    """The diagnostic must survive for the case it was written for."""
    with caplog.at_level(logging.WARNING, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_Auth("401 unauthorized"), "plain")
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "could not reach the LLM endpoint" in text, (
        "a genuine auth failure on a live run is still a misconfiguration worth escalating"
    )


def test_cancelled_run_does_not_report_a_misconfiguration(caplog, cancel_token):
    cancel_token.cancel("cancelled by admin")
    with caplog.at_level(logging.DEBUG, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_Auth("401 unauthorized"), "plain")
    records = [r for r in caplog.records]
    text = "\n".join(r.getMessage() for r in records)

    assert "Check VULTURE_VALIDATE_LLM_MODEL" not in text, (
        "a cancelled run must not tell the operator to check their model and base URL — "
        "the configuration is fine, the run was cancelled"
    )
    assert not any(r.levelno >= logging.WARNING for r in records), (
        f"a cancelled run's in-flight call must not escalate; got {[r.levelname for r in records]}"
    )
    assert "cancel" in text.lower(), (
        f"the line must still say what happened, and name cancellation as the reason; got {text!r}"
    )


def test_cancellation_check_precedes_the_size_classification(caplog, cancel_token):
    """Cancellation is checked first: a size error on a cancelled run is also
    not an operator-actionable event."""
    cancel_token.cancel("cancelled by admin")
    with caplog.at_level(logging.DEBUG, logger=llm_judge.log.name):
        llm_judge._log_call_failure(_Auth("request body too large"), "structured-output")
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


def test_cancel_token_reaches_the_pool_worker(caplog, cancel_token):
    """The fix must fire where the failure actually happens.

    `_log_call_failure` runs inside an L5 batch worker, not on the thread that
    bound the cancel token. The judge submits each batch as
    `pool.submit(contextvars.copy_context().run, _process_batch, ...)` for
    exactly this reason. If the token did not survive that hop, the
    cancellation check would be dead code in production while passing every
    main-thread test — so this asserts the hop, not just the branch.
    """
    import contextvars
    from concurrent.futures import ThreadPoolExecutor

    cancel_token.cancel("cancelled by admin")

    with caplog.at_level(logging.DEBUG, logger=llm_judge.log.name):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(
                contextvars.copy_context().run,
                llm_judge._log_call_failure,
                _Auth("401 unauthorized"),
                "plain",
            ).result()

    text = "\n".join(r.getMessage() for r in caplog.records)
    assert not any(r.levelno >= logging.WARNING for r in caplog.records), (
        f"the cancel token did not reach the pool worker; got {[r.levelname for r in caplog.records]}"
    )
    assert "cancel" in text.lower(), text


def test_pool_worker_without_the_context_copy_still_warns(caplog, cancel_token):
    """The control for the test above: submitted WITHOUT copy_context, the
    worker sees no token and the old escalation is correct behaviour. This is
    what proves the previous test is testing propagation and not a no-op."""
    from concurrent.futures import ThreadPoolExecutor

    cancel_token.cancel("cancelled by admin")

    with caplog.at_level(logging.DEBUG, logger=llm_judge.log.name):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(llm_judge._log_call_failure, _Auth("401 unauthorized"), "plain").result()

    assert any(r.levelno >= logging.WARNING for r in caplog.records), (
        "without the context copy the worker cannot know the run was cancelled, so the "
        "endpoint warning is the right answer — if this passes silently the propagation "
        "test above proves nothing"
    )
