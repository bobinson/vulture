"""Feature 0061 — CancelToken + ambient contextvar (unit). Test T5."""
from __future__ import annotations

import contextvars

import pytest

from shared.cancellation import (
    CancelToken,
    current_audit_deadline,
    current_cancel_token,
    is_cancelled,
    set_audit_deadline,
    set_cancel_token,
)


@pytest.fixture(autouse=True)
def _clean_ambient_context():
    """Isolate from ambient cancel/deadline state that other tests (e.g. direct
    run_combined_audit calls) may have left in this thread's context."""
    from shared import cancellation

    tok_reset = cancellation._current_token.set(None)
    dl_reset = cancellation._current_deadline.set(None)
    try:
        yield
    finally:
        cancellation._current_token.reset(tok_reset)
        cancellation._current_deadline.reset(dl_reset)


class TestCancelToken:
    def test_starts_uncancelled(self):
        t = CancelToken()
        assert not t.cancelled()
        assert t.reason is None

    def test_cancel_sets_flag_and_reason(self):
        t = CancelToken()
        t.cancel("client_disconnected")
        assert t.cancelled()
        assert t.reason == "client_disconnected"

    def test_cancel_is_idempotent_first_reason_wins(self):
        t = CancelToken()
        t.cancel("first")
        t.cancel("second")
        assert t.cancelled()
        assert t.reason == "first"

    def test_default_reason(self):
        t = CancelToken()
        t.cancel()
        assert t.reason == "cancelled"


class TestAmbientContext:
    def test_unset_is_none(self):
        assert contextvars.copy_context().run(current_cancel_token) is None

    def test_set_and_get(self):
        def body():
            t = CancelToken()
            set_cancel_token(t)
            return current_cancel_token() is t

        assert contextvars.copy_context().run(body) is True

    def test_is_cancelled_reflects_token(self):
        def body():
            t = CancelToken()
            set_cancel_token(t)
            before = is_cancelled()
            t.cancel()
            return before, is_cancelled()

        before, after = contextvars.copy_context().run(body)
        assert before is False
        assert after is True

    def test_isolation_across_contexts(self):
        def make():
            set_cancel_token(CancelToken())
            return current_cancel_token()

        t1 = contextvars.copy_context().run(make)
        t2 = contextvars.copy_context().run(make)
        assert t1 is not t2

    def test_deadline_set_and_get(self):
        def body():
            set_audit_deadline(123.5)
            return current_audit_deadline()

        assert contextvars.copy_context().run(body) == 123.5

    def test_deadline_unset_is_none(self):
        assert contextvars.copy_context().run(current_audit_deadline) is None
