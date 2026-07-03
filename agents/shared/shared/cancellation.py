"""Cooperative cancellation for agent audits (feature 0061).

A :class:`CancelToken` is created per HTTP ``/run`` request in the transport
(:func:`shared.transport.sse_app.create_sse_app`), bound into the request's
``contextvars`` context, and polled from the worker thread that drives the
*synchronous* audit generator (:func:`shared.audit_runner.run_combined_audit`).
When the SSE consumer (the backend) disconnects or the wall-clock ceiling
trips, the audit stops promptly instead of leaving an orphaned LLM sweep
running (the ``bdd9a5c1`` runaway that motivated this feature).

Backed by :class:`threading.Event` so it is safe to *set* from the async
event-loop thread and *read* from the worker thread. It is exposed
**ambiently** via a ``ContextVar`` rather than threaded through every agent's
``run_audit`` signature — cancellation is a cross-cutting runtime concern
(cf. Go's ``context.Context``), and all agents share one transport.

.. important::
   ``ContextVars`` are inherited by ``asyncio`` Tasks and copied by
   ``contextvars.copy_context()``, but a **manually created**
   ``threading.Thread`` starts with an *empty* context. Code that spawns its
   own thread (e.g. the L5 validation thread in ``run_combined_audit``) must
   run its target via ``copy_context().run(...)`` or the ambient token /
   deadline will be invisible there (feature 0061 §3.1 caveat F11c).
"""
from __future__ import annotations

import contextvars
import threading


class CancelToken:
    """Cross-thread cooperative cancellation signal.

    ``cancel()`` is idempotent; the *first* reason wins so an early
    disconnect reason is not overwritten by a later ``stream_closed``.
    """

    __slots__ = ("_event", "_reason")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None

    def cancel(self, reason: str = "cancelled") -> None:
        if not self._event.is_set():
            self._reason = reason
        self._event.set()

    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason


# Ambient per-request cancellation state.
_current_token: contextvars.ContextVar["CancelToken | None"] = contextvars.ContextVar(
    "vulture_cancel_token", default=None
)
# Absolute ``time.monotonic()`` deadline for the WHOLE audit, shared across the
# generate + L5 phases so their timeouts cannot stack (feature 0061 F11a).
# ``None`` ⇒ no ceiling.
_current_deadline: contextvars.ContextVar["float | None"] = contextvars.ContextVar(
    "vulture_audit_deadline", default=None
)


def set_cancel_token(token: "CancelToken | None") -> contextvars.Token:
    """Bind *token* as the ambient cancel token; returns a reset handle."""
    return _current_token.set(token)


def current_cancel_token() -> "CancelToken | None":
    """The ambient cancel token for the current context, or ``None``."""
    return _current_token.get()


def set_audit_deadline(deadline: "float | None") -> contextvars.Token:
    """Bind the ambient whole-audit deadline (``time.monotonic`` seconds)."""
    return _current_deadline.set(deadline)


def current_audit_deadline() -> "float | None":
    """The ambient whole-audit deadline for the current context, or ``None``."""
    return _current_deadline.get()


def is_cancelled() -> bool:
    """True iff a token is bound and cancelled in the current context."""
    tok = _current_token.get()
    return tok is not None and tok.cancelled()
