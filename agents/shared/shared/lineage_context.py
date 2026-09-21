"""Ambient per-run lineage evidence question (feature 0091 §6.1).

THE GAP THIS CLOSES. The backend puts ``lineage_checks_requested`` at the TOP
LEVEL of the ``/run`` request body (``agent_proxy_service.go``), because §6.1
puts it there — it is a question about the whole scan, not a per-agent config
knob. But every agent's entry point has the fixed four-argument shape
``run_audit(run_id, source_path, config, prior_findings)``, so there is no
parameter for it to arrive through, and ``AuditRequest`` silently discarded it:
the backend asked, ten agents never heard the question, and every LLM-tier
lineage row would have landed at ``unconfirmed`` on every scan while the wire
format looked correct from both ends.

WHY A CONTEXTVAR. This is the third per-run value the backend injects that no
agent signature carries — ``CancelToken`` (0061) and the broker token /
task_type / context window (0064) are the others, and both are bound ambiently
by the transport for exactly this reason. Widening ten ``run_audit``
signatures for a value only ``run_combined_audit`` reads would touch every
agent and every agent test to move one dict from the request to the runner.

The transport binds it with ``ctx.run`` into the context it copies for the
audit worker thread, so ``run_combined_audit`` sees it in that thread. An
explicit ``lineage_checks_requested=`` keyword still wins — that is how the
tests drive it, and an explicit argument outranking an ambient one is the
behaviour a caller expects.

.. important::
   Like every other ambient value here, this is invisible inside a manually
   created ``threading.Thread``; such a thread must be started via
   ``contextvars.copy_context().run(...)``.
"""

from __future__ import annotations

import contextvars
from typing import Any

# The `{"schema": 1, "rows": [...]}` payload for the current run, or None when
# the backend asked nothing (the ordinary case, and every pre-0091 backend).
_current_lineage_request: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("vulture_lineage_checks_requested", default=None)
)


def set_lineage_checks_requested(
    requested: dict[str, Any] | None,
) -> contextvars.Token:
    """Bind *requested* as this run's lineage question; returns a reset handle."""
    return _current_lineage_request.set(requested)


def current_lineage_checks_requested() -> dict[str, Any] | None:
    """This run's lineage question, or ``None`` when nothing was asked."""
    return _current_lineage_request.get()


def reset_lineage_checks_requested(token: contextvars.Token) -> None:
    """Undo one :func:`set_lineage_checks_requested`, for tests."""
    _current_lineage_request.reset(token)
