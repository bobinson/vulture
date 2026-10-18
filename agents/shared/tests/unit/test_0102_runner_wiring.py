"""Feature 0102 (D20, plan task 3.4): a skill thread sees the audit's context.

``run_combined_audit`` enters one ``AuditContext`` per audit (a ``ContextVar``
set at the ``clear_caches()`` site) and submits each skill through
``contextvars.copy_context().run``. Skills run on the runner's thread pool, and
a pool thread does NOT inherit the submitting thread's context variables: it
starts from an empty context. Without the ``copy_context`` submit, a decline
recorded by a skill would land in the process default context, and the
audit's ``result`` snapshot would report zero declines.

The stub skill records one decline through
``shared.ast.context.current().decline(...)`` from inside the pool thread. It
reads no ``.engine``: ``AuditContext`` has no engine field (no flag, D12).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from shared.audit_runner import run_combined_audit
from tests.support.agent_run import result_payload, thinking_lines

_CATEGORY = "stub_decline"


def _record_one_decline() -> None:
    """Record one structurally-built decline into the current audit context."""
    from shared.ast import FamilyRule, Flow, Origin
    from shared.ast.context import current

    rule = FamilyRule(
        family="path", check_id="stub.path", category="CWE-22", title="Stub rule",
        severity="high", recommendation="Stub recommendation", cwe_id="22",
    )
    flow = Flow(
        family="path", sink=0, sink_line=1, span=(0, 1), arg=0,
        origins=frozenset({Origin(cls="external", role="request")}),
        hops=(), guards=(), truncated=False,
    )
    current().decline(flow, rule, "guarded:validate")


def _audit(source_path: str, off_caller_thread: list[bool]) -> list[str]:
    """Run a skills-only audit whose one skill records a decline.

    The skill appends whether it ran on a thread other than the one consuming
    the audit generator, so the test can tell a pool thread from the caller's.
    """
    caller = threading.get_ident()

    def declining_skill(_source_path: str) -> dict[str, Any]:
        off_caller_thread.append(threading.get_ident() != caller)
        _record_one_decline()
        return {"findings": []}

    return list(run_combined_audit(
        run_id="0102-wiring", source_path=source_path, categories=[_CATEGORY],
        skill_map={_CATEGORY: declining_skill}, use_llm=False,
    ))


def _skill_failures(events: list[str]) -> list[str]:
    """The runner's ``Skill <cat> failed: ...`` lines; a failing stub says why."""
    return [line for line in thinking_lines(events) if line.startswith(f"Skill {_CATEGORY} failed")]


def test_skill_thread_sees_audit_context(tmp_path: Path) -> None:
    """A decline recorded on a pool thread reaches the audit's ``ast_coverage``."""
    off_caller_thread: list[bool] = []

    events = _audit(str(tmp_path), off_caller_thread)

    coverage = result_payload(events).get("ast_coverage") or {}
    observed = {
        "skill ran once, on a pool thread": off_caller_thread,
        "skill failures": _skill_failures(events),
        "ast_coverage.declines.count": coverage.get("declines", {}).get("count"),
    }
    assert observed == {
        "skill ran once, on a pool thread": [True],
        "skill failures": [],
        "ast_coverage.declines.count": 1,
    }
