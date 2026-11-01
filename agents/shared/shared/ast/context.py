"""The per-audit ``AuditContext`` (feature 0102, LLD D10, D12, D20, §4, §5; A18, A20, A31, A41).

Every concurrent audit of an agent process owns one ``AuditContext``: its source ``root``, its
``coverage`` (the §10.2 record), its bounded decline ``ledger`` (§10.3), its circuit
``breaker`` (D10), since A18 the ``declined`` map of the parses it refused and, since A44 (2),
the ``tickets`` its skill threads issued ahead (``prefetch.TicketIndex``, §4.1 item 8). There
is no ``engine`` field: no flag selects a tier (D12).

The current audit lives in a ``ContextVar`` (D20). ``enter(root)`` makes a new audit current in
the caller's context and returns the ``Token``; ``leave(token)`` gives that context back what
it held before, so a direct caller of it is on the process default again (A41 (6): the runner
calls it right after its ``ast_coverage`` snapshot), and closes the audit's ticket index. ``leave`` never raises: a token from
another context, or one already used, makes the process default current instead. There is no
``exit``, and ``clear_caches()`` cannot detach an entered audit: it resets only the default
(below). A skill thread reaches its audit because the runner submits each skill through
``contextvars.copy_context().run`` (one line, plan 3.4).

Outside any audit, ``current()`` is the PROCESS DEFAULT, one object on every thread (the corpus
runner and unit tests are such callers). ``reset_default()`` replaces it with a fresh one:
tallies, fallback counts, declines, breaker and declined map; ``file_scanner.clear_caches()``
calls it in a process that loaded the layer (A20). It never touches an entered audit
(A31 (6)), and the model cache, shared by every audit, is not per-audit state (D5).
"""

from __future__ import annotations

import os
import threading
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shared.ast.coverage import Coverage
from shared.ast.declines import DeclineLedger, DeclineRecord, render_origins
from shared.ast.limits import CIRCUIT_BREAK_AFTER
from shared.ast.prefetch import TicketIndex

if TYPE_CHECKING:
    from shared.ast.flow import Flow, _Rule

__all__ = ["AuditContext", "Breaker", "current", "enter", "leave", "reset_default"]


class Breaker:
    """D10: one audit's circuit breaker. ``CIRCUIT_BREAK_AFTER`` worker timeouts or crashes
    open it for the rest of the audit (every later file is ``circuit_open``); it bounds the
    audit that owns it, never the process (risk 13)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._faults = 0

    @property
    def tripped(self) -> bool:
        return self._faults >= CIRCUIT_BREAK_AFTER

    def record(self) -> None:
        """One more timeout or crash (the pool decides which faults count, D10)."""
        with self._lock:
            self._faults += 1


@dataclass(frozen=True, slots=True, eq=False)
class AuditContext:
    """One audit's state (D20, A18). ``declined`` maps a model-cache key (D5, A14) to the
    bare reason its parse was refused for (A31 (5)); ``tickets`` holds the requests its skill
    threads issued ahead (§4.1 item 8), closed when the audit ends; ``root`` is None for the
    process default, which belongs to no walk."""

    root: Path | None
    coverage: Coverage
    ledger: DeclineLedger
    breaker: Breaker
    declined: dict[tuple[Any, ...], str]
    tickets: TicketIndex = field(default_factory=TicketIndex)

    @classmethod
    def new(cls, root: str | os.PathLike[str] | None) -> AuditContext:
        """A fresh audit of ``root``: nothing tallied, declined or issued ahead, the breaker
        closed."""
        ledger, breaker = DeclineLedger(), Breaker()
        where = None if root is None else Path(root)
        return cls(where, Coverage(ledger, breaker), ledger, breaker, {})

    def tally(self, name: str, n: int = 1) -> None:
        """``n`` more of the §10.2 tally ``name`` (the call §8.5's ``decide`` makes)."""
        self.coverage.tally(name, n)

    def decline(self, path: str | os.PathLike[str], flow: Flow, rule: _Rule, label: str) -> None:
        """``decide`` declined ``flow`` in the consumer's file ``path`` under ``rule`` with the
        decline ``label`` (A30 (1)): one ``DeclineRecord`` at the sink line."""
        origins = render_origins(flow.origins)
        self.ledger.add(DeclineRecord(rule.family, Path(path), flow.sink_line, label, origins))


# The current audit of this context, if one was entered (D20).
_AUDIT: ContextVar[AuditContext | None] = ContextVar("shared_ast_audit", default=None)
# The process default: the audit of every caller that entered none.
_default = AuditContext.new(None)


def current() -> AuditContext:
    """The audit this context entered, else the process default (D20)."""
    audit = _AUDIT.get()
    return _default if audit is None else audit


def enter(root: str | os.PathLike[str]) -> Token[AuditContext | None]:
    """Make a new audit of ``root`` current in the caller's context; its ``Token``."""
    return _AUDIT.set(AuditContext.new(root))


def leave(token: Token[AuditContext | None]) -> None:
    """Leave the audit ``enter`` returned ``token`` for: the caller's context holds what it
    held before (A41 (6)), and the audit's ticket index is closed (§4.1 item 8: its tickets
    discarded, later issues refused). Never raises into the runner: a token already used, or
    one from another context, makes the process default current instead."""
    left = _AUDIT.get()
    try:
        _AUDIT.reset(token)
    except (RuntimeError, ValueError):  # used / set in another context
        _AUDIT.set(None)
    if left is not None:
        left.tickets.close()


def reset_default() -> None:
    """Start the process default over (A20, A31 (6)), the old default's ticket index closed;
    an entered audit is untouched."""
    global _default
    old, _default = _default, AuditContext.new(None)
    old.tickets.close()
