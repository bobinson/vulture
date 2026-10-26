"""Parse prefetch: a skill's walk sends its next files to idle workers before it reaches them
(feature 0102, LLD §4.1 items 6-8; A44 (2), user decision D-I (ii)).

A skill loops over its files under ``walk(files, families)``: the filtered list, in order, and
the families its rules ask about. The walk is the current one of the skill thread's context (a
``ContextVar``) until it ends; entering it does no I/O and records nothing. The REAL head calls
``advance(path)`` right before it asks ``owns_answer(path)``: the walk's cursor moves past
``path``, and each position of the window ``[cursor, cursor + PREFETCH_AHEAD)`` not considered
yet is considered once, in order, by ``cache.issue_ahead`` — which sends the file's answer
request ahead and files its ticket in the audit's ``TicketIndex`` when the consumer would ask
for it and nothing holds it yet. A position refused for want of a slot ends that advance; the
head's ``refill()``, right after ``owns_answer`` collected its file's ticket and so freed a
slot, considers it again, as does the next advance. Outside a walk, with the audit's breaker
tripped or its index closed, ``advance`` and ``refill`` do nothing, so the regex seams (which
replace the head above ``advance``) and a walk without its head issue nothing.

**One request a key.** ``issue_ahead`` reserves the key in the index (``reserve``) in the same
step that finds nothing holds it, before its read, so two skill walks of one audit never issue
one key twice; the ticket then takes the reservation's place (``file``), or the key is given
back (``release``) when nothing was issued. A flight leader that finds the key reserved — one
skill's head caught up with the other's walk — waits the few moments the issue takes, then
claims the ticket, so it never sends the request a second time.

**No thread, no future.** Everything runs on the consumer's own thread: a ticket is a request
already sent, its reply waiting in the worker's pipe. The key's flight leader claims it
(``cache._build``) — any thread of the audit, so two skills never parse one key twice — and the
walk discards what it filed and nobody claimed when it ends, normally or by a raise. The
audit's index is closed by ``context.leave``, ``context.reset_default`` and the runner's
skill-phase ``finally``: its tickets are discarded and later issues refused, so an abandoned
skill thread goes synchronous.

**The bound.** The pool issues at most ``W - PREFETCH_RESERVE`` tickets process-wide, and a
skill thread holds at most one reservation at a time, so an index holds O(W) entries and each
of its operations is O(1); a walk keeps its list, a position map and two cursors, O(1) per
advance amortised (each position is considered once unless a slot was wanting).

Its module-level imports are ``contextlib``, ``contextvars``, ``threading`` and ``limits``
(read at call time, so a patched bound applies): ``import shared.ast.prefetch`` loads no pool,
cache, model or parser, and ``context`` imports it for ``TicketIndex``.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Protocol

from shared.ast import limits

if TYPE_CHECKING:
    from collections.abc import Hashable, Iterable
    from os import PathLike
    from pathlib import Path

    from shared.ast.context import AuditContext

__all__ = ["TicketIndex", "advance", "refill", "walk"]


class _Filed(Protocol):
    """A ticket as the index holds it: something it can give up (``cache._Shipment``)."""

    def discard(self) -> None: ...


class _Reserved:
    """What a reserved key holds until its ticket is filed or the key released: nothing was
    sent yet, so nothing to give up."""

    __slots__ = ()

    def discard(self) -> None:
        """Nothing was sent."""


_RESERVED = _Reserved()
_NOTHING = (None, None)  # an index entry's (walk, ticket) for a key it does not hold


class TicketIndex:
    """One audit's tickets issued ahead (§4.1 items 6-8), each under its answer key and tagged
    with the walk that issued it: reserved before its issue (module docstring), claimed by the
    key's flight leader, drained by its walk when that ends, all discarded when the index is
    closed (the audit's end), after which nothing is reserved. Safe for the audit's skill
    threads, which reserve, file and claim at once."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._settled = threading.Condition(self._lock)  # a reservation filed or given back
        self._filed: dict[Hashable, tuple[object, _Filed]] = {}
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def reserve(self, key: Hashable, walk: object) -> bool:
        """``key`` reserved for the ticket ``walk`` is about to issue, in one step with the test
        that nothing holds it; False when the index is closed or holds ``key``, filed or
        reserved."""
        with self._lock:
            free = not (self._closed or key in self._filed)
            if free:
                self._filed[key] = (walk, _RESERVED)
        return free

    def release(self, key: Hashable) -> None:
        """``key``'s reservation given back: nothing was issued under it."""
        with self._lock:
            if self._filed.get(key, _NOTHING)[1] is _RESERVED:
                del self._filed[key]
            self._settled.notify_all()

    def file(self, key: Hashable, filed: _Filed) -> None:
        """``filed`` in the place of ``key``'s reservation, for the walk that reserved it; given
        up at once, outside the lock, when the reservation is gone (the index closed, or its
        walk drained)."""
        with self._lock:
            walk, held = self._filed.get(key, _NOTHING)
            kept = held is _RESERVED
            if kept:
                self._filed[key] = (walk, filed)
            self._settled.notify_all()
        if not kept:
            filed.discard()

    def claim(self, key: Hashable) -> _Filed | None:
        """The ticket filed under ``key``, taken out: one claimant, ever. A key still reserved —
        its ticket on its way from another thread of the audit — is waited for, at most
        ``WALL_TIMEOUT_S``: then claimed, or, given back, left to its claimant's own request."""
        with self._lock:
            self._settled.wait_for(lambda: self._unreserved(key), limits.WALL_TIMEOUT_S)
            held = self._filed.get(key, _NOTHING)[1]
            claimed = held is not None and held is not _RESERVED
            if claimed:
                del self._filed[key]
        return held if claimed else None

    def _unreserved(self, key: Hashable) -> bool:
        """Under the lock: ``key`` holds no reservation (a ticket, or nothing)."""
        return self._filed.get(key, _NOTHING)[1] is not _RESERVED

    def drain(self, walk: object) -> None:
        """Discard every ticket ``walk`` filed that nobody claimed."""
        with self._lock:
            mine = [key for key, (by, _) in self._filed.items() if by is walk]
            left = [self._filed.pop(key)[1] for key in mine]
            self._settled.notify_all()
        _discard(left)

    def close(self) -> None:
        """Discard every ticket filed, and refuse any filed from now on."""
        with self._lock:
            self._closed = True
            left, self._filed = [filed for _, filed in self._filed.values()], {}
            self._settled.notify_all()
        _discard(left)


def _discard(tickets: list[_Filed]) -> None:
    """Give ``tickets`` up, outside the index's lock (a discard may read a reply)."""
    for ticket in tickets:
        ticket.discard()


class _Walk:
    """One skill's walk (module docstring): its files, each file's position, the families its
    rules ask about, its cursor and the next position not yet considered."""

    __slots__ = ("_cursor", "_families", "_next", "_positions", "files")

    def __init__(self, files: list[Path], families: frozenset[str]) -> None:
        self.files = files
        self._positions: dict[str | PathLike[str], int] = {path: at for at, path in enumerate(files)}
        self._families = families
        self._cursor = 0
        self._next = 0

    def advance(self, path: str | PathLike[str]) -> None:
        """Move the cursor past ``path`` and consider the window ahead of it (``advance``)."""
        position = self._positions.get(path)
        if position is None:
            return
        audit = _current()
        if _issuing(audit):
            self._cursor = max(self._cursor, position + 1)
            self._next = max(self._next, self._cursor)
            self._consider(audit)

    def refill(self) -> None:
        """Consider the window again, the cursor unmoved: the positions the last advance left
        for want of a slot (``refill``)."""
        audit = _current()
        if _issuing(audit):
            self._consider(audit)

    def _consider(self, audit: AuditContext) -> None:
        """Each position of ``[cursor, cursor + PREFETCH_AHEAD)`` not considered yet, in order,
        until one is refused a slot; each ticket filed as this walk's."""
        from shared.ast.cache import issue_ahead

        end = min(self._cursor + limits.PREFETCH_AHEAD, len(self.files))
        while self._next < end and issue_ahead(self.files[self._next], self._families, audit, self):
            self._next += 1


# The walk of this context, if one is open (a skill thread's).
_WALK: ContextVar[_Walk | None] = ContextVar("shared_ast_walk", default=None)


@contextmanager
def walk(files: Iterable[Path], families: Iterable[str]) -> Iterator[list[Path]]:
    """A skill's file loop: ``with walk(files, families) as walked: for path in walked: ...``
    yields ``files`` as given, in order, with ``families`` the ones its rules ask about. The
    walk is the current one of the caller's context while it is open; on exit, normally or by
    a raise, its unclaimed tickets are discarded and the context's previous walk restored."""
    current = _Walk(list(files), frozenset(families))
    token = _WALK.set(current)
    try:
        yield current.files
    finally:
        try:
            _current().tickets.drain(current)
        finally:
            _WALK.reset(token)


def advance(path: str | PathLike[str]) -> None:
    """The real head's call, right before it asks ``owns_answer(path)``: the current walk
    sends its next files ahead (module docstring); nothing outside a walk."""
    current_walk = _WALK.get()
    if current_walk is not None:
        current_walk.advance(path)


def refill() -> None:
    """The real head's call right after ``owns_answer`` collected its file's ticket, which
    freed that ticket's slot: the current walk considers again what its last advance left for
    want of a slot (module docstring); nothing outside a walk."""
    current_walk = _WALK.get()
    if current_walk is not None:
        current_walk.refill()


def _current() -> AuditContext:
    """The audit of this context (``context.current()``), imported at call time: ``context``
    imports this module."""
    from shared.ast.context import current

    return current()


def _issuing(audit: AuditContext) -> bool:
    """Whether ``audit`` still issues: its breaker closed and its ticket index open."""
    return not (audit.breaker.tripped or audit.tickets.closed)
