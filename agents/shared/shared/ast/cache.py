"""The model cache, ``get_model``, ``owns`` and ``owns_answer`` (feature 0102, LLD D5, D10, §4,
§4.1, §5, §10.2).

One process-wide store of parsed ``FileModel`` objects and worker-built ``FileAnswer`` objects,
shared by every concurrent audit of the agent process (§4):

* **Key (D5, A14)** = ``(resolved_path, size, mtime_ns, GRAMMAR_PACK_VERSION, MODEL_SCHEMA,
  language, grammar entry point)``. Every spelling of one file under one grammar is one
  entry; a name whose suffix selects another entry point (a ``.tsx`` link to a ``.ts`` file)
  is a second entry; a rewrite at the same size or a restored mtime misses, so staleness and
  cross-audit poisoning (T9) are handled by the key.
* **The key is the stat seen before the read (A9).** The text is read from disk past the
  scanner's path-keyed read cache, whose copy may predate the stat, and the file is stat'ed
  again after the read: a model whose file changed in between (content, or a link
  re-pointed) is served but never stored, so no model is ever cached under a key its text
  does not belong to.
* **Byte budget (D5)** = ``min(128 MB, 25 % of the deployment limit)`` (``pool``'s
  ``model_cache_budget`` over feature 0103's one limit reader). LRU by ``bytes_estimate``,
  the footprint a model's build made (A17): least-recent entries go, only as many as needed;
  a model heavier than the whole budget is served, never stored. Evicted models are dropped
  after the cache lock is, so no request waits on their teardown; an analysis refers to its
  model weakly, so reference counting frees an evicted model and its analysis once no holder
  keeps them.
* **An analysis is charged to its model (A35).** Each stored model is one entry, which carries
  its weight. A stored model reports its analysis' ``bytes_estimate`` when the analysis is
  first built (``FileModel.charge_to``, to its own entry, which it reaches weakly): the
  entry's weight grows by it, once, the entry becomes the most recently used, and
  least-recent entries go until the budget holds again — the entry itself last, which then
  stays with its holders as a model served, not stored. An entry the cache gave up (evicted,
  or cleared) is gone, so its model charges nothing. A model never stored is charged nowhere:
  it keeps its analysis for its own lifetime.
* **Single-flight (D5).** The first request for a key leads its parse; a concurrent one
  waits on the leader's per-key ``Event`` and takes the leader's outcome. The cache lock is
  never held across a parse. The leader lands its outcome and sets the Event in a
  ``finally``, so no waiter is stranded; a waiter whose leader died without an outcome
  re-boards (re-leads or joins), so the worst case is one redundant parse.
* **Positive outcomes only; refusals are per audit (A18, A31 (5)).** Nothing negative enters
  this cache. A parse refused for a reason of the file's bytes (``MEMOISED_REASONS``, derived
  from ``coverage.REASONS``) is recorded in the current audit's ``declined`` map under the key,
  as the bare reason: the same key again in that audit is None with no pool call, no second
  breaker fault and no second fallback tally, and the next audit asks again. ``spawn_failed`` (a fault of the pool, not of the file) is not
  memoised; ``circuit_open`` needs no memo (the breaker stays open for the audit).
* **Cache events (§10.2 ``tallies.cache``, D14, A41 (8)).** A request that leads a parse is a
  ``miss``; every later request of its key is a ``hit`` — whether it joins the parse in flight,
  reads the stored model or reads the audit's ``declined`` memo — so an audit's counts do not
  depend on how its skill threads interleave. ``evictions`` counts the models evicted.
* **Never emptied per audit (D5).** ``file_scanner.clear_caches()`` starts the default
  audit over (``context.reset_default()``, A20) and leaves every model here: the models are
  shared by the audits still running, and the key already carries the mtime. ``clear()``
  evicts COMPLETED entries only; an in-flight key keeps its leader, which a later request
  still joins.

* **Two kinds, one code path (§4.1 item 4).** ``owns_answer``, the production heads' call, is
  ``owns`` asking for the file's ANSWER (``answer.FileAnswer``: its coverage facts and every
  owned family's candidate flows, built by the worker, admitted by D3') instead of its
  skeleton. Ownership, the A18 memo, A9's stat, the breaker and every coverage record are the
  same code; the request's kind (``_Kind``) sets only the header's ``answer`` flag, the reply's
  admission and the key's suffix: an answer's key is D5's with ``ANSWER_SCHEMA`` appended, so
  a model's key — and ``get_model``, the library path (bench, goldens, fact dump) — is
  unchanged. One budget weighs both by ``bytes_estimate``; an answer charges no analysis.
* **Tickets (§4.1 items 6, 7).** ``issue_ahead`` sends a file's answer request ahead, on a
  skill's own thread (``prefetch.advance``), when its consumer would ask for it and nothing
  holds its key — the key reserved in the audit's ``TicketIndex`` in the same step — and files
  the ticket there in the reservation's place. Of the cache it reads
  only ``ModelCache.known`` (no LRU touch, no event); it stores and records nothing. The key's
  flight leader — its ``_build`` — claims a ticket filed under its EXACT key and collects it in
  place of a request, so ``tallies.cache`` is the synchronous run's on any interleaving
  (A41 (8)), and nothing enters the cache before its consumer asks: prefetch never evicts.

``get_model`` = ``profile_for`` -> stat (key, size cap) -> the audit's ``declined`` map ->
cache -> read -> UTF-8 encode -> ``WorkerPool.parse`` -> ``validate_reply`` ->
``FileModel.from_doc``; ``owns_answer`` claims a ticket or reads, then ``validate_answer``.
Neither raises. Each outcome is recorded on the current audit's coverage
(``context.current()``, D20), once per path (A8): a ``None`` for a file with a profile as its
§10.2 fallback reason (an unreadable path is not a fallback: no tier reads it, A11), a model or
an answer as the facts it carries, an owned file as ``parsed``.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path
from typing import Any, TypeGuard

from shared.ast import ANSWER_SCHEMA, MODEL_SCHEMA
from shared.ast import profile as _profile
from shared.ast._frames import ModelError
from shared.ast._validate import validate_reply
from shared.ast.answer import FileAnswer, validate_answer
from shared.ast.context import AuditContext, current
from shared.ast.coverage import (
    CACHE_EVICTIONS,
    CACHE_HITS,
    CACHE_MISSES,
    MEMOISED_REASONS,
)
from shared.ast.limits import MAX_FILE_SIZE
from shared.ast.model import FileModel
from shared.ast.pool import ParseResult, Ticket, get_pool, model_cache_budget
from shared.ast.profile import LanguageProfile, profile_for
from shared.ast.roles import needed_families
from shared.tools import membudget
from shared.tools.file_scanner import MAX_FILE_SIZE as READ_CAP
from shared.tools.file_scanner import read_file_uncached

__all__ = ["ModelCache", "clear", "get_model", "issue_ahead", "owns", "owns_answer"]

logger = logging.getLogger(__name__)

# D5 as A14 extends it: (resolved path, size, mtime_ns, GRAMMAR_PACK_VERSION, MODEL_SCHEMA,
# language, grammar entry point); an answer's key has ``ANSWER_SCHEMA`` appended (§4.1 item 4).
type Key = tuple[Any, ...]
# What the cache serves a request: a model (the library path) or an answer (the production
# heads, §4.1). One cache, one budget, two kinds.
type Served = FileModel | FileAnswer
_SERVED = (FileModel, FileAnswer)
# A miss's outcome: what it serves; a §10.2 fallback reason every requester tallies; or None
# for a path no tier can read (nothing to tally).
type Outcome = Served | str | None
# A build's outcome and whether it may be stored (A9: not when its file changed while read).
type Built = tuple[Outcome, bool]

# The largest file the layer models: its own cap and the reader's, whichever is lower — a
# file the reader refuses has no text to ship (§4, §8.7). Not a cap of its own (D18).
_SIZE_CAP = min(MAX_FILE_SIZE, READ_CAP)


# ── the cache (D5) ───────────────────────────────────────────────────────────


@dataclass(slots=True, eq=False)
class _Flight:
    """One key's parse in progress: ``done`` is set once the leader is finished, with
    ``settled`` telling whether it left an ``outcome`` for its waiters, and ``keep`` whether
    that outcome may be stored."""

    done: threading.Event = field(default_factory=threading.Event)
    settled: bool = False
    keep: bool = True
    outcome: Outcome = None


# What a waiter gets from a flight whose leader left no outcome: board again.
_REBOARD = object()


@dataclass(slots=True, eq=False, weakref_slot=True)
class _Entry:
    """One stored model or answer (A35, §4.1 item 4): its key, what it serves and its weight —
    the ``bytes_estimate``, then a model's analysis' too once ``analysed`` (an answer charges
    nothing). Only the cache holds an entry: a model's charge reaches it weakly, so an entry
    the cache gives up is freed under the cache lock and its model charges nothing after
    (``_charged``)."""

    key: Key
    served: Served
    weight: int
    analysed: bool = False


def _evicted(models: list[Served]) -> None:
    """Models and answers an insertion or a charge evicted, tallied on the current audit outside the cache
    lock (the caller drops them once it returns)."""
    if models:
        current().coverage.record_cache(CACHE_EVICTIONS, len(models))


class ModelCache:
    """D5's one cache: a byte-budgeted LRU of immutable models and answers (§4.1 item 4),
    single-flight per key."""

    def __init__(self, budget: int) -> None:
        self.budget = budget
        self.bytes = 0
        self._lock = threading.Lock()
        self._models: OrderedDict[Key, _Entry] = OrderedDict()
        self._flights: dict[Key, _Flight] = {}

    def get(self, key: Key, build: Callable[..., Built], *args: Any) -> Outcome:
        """The model under ``key``, or ``build(*args)``'s outcome, built once however many
        threads ask at once."""
        while True:
            found, leads = self._board(key)
            if leads:
                return self._lead(key, found, build, args)  # type: ignore[arg-type]
            outcome = _joined(found)
            if outcome is not _REBOARD:
                current().coverage.record_cache(CACHE_HITS)
                return outcome  # type: ignore[return-value]

    def known(self, key: Key) -> bool:
        """Whether ``key`` is stored or in flight, read under the lock with no LRU touch and no
        cache event: the prefetch's one read of the cache (§4.1 item 4)."""
        with self._lock:
            return key in self._models or key in self._flights

    def clear(self) -> None:
        """Evict every completed model; an in-flight parse keeps its leader and waiters.
        The evicted models are dropped once the lock is."""
        with self._lock:
            evicted, self._models = self._models, OrderedDict()
            self.bytes = 0
            models = [entry.served for entry in evicted.values()]
            evicted.clear()  # the entries go under the lock: none is charged after
        models.clear()

    def _board(self, key: Key) -> tuple[Served | _Flight, bool]:
        """Under the lock, in one step: the stored model (made the most recently used), the
        in-flight parse to join, or a new flight this thread leads (``True``)."""
        with self._lock:
            entry = self._models.get(key)
            if entry is not None:
                self._models.move_to_end(key)
                return entry.served, False
            flight = self._flights.get(key)
            if flight is not None:
                return flight, False
            flight = self._flights[key] = _Flight()
            return flight, True

    def _lead(
        self, key: Key, flight: _Flight, build: Callable[..., Built], args: tuple[Any, ...]
    ) -> Outcome:
        try:
            flight.outcome, flight.keep = build(*args)
            flight.settled = True
        finally:
            evicted = self._land(key, flight)
            flight.done.set()
        current().coverage.record_cache(CACHE_MISSES)
        _evicted(evicted)
        return flight.outcome

    def _land(self, key: Key, flight: _Flight) -> list[Served]:
        """Under the lock: store the leader's model (if any, and if it may be kept) and retire
        its flight, in one step, so a request sees one or the other. Returns the models
        evicted to make room, dropped by the caller once the lock is."""
        with self._lock:
            del self._flights[key]
            return self._store(key, flight.outcome) if flight.keep else []

    def _store(self, key: Key, outcome: Outcome) -> list[Served]:
        if not isinstance(outcome, _SERVED) or outcome.bytes_estimate > self.budget:
            return []
        evicted = self._make_room(outcome.bytes_estimate)
        entry = self._models[key] = _Entry(key, outcome, outcome.bytes_estimate)
        self.bytes += entry.weight
        outcome.charge_to(partial(self._charge, weakref.ref(entry)))
        return evicted

    def _charge(self, entry: weakref.ref[_Entry], weight: int) -> None:
        """A35: the entry's model built its analysis, which weighs ``weight``. While the entry
        is stored, it is charged that once and made the most recently used, and least-recent
        entries go until the budget holds (the entry itself last)."""
        with self._lock:
            evicted = self._charged(entry(), weight)
        _evicted(evicted)

    def _charged(self, entry: _Entry | None, weight: int) -> list[Served]:
        if entry is None or entry.analysed:
            return []
        entry.analysed = True
        entry.weight += weight
        self.bytes += weight
        self._models.move_to_end(entry.key)
        return self._make_room(0)

    def _make_room(self, weight: int) -> list[Served]:
        """Evict least-recently-used entries — each weighs its model and its analysis' charge,
        or its answer — until ``weight`` more fits the budget; what they served."""
        evicted: list[Served] = []
        while self._models and self.bytes + weight > self.budget:
            _, old = self._models.popitem(last=False)
            self.bytes -= old.weight
            evicted.append(old.served)
        return evicted


def _joined(found: Served | _Flight) -> Outcome | object:
    """A stored model or answer, or the outcome of the flight once its leader is done
    (``_REBOARD`` when the leader left none)."""
    if not isinstance(found, _Flight):
        return found
    found.done.wait()
    return found.outcome if found.settled else _REBOARD


_CACHE = ModelCache(model_cache_budget(membudget.deployment_memory_limit()))


def clear() -> None:
    """Evict every completed model (an explicit hook; never called per audit, D5)."""
    _CACHE.clear()


# ── what a request asks for (§4.1 item 4) ───────────────────────────────────


def _model(
    doc: Mapping[str, Any], profile: LanguageProfile, grammar: str, text: str, data: bytes
) -> FileModel:
    """A skeleton checked at the boundary and against its request (D3, §11 T10), then the
    model of ``text``, whose UTF-8 encoding ``data`` the worker parsed."""
    return FileModel.from_doc(validate_reply(doc, profile, grammar, data), text)


def _answer(
    doc: Mapping[str, Any], profile: LanguageProfile, grammar: str, text: str, data: bytes
) -> FileAnswer:
    """An answer checked at the boundary and against its request (D3', §11 T10, T11)."""
    return validate_answer(doc, profile, grammar, data, text)


@dataclass(frozen=True, slots=True)
class _Kind:
    """What a request asks a worker for: a skeleton, admitted as a ``FileModel`` (the library
    path: ``get_model``, ``owns``), or an answer, admitted as a ``FileAnswer`` (the production
    heads' ``owns_answer``, §4.1). Both run one code path; the kind sets the header's
    ``answer`` flag, the reply's admission and the key's suffix."""

    answer: bool
    suffix: tuple[int, ...]
    admit: Callable[[Mapping[str, Any], LanguageProfile, str, str, bytes], Served]


_MODEL = _Kind(False, (), _model)
_ANSWER = _Kind(True, (ANSWER_SCHEMA,), _answer)


@dataclass(frozen=True, slots=True)
class _Ask:
    """One request of a file: the path as asked, its profile and grammar entry point, the stat
    its key was read from (A9), the kind it asks for, and its key (D5, A14, §4.1 item 4)."""

    path: Path
    profile: LanguageProfile
    grammar: str
    before: os.stat_result
    kind: _Kind
    key: Key

    @property
    def variant(self) -> str | None:
        """The grammar entry point on the wire: None for the language's own, which the worker
        defaults to."""
        return None if self.grammar == self.profile.grammar_attr else self.grammar

    def send(self, data: bytes) -> ParseResult:
        """``data`` to the pool as ``WorkerPool.parse`` (§4), the answer flag only for an
        answer: a skeleton request is today's, word for word."""
        flag = (True,) if self.kind.answer else ()
        return get_pool().parse(self.profile.language, data, self.variant, *flag)

    def issue(self, data: bytes) -> Ticket | None:
        """``data`` issued ahead to the pool (``WorkerPool.issue``, §4.1 item 5): ``send``'s
        request, its reply left in the worker's pipe."""
        return get_pool().issue(self.profile.language, data, self.variant, self.kind.answer)


@dataclass(frozen=True, slots=True, eq=False)
class _Shipment:
    """A file's bytes on their way to a worker (§4): the text the parent read once (size cap,
    ``errors="replace"``, read recorder), its UTF-8 encoding — every span indexes it — and the
    stat the read followed (A9); for a request issued ahead, its ticket (§4.1 item 6)."""

    text: str
    data: bytes
    stat: os.stat_result
    ticket: Ticket | None = None

    def reply(self, ask: _Ask) -> ParseResult:
        """The worker's reply to ``ask``: the ticket collected, or a synchronous request."""
        ticket = self.ticket
        return ask.send(self.data) if ticket is None else ticket.pool.collect(ticket)

    def discard(self) -> None:
        """Give the ticket up unclaimed (a walk's end, the audit's), recording nothing."""
        ticket = self.ticket
        if ticket is not None:
            ticket.pool.discard(ticket)


# ── get_model, owns and owns_answer (§5, §4.1) ───────────────────────────────


def get_model(path: str | Path) -> FileModel | None:
    """``path``'s model, or None: the file falls back to the regex tier, its reason tallied
    on the current audit (once per path, A8). Never raises."""
    return _served(path, _MODEL)  # type: ignore[return-value]


def owns(path: str | Path) -> FileModel | None:
    """``get_model(path)`` when the AST tier owns the file — the model has no ERROR node and
    this audit's breaker is closed (D10) — else None (regex fallback, tallied). No flag."""
    return _owned(path, get_model(path))  # type: ignore[return-value]


def owns_answer(path: str | Path) -> FileAnswer | None:
    """``owns`` for the production heads (§4.1 item 4): ``path``'s worker-built ANSWER when the
    AST tier owns the file, else None — by ``owns``' one code path (ownership, the A18 memo,
    A9's stat, the breaker, every coverage record), under the answer key, a ticket issued ahead
    collected in place of a request. Never raises."""
    return _owned(path, _served(path, _ANSWER))  # type: ignore[return-value]


def _served(path: str | Path, kind: _Kind) -> Served | None:
    """What ``kind`` serves for ``path`` on the current audit, its outcome recorded there."""
    audit = current()
    return _recorded(audit, path, _outcome(path, audit, kind))


def _owned(path: str | Path, found: Served | None) -> Served | None:
    """``found`` when the AST tier owns its file (D10), recorded ``parsed``; else None, the
    reason recorded as the file's fallback."""
    if found is None:
        return None
    audit = current()
    reason = _not_owned(audit, found)
    if reason is not None:
        audit.coverage.record_fallback(path, reason)
        return None
    audit.coverage.record_parsed(path)
    return found


def _recorded(audit: AuditContext, path: str | Path, outcome: Outcome) -> Served | None:
    """``outcome`` recorded on ``audit``'s coverage: a reason as its fallback, a model or an
    answer as the facts it carries (A31 (8)); what it serves, or None."""
    if isinstance(outcome, str):
        audit.coverage.record_fallback(path, outcome)
        return None
    if outcome is not None:
        audit.coverage.record_model(path, outcome)
    return outcome


def _not_owned(audit: AuditContext, found: Served) -> str | None:
    """Why the AST tier does not own a file it has a model or an answer of, or None."""
    if audit.breaker.tripped:
        return "circuit_open"
    if found.error_nodes:
        return "parse_error"
    return None


def _outcome(path: str | Path, audit: AuditContext, kind: _Kind) -> Outcome:
    """What ``kind`` serves for ``path``, or the reason there is none. ``unsupported`` is
    decided first, from the extension alone (O1); then the stat (``_asked``)."""
    profile = profile_for(path)
    if profile is None:
        return "unsupported"
    ask = _asked(path, profile, kind)
    return _keyed(ask, audit) if isinstance(ask, _Ask) else ask


def _asked(path: str | Path, profile: LanguageProfile, kind: _Kind) -> _Ask | str | None:
    """``path``'s request of ``kind``, or why there is none: None for anything but a regular
    file (no tier reads it, A11); ``too_large`` from the stat, before any read or worker."""
    found = _regular_file(path)
    if found is None:
        return None
    resolved, info = found
    if info.st_size > _SIZE_CAP:
        return "too_large"
    grammar = profile.grammar_for(path)
    key = (*_model_key(resolved, info, profile, grammar), *kind.suffix)
    return _Ask(Path(path), profile, grammar, info, kind, key)


def _keyed(ask: _Ask, audit: AuditContext) -> Outcome:
    """A key this audit declined earlier (A18), without asking the pool; else the cache's
    outcome, a refusal memoised (by the leader's ``_build`` before its flight lands; here for a
    request that joined the flight of another audit's leader)."""
    declined = audit.declined.get(ask.key)
    if declined is not None:
        audit.coverage.record_cache(CACHE_HITS)  # A41 (8): a later request of the key
        return declined
    return _remembered(audit, ask.key, _CACHE.get(ask.key, _build, audit, ask))


def _model_key(resolved: str, info: os.stat_result, profile: LanguageProfile, grammar: str) -> Key:
    """D5's key as A14 extends it. The grammar pack stamp is read here, on first use (A16)."""
    return (
        resolved, info.st_size, info.st_mtime_ns, _profile.GRAMMAR_PACK_VERSION, MODEL_SCHEMA,
        profile.language, grammar,
    )


def _remembered(audit: AuditContext, key: Key, outcome: Outcome) -> Outcome:
    """``outcome``, recorded in ``audit``'s ``declined`` map first when it is a memoised
    refusal (A18): the bare reason under the key (A31 (5))."""
    if isinstance(outcome, str) and outcome in MEMOISED_REASONS:
        audit.declined[key] = outcome
    return outcome


def _regular_file(path: str | Path) -> tuple[str, os.stat_result] | None:
    """The resolved path and its stat, or None for anything but a regular file: a missing
    path, a directory, a dangling or looping link, a name the OS refuses."""
    try:
        resolved = os.path.realpath(path)
        info = os.stat(resolved)
    except (OSError, ValueError):
        return None
    return (resolved, info) if stat.S_ISREG(info.st_mode) else None


def _build(audit: AuditContext, ask: _Ask) -> Built:
    """A miss, led by a request of ``audit``: the parse, made safe — an unexpected fault is
    ``worker_error``, never a raise — its refusal memoised in ``audit`` BEFORE its flight
    lands (A18, A41 (8)). A later request of the key in this audit reads the memo — a hit,
    with no second pool call and no second breaker fault — and never finds the key with
    neither a flight nor a memo, which would lead a second parse."""
    try:
        built = _parse(audit, ask)
    except Exception as exc:  # get_model never raises (§5)
        logger.warning("ast model build: unexpected %s; file falls back", type(exc).__name__)
        built = "worker_error", True
    _remembered(audit, ask.key, built[0])
    return built


def _parse(audit: AuditContext, ask: _Ask) -> Built:
    """§4: the parent reads the text once and ships its UTF-8 encoding; every span of what the
    worker answers indexes that encoding. A ticket this audit filed under the key is claimed
    instead — by the key's flight leader alone, which this build is — and collected (§4.1 item
    7). A9: what a file changed since the key's stat answers is served but not kept."""
    shipment = _claimed(audit, ask) or _read(ask)
    if shipment is None:
        return None, True
    outcome = _admitted(ask, shipment)
    return outcome, isinstance(outcome, str) or _unchanged(ask, shipment)


def _claimed(audit: AuditContext, ask: _Ask) -> _Shipment | None:
    """The ticket ``audit`` filed under ``ask``'s exact key, popped (§4.1 item 7): answers only;
    a file rewritten since its issue has another key, and its ticket stays unclaimed."""
    return audit.tickets.claim(ask.key) if ask.kind.answer else None


def _read(ask: _Ask) -> _Shipment | None:
    """``ask``'s text read from disk now, past the scanner's path-keyed cache (A9: after the
    key's stat), and its UTF-8 encoding; None for a file no tier can read."""
    text = read_file_uncached(ask.path)
    return None if text is None else _Shipment(text, text.encode("utf-8"), ask.before)


def _admitted(ask: _Ask, shipment: _Shipment) -> Outcome:
    """The worker's reply to ``shipment`` checked at the boundary and against its request
    (D3 or D3', §11 T10), then admitted as ``ask``'s kind: a reply either check rejects is
    ``bad_model``."""
    reply = shipment.reply(ask)
    if isinstance(reply, str):
        return reply
    try:
        return ask.kind.admit(reply, ask.profile, ask.grammar, shipment.text, shipment.data)
    except ModelError:
        return "bad_model"


def _unchanged(ask: _Ask, shipment: _Shipment) -> bool:
    """A9: the text was read from the file the key's stat described — the shipment's stat is
    the key's — and the file is still that one now, at the same size and mtime."""
    return _identity(shipment.stat) == _identity(ask.before) and _still(ask.path, ask.before)


def _still(path: Path, before: os.stat_result) -> bool:
    """``path`` still names the file ``before`` described, at the same size and mtime."""
    try:
        after = os.stat(path)
    except (OSError, ValueError):
        return False
    return _identity(after) == _identity(before)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


# ── the issue-ahead (§4.1 item 6) ────────────────────────────────────────────


def issue_ahead(
    file: str | Path, families: frozenset[str], audit: AuditContext, walk: object = None
) -> bool:
    """``file``'s answer request sent ahead to an idle worker and filed under its answer key in
    ``audit``'s ticket index, as ``walk``'s (None outside a walk), when its consumer would ask
    for it and nothing holds it yet: ``audit`` was not served it already; its profile owns one
    of ``families`` (``profile.owns_family``, the heads' predicate); it is a regular file within
    the size cap; its key is not stored, in flight, declined in ``audit`` (A18), reserved or
    filed — and is then reserved, in the same step; its text (read after the stat, A9) holds a
    sink key of one of those families (``needed_families``, §9.2). It records nothing and
    stores nothing (A44 (2)). True once ``file`` is considered — issued, or never to be — and
    False when the pool had no slot to give, which it mostly tells before any I/O: the walk
    asks again later. An audit whose index is closed (its end, §4.1 item 8) issues nothing
    more."""
    if audit.tickets.closed:
        return True
    if not get_pool().issuable():
        return False
    ahead = _ahead(file, families, audit, walk)
    return ahead is None or _issued(*ahead, audit)


def _ahead(
    file: str | Path, families: frozenset[str], audit: AuditContext, walk: object
) -> tuple[_Ask, frozenset[str]] | None:
    """``file``'s answer request and the ``families`` its profile owns, when it owns one and
    its key is new to ``audit`` — the key then reserved for ``walk`` (``_unasked``); no read."""
    owned = _owned_families(file, families, audit)
    profile = profile_for(file) if owned else None
    ask = None if profile is None else _asked(file, profile, _ANSWER)
    return (ask, owned) if _unasked(ask, audit, walk) else None


# What ``_owned_families`` answers for a file the issue-ahead leaves alone.
_NO_FAMILIES: frozenset[str] = frozenset()


def _owned_families(file: str | Path, families: frozenset[str], audit: AuditContext) -> frozenset[str]:
    """The ``families`` ``file``'s profile owns (``profile.owns_family``, the heads' one
    predicate); none for a file ``audit`` was served already: a consumer asked for it, so its
    answer is stored (or the file changed since, and the consumer is past it)."""
    if audit.coverage.served(file):
        return _NO_FAMILIES
    return frozenset(family for family in families if _profile.owns_family(file, family))


def _unasked(ask: _Ask | str | None, audit: AuditContext, walk: object) -> TypeGuard[_Ask]:
    """``ask`` is a request (``_asked`` named no reason) whose key nothing holds — neither
    stored nor in flight (``known``), nor declined in ``audit``, nor reserved or filed in its
    ticket index — and the key is then reserved there for ``walk``, in one step with that last
    test (``TicketIndex.reserve``)."""
    if not isinstance(ask, _Ask):
        return False
    key = ask.key
    return not (_CACHE.known(key) or key in audit.declined) and audit.tickets.reserve(key, walk)


def _issued(ask: _Ask, owned: frozenset[str], audit: AuditContext) -> bool:
    """``ask``'s text read and, when it holds a sink key of one of ``owned``, issued and filed
    in its reservation's place; else the reservation released. False only when the pool gave
    no slot."""
    shipment = _wanted(ask, owned)
    ticket = None if shipment is None else ask.issue(shipment.data)
    if ticket is None:
        audit.tickets.release(ask.key)
        return shipment is None
    audit.tickets.file(ask.key, replace(shipment, ticket=ticket))
    return True


def _wanted(ask: _Ask, owned: frozenset[str]) -> _Shipment | None:
    """``ask``'s text read, when it holds a sink key of one of ``owned`` (``needed_families``,
    §9.2); else None."""
    shipment = _read(ask)
    return shipment if shipment is not None and needed_families(shipment.text, owned) else None
