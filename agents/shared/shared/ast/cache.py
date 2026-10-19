"""The model cache, ``get_model`` and ``owns`` (feature 0102, LLD D5, D10, §4, §5, §10.2).

One process-wide store of parsed ``FileModel`` objects, shared by every concurrent audit of
the agent process (§4):

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

``get_model`` = ``profile_for`` -> stat (key, size cap) -> the audit's ``declined`` map ->
cache -> read -> UTF-8 encode -> ``WorkerPool.parse`` -> ``validate_reply`` ->
``FileModel.from_doc``. It never raises. Each outcome is recorded on the current audit's
coverage (``context.current()``, D20), once per path (A8): a ``None`` for a file with a
profile as its §10.2 fallback reason (an unreadable path is not a fallback: no tier reads it,
A11), a model as the facts it carries, an owned file as ``parsed``.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
import weakref
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from shared.ast import MODEL_SCHEMA
from shared.ast import profile as _profile
from shared.ast._frames import ModelError
from shared.ast._validate import validate_reply
from shared.ast.context import AuditContext, current
from shared.ast.coverage import (
    CACHE_EVICTIONS,
    CACHE_HITS,
    CACHE_MISSES,
    MEMOISED_REASONS,
)
from shared.ast.limits import MAX_FILE_SIZE
from shared.ast.model import FileModel
from shared.ast.pool import get_pool, model_cache_budget
from shared.ast.profile import LanguageProfile, profile_for
from shared.tools import membudget
from shared.tools.file_scanner import MAX_FILE_SIZE as READ_CAP
from shared.tools.file_scanner import read_file_uncached

__all__ = ["ModelCache", "clear", "get_model", "owns"]

logger = logging.getLogger(__name__)

# D5 as A14 extends it: (resolved path, size, mtime_ns, GRAMMAR_PACK_VERSION, MODEL_SCHEMA,
# language, grammar entry point).
type Key = tuple[str, int, int, str, int, str, str]
# A miss's outcome: the model; a §10.2 fallback reason every requester tallies; or None for a
# path no tier can read (nothing to tally).
type Outcome = FileModel | str | None
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
    """One stored model (A35): its key, the model and its weight — the model's
    ``bytes_estimate``, then its analysis' too once ``analysed``. Only the cache holds an
    entry: the model's charge reaches it weakly, so an entry the cache gives up is freed under
    the cache lock and its model charges nothing after (``_charged``)."""

    key: Key
    model: FileModel
    weight: int
    analysed: bool = False


def _evicted(models: list[FileModel]) -> None:
    """Models an insertion or a charge evicted, tallied on the current audit outside the cache
    lock (the caller drops them once it returns)."""
    if models:
        current().coverage.record_cache(CACHE_EVICTIONS, len(models))


class ModelCache:
    """D5's one cache: a byte-budgeted LRU of immutable models, single-flight per key."""

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

    def clear(self) -> None:
        """Evict every completed model; an in-flight parse keeps its leader and waiters.
        The evicted models are dropped once the lock is."""
        with self._lock:
            evicted, self._models = self._models, OrderedDict()
            self.bytes = 0
            models = [entry.model for entry in evicted.values()]
            evicted.clear()  # the entries go under the lock: none is charged after
        models.clear()

    def _board(self, key: Key) -> tuple[FileModel | _Flight, bool]:
        """Under the lock, in one step: the stored model (made the most recently used), the
        in-flight parse to join, or a new flight this thread leads (``True``)."""
        with self._lock:
            entry = self._models.get(key)
            if entry is not None:
                self._models.move_to_end(key)
                return entry.model, False
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

    def _land(self, key: Key, flight: _Flight) -> list[FileModel]:
        """Under the lock: store the leader's model (if any, and if it may be kept) and retire
        its flight, in one step, so a request sees one or the other. Returns the models
        evicted to make room, dropped by the caller once the lock is."""
        with self._lock:
            del self._flights[key]
            return self._store(key, flight.outcome) if flight.keep else []

    def _store(self, key: Key, outcome: Outcome) -> list[FileModel]:
        if not isinstance(outcome, FileModel) or outcome.bytes_estimate > self.budget:
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

    def _charged(self, entry: _Entry | None, weight: int) -> list[FileModel]:
        if entry is None or entry.analysed:
            return []
        entry.analysed = True
        entry.weight += weight
        self.bytes += weight
        self._models.move_to_end(entry.key)
        return self._make_room(0)

    def _make_room(self, weight: int) -> list[FileModel]:
        """Evict least-recently-used entries — each weighs its model and its analysis' charge
        — until ``weight`` more fits the budget; their models."""
        evicted: list[FileModel] = []
        while self._models and self.bytes + weight > self.budget:
            _, old = self._models.popitem(last=False)
            self.bytes -= old.weight
            evicted.append(old.model)
        return evicted


def _joined(found: FileModel | _Flight) -> Outcome | object:
    """A stored model, or the outcome of the flight once its leader is done (``_REBOARD``
    when the leader left none)."""
    if isinstance(found, FileModel):
        return found
    found.done.wait()
    return found.outcome if found.settled else _REBOARD


_CACHE = ModelCache(model_cache_budget(membudget.deployment_memory_limit()))


def clear() -> None:
    """Evict every completed model (an explicit hook; never called per audit, D5)."""
    _CACHE.clear()


# ── get_model and owns (§5) ──────────────────────────────────────────────────


def get_model(path: str | Path) -> FileModel | None:
    """``path``'s model, or None: the file falls back to the regex tier, its reason tallied
    on the current audit (once per path, A8). Never raises."""
    audit = current()
    return _recorded(audit, path, _outcome(path, audit))


def owns(path: str | Path) -> FileModel | None:
    """``get_model(path)`` when the AST tier owns the file — the model has no ERROR node and
    this audit's breaker is closed (D10) — else None (regex fallback, tallied). No flag."""
    model = get_model(path)
    if model is None:
        return None
    audit = current()
    reason = _not_owned(audit, model)
    if reason is not None:
        audit.coverage.record_fallback(path, reason)
        return None
    audit.coverage.record_parsed(path)
    return model


def _recorded(audit: AuditContext, path: str | Path, outcome: Outcome) -> FileModel | None:
    """``outcome`` recorded on ``audit``'s coverage: a reason as its fallback, a model as the
    facts it carries (A31 (8)); the model, or None."""
    if isinstance(outcome, str):
        audit.coverage.record_fallback(path, outcome)
        return None
    if outcome is not None:
        audit.coverage.record_model(path, outcome)
    return outcome


def _not_owned(audit: AuditContext, model: FileModel) -> str | None:
    """Why the AST tier does not own a file it has a model of, or None."""
    if audit.breaker.tripped:
        return "circuit_open"
    if model.error_nodes:
        return "parse_error"
    return None


def _outcome(path: str | Path, audit: AuditContext) -> Outcome:
    """The model or the reason there is none. ``unsupported`` is decided first, from the
    extension alone (O1); then the stat (an unreadable path is None)."""
    profile = profile_for(path)
    if profile is None:
        return "unsupported"
    found = _regular_file(path)
    if found is None:
        return None
    return _keyed(path, profile, *found, audit)


def _keyed(
    path: str | Path,
    profile: LanguageProfile,
    resolved: str,
    info: os.stat_result,
    audit: AuditContext,
) -> Outcome:
    """``too_large`` from the stat, before any read or worker; a key this audit declined
    earlier (A18) without asking the pool; else the cache's outcome, a refusal memoised (by
    the leader's ``_build`` before its flight lands; here for a request that joined the flight
    of another audit's leader)."""
    if info.st_size > _SIZE_CAP:
        return "too_large"
    grammar = profile.grammar_for(path)
    key = _model_key(resolved, info, profile, grammar)
    declined = audit.declined.get(key)
    if declined is not None:
        audit.coverage.record_cache(CACHE_HITS)  # A41 (8): a later request of the key
        return declined
    outcome = _CACHE.get(key, _build, audit, key, path, profile, grammar, info)
    return _remembered(audit, key, outcome)


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


def _build(
    audit: AuditContext,
    key: Key,
    path: str | Path,
    profile: LanguageProfile,
    grammar: str,
    before: os.stat_result,
) -> Built:
    """A miss, led by a request of ``audit``: the parse, made safe — an unexpected fault is
    ``worker_error``, never a raise — its refusal memoised in ``audit`` BEFORE its flight
    lands (A18, A41 (8)). A later request of the key in this audit reads the memo — a hit,
    with no second pool call and no second breaker fault — and never finds the key with
    neither a flight nor a memo, which would lead a second parse."""
    try:
        built = _parse(Path(path), profile, grammar, before)
    except Exception as exc:  # get_model never raises (§5)
        logger.warning("ast model build: unexpected %s; file falls back", type(exc).__name__)
        built = "worker_error", True
    _remembered(audit, key, built[0])
    return built


def _parse(path: Path, profile: LanguageProfile, grammar: str, before: os.stat_result) -> Built:
    """§4: the parent reads the text once (size cap, ``errors="replace"``, read recorder)
    and ships its UTF-8 encoding; every span of the model indexes that encoding. A9: the
    read is from disk, and a model whose file changed since ``before`` (the key's stat) is
    served but not kept."""
    text = read_file_uncached(path)
    if text is None:
        return None, True
    outcome = _shipped(profile, grammar, text)
    return outcome, not isinstance(outcome, FileModel) or _unchanged(path, before)


def _unchanged(path: Path, before: os.stat_result) -> bool:
    """``path`` still names the file ``before`` described, at the same size and mtime."""
    try:
        after = os.stat(path)
    except (OSError, ValueError):
        return False
    return _identity(after) == _identity(before)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _shipped(profile: LanguageProfile, grammar: str, text: str) -> Outcome:
    """``text`` to the pool as ``WorkerPool.parse(language, bytes)`` (§4), with ``grammar``,
    the entry point the file's suffix selects (None on the wire for the language's own, which
    the worker defaults to), and the reply checked against that request."""
    data = text.encode("utf-8")
    answer = _ask(profile, grammar, data)
    return answer if isinstance(answer, str) else _model(answer, profile, grammar, text, data)


def _ask(profile: LanguageProfile, grammar: str, data: bytes) -> dict[str, Any] | str:
    """``WorkerPool.parse(language, bytes)`` with the entry point ``grammar`` (None on the
    wire for the language's own, which the worker defaults to): the pool's answer."""
    variant = None if grammar == profile.grammar_attr else grammar
    return get_pool().parse(profile.language, data, variant)


def _model(
    doc: Mapping[str, Any], profile: LanguageProfile, grammar: str, text: str, data: bytes
) -> Outcome:
    """The worker's document checked at the boundary and against its request (D3, §11 T10),
    then the model: a document either check rejects is ``bad_model``."""
    try:
        valid = validate_reply(doc, profile, grammar, data)
    except ModelError:
        return "bad_model"
    return FileModel.from_doc(valid, text)
