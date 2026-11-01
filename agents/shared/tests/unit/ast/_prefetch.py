"""Feature 0102, A44 (2) (LLD §4.1, plan task 3.9): what the parse-prefetch, answer-wire and
runner-prefetch tests share. Not a test module.

Task 3.9 adds ``shared.ast.prefetch`` (``walk``, ``advance``, ``TicketIndex``),
``shared.ast.answer`` (``FileAnswer``, ``encode``, ``validate_answer``), ``ANSWER_SCHEMA``, the
cache's ``owns_answer``, ``issue_ahead`` and ``ModelCache.known``, the pool's ``issue`` /
``collect`` / ``discard``, ``profile.owns_family`` and ``limits.PREFETCH_AHEAD`` /
``PREFETCH_RESERVE``. Each of them is reached only from a test body, never at import (a module
through an accessor, a name as an attribute read at call time), so every module that imports
this one COLLECTS before they exist and each test fails on its own, with the
``ModuleNotFoundError`` or ``AttributeError`` of the API it needs (``_analysis``' convention).

What lives here, one helper per idea:

* pools of a known size, installed as the process pool when the cache must reach them; a
  ticket (``ticket``: the one spelling of ``issue``); the pool read from outside: its free
  slots and how many tickets it issues now (``drained``, against ``idle``). A ticket probe
  COLLECTS what it issues: a discard may retire a worker;
* ``Spy``, a recording stand-in for one function or method, read by parameter NAME (bound
  against the real signature), so a call is read the same whether it passed an argument by
  position or by keyword; an audit's breaker faults are a spy's calls (``faults_of``);
* one audit entered in a context of its own (``Audit``, D20), the copies its skill threads run
  in, and leaving it; runs on threads at once (``in_threads``, ``at_once``);
* the trees the walks read: JavaScript files with a ``path`` or a ``request`` sink, or none;
* the consumer the cwe head is (§4.1 item 6): ``prefetch.advance`` then ``owns_answer`` for a
  file whose profile owns a walked family and whose text holds that family's sink key;
  ``walk_all`` walks a file list with it, paced by a ``Pace`` (two consumers in lockstep, or a
  trailer that only starts once the leader is ``PREFETCH_AHEAD`` files in);
* the one model cache's entries in LRU order and its bytes, emptied around a test
  (``cold_caches``), the answer key (D5's model key plus ``ANSWER_SCHEMA``), a worker's raw
  answer and its validation (D3'), a reply's readiness, and a monotonic clock a test moves
  forward instead of sleeping.
"""

from __future__ import annotations

import contextvars
import importlib
import inspect
import itertools
import select
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import Future, wait
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import shared.ast
from shared.ast import cache as ast_cache
from shared.ast import context as ast_context
from shared.ast import limits
from shared.ast import pool as pool_mod
from shared.ast import profile as ast_profile
from shared.ast.pool import WorkerPool
from shared.ast.profile import profile_for
from shared.ast.roles import needed_families
from shared.testing.timing import budget
from shared.tools.file_scanner import clear_caches, read_file_safe
from tests.unit.ast._audit import CLEAN_JS, model_cache_key, names
from tests.unit.ast._support import AST_V1, workers_of, write

# ── the task-3.9 modules, reached per test ───────────────────────────────────


def prefetch_mod() -> ModuleType:
    """``shared.ast.prefetch`` (plan 3.9): ``walk(files, families)``, ``advance(path)``,
    ``TicketIndex``."""
    return importlib.import_module("shared.ast.prefetch")


def answer_mod() -> ModuleType:
    """``shared.ast.answer`` (plan 3.9): ``FileAnswer``, ``AnswerAnalysis``, ``encode``,
    ``validate_answer`` (D3')."""
    return importlib.import_module("shared.ast.answer")


def owns_answer(path: Path) -> Any:
    """``shared.ast.cache.owns_answer(path)``: the production head's call (§5)."""
    return ast_cache.owns_answer(path)


def set_ahead(patch: pytest.MonkeyPatch, ahead: int) -> None:
    """``PREFETCH_AHEAD`` patched where ``prefetch`` may read it (D18: a ``limits`` constant
    read at call time, or a name ``prefetch`` imported); ``patch`` undoes it."""
    patch.setattr(limits, "PREFETCH_AHEAD", ahead)
    patch.setattr(prefetch_mod(), "PREFETCH_AHEAD", ahead, raising=False)


# The ``ast_v1`` depth bomb: 200,000-deep nesting, ``too_deep``, its worker past
# ``MAX_WORKER_RSS_MB``.
BOMB = AST_V1 / "cwe_22_19_bomb.js"
# A worker's resident high-water is read from /proc, so a test that needs it runs on Linux only.
ON_LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"),
                              reason="the worker's high-water is read from /proc (Linux)")

# ── pools of a known size ────────────────────────────────────────────────────

# A small file every v1 worker parses clean.
PROBE_JS = CLEAN_JS.encode("utf-8")


def sized_pool(patch: pytest.MonkeyPatch, count: int, cmd: list[str] | None = None) -> WorkerPool:
    """A new pool of ``count`` slots running ``cmd`` (None: the real worker); not the process
    pool. The caller closes it (``contextlib.closing``)."""
    patch.setattr(pool_mod, "worker_count", workers_of(count))
    return WorkerPool(cmd=cmd)


@contextmanager
def process_pool(count: int, cmd: list[str] | None = None) -> Iterator[WorkerPool]:
    """A pool of ``count`` slots running ``cmd``, made the PROCESS pool (``get_pool()``, which
    the cache and the prefetch reach) for the block; closed, and the previous one restored,
    after it."""
    with pytest.MonkeyPatch.context() as patch:
        pool = sized_pool(patch, count, cmd)
        patch.setattr(pool_mod, "_POOL", pool)
        try:
            yield pool
        finally:
            pool.close()


def ticket(
    pool: WorkerPool, data: bytes = PROBE_JS, *, answer: bool = False,
    language: str = "javascript", grammar: str | None = None,
) -> Any:
    """``pool.issue`` (§4.1 item 5), its one spelling here: a ticket for ``data`` in
    ``language`` with the grammar entry point ``grammar`` (None: the language's own), asking
    for the worker's ANSWER when ``answer``; None when the pool refuses."""
    return pool.issue(language, data, grammar, answer)


def issue_all(pool: WorkerPool) -> list[Any]:
    """Every ticket ``pool`` issues (``PROBE_JS``) before its first refusal, at most one per
    slot and one more (a pool that never refuses ends the probe instead of the run)."""
    return list(itertools.islice(iter(partial(ticket, pool), None), pool.size + 1))


def discard_all(run: Callable[..., Any], pool: WorkerPool, tickets: Sequence[Any]) -> None:
    """Each of ``tickets`` discarded through ``run`` (an audit's ``run``, so in its context)."""
    for each in tickets:
        run(pool.discard, each)


def _collected(pool: WorkerPool) -> int:
    tickets = issue_all(pool)
    for each in tickets:
        pool.collect(each)
    return len(tickets)


def tickets_issuable(pool: WorkerPool) -> int:
    """How many tickets ``pool`` issues now, asked in an audit of its own (its breaker
    closed); each is collected, so no worker is retired by the probe."""
    return Audit(Path.cwd()).run(_collected, pool)


def drained(pool: WorkerPool) -> dict[str, int]:
    """``pool`` read from outside: its free slots (``_free``, the FIFO of §4) and the tickets
    it issues now — ``idle(pool)`` when no ticket is outstanding and the counter is exact."""
    return {"free slots": pool._free.qsize(), "tickets issuable": tickets_issuable(pool)}


def idle(pool: WorkerPool) -> dict[str, int]:
    """What ``drained`` reads of a pool with nothing outstanding: every slot free, and
    ``W - PREFETCH_RESERVE`` tickets issuable."""
    return {"free slots": pool.size, "tickets issuable": pool.size - limits.PREFETCH_RESERVE}


# ── spies ────────────────────────────────────────────────────────────────────


class Spy:
    """Stands in for one function or method: ``before`` (if set) sees each call's bound
    arguments first, then the real one runs; each call's arguments and whether it returned
    something (not None) are recorded, in order, and appended to ``log`` (shared by several
    spies) as ``(name, arguments)``. No result is kept: a parsed document or a retired ticket
    is never held past its call."""

    def __init__(self, real: Callable[..., Any], name: str, log: list[Any] | None = None) -> None:
        self.real = real
        self.name = name
        self.log: list[Any] = [] if log is None else log
        self.calls: list[dict[str, Any]] = []
        self.answered: list[bool] = []
        self.before: Callable[[dict[str, Any]], None] | None = None
        self._signature = inspect.signature(real)
        self._lock = threading.Lock()

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        arguments = dict(self._signature.bind(*args, **kwargs).arguments)
        if self.before is not None:
            self.before(arguments)
        result = self.real(*args, **kwargs)
        with self._lock:
            self.calls.append(arguments)
            self.answered.append(result is not None)
            self.log.append((self.name, arguments))
        return result

    def values(self, parameter: str) -> list[Any]:
        """``parameter``'s value in each call, in call order."""
        return [arguments[parameter] for arguments in self.calls]

    def made(self) -> int:
        """How many calls returned something (an issued ticket, a given answer)."""
        return sum(self.answered)


def _as_method(spy: Spy) -> Callable[..., Any]:
    def method(self: Any, *args: Any, **kwargs: Any) -> Any:
        return spy(self, *args, **kwargs)

    return method


def spy_on(patch: pytest.MonkeyPatch, owner: Any, name: str, log: list[Any] | None = None) -> Spy:
    """``owner.name`` (a class's method, or a module's function) replaced by a ``Spy`` of it;
    ``patch`` undoes it. The real attribute must exist: a missing task-3.9 name fails here,
    with its ``AttributeError``."""
    spy = Spy(getattr(owner, name), name, log)
    patch.setattr(owner, name, _as_method(spy) if isinstance(owner, type) else spy)
    return spy


def pool_spies(patch: pytest.MonkeyPatch, log: list[Any] | None = None) -> dict[str, Spy]:
    """Spies on the four pool operations a request can reach: ``parse``, ``issue``,
    ``collect`` and ``discard``."""
    operations = ("parse", "issue", "collect", "discard")
    return {name: spy_on(patch, WorkerPool, name, log) for name in operations}


def shipped(spy: Spy) -> list[bytes]:
    """The bytes of every request ``spy`` (on ``parse`` or ``issue``) let reach a worker: for
    ``issue``, only the calls that issued a ticket."""
    return [data for data, made in zip(spy.values("data"), spy.answered, strict=True) if made]


def faults_of(record: Spy, breaker: ast_context.Breaker) -> int:
    """``breaker``'s faults among the calls of ``record``, a spy on ``Breaker.record`` (D10):
    an audit's faults observed as calls, never read off a field of the breaker. A breaker
    compares by identity, so no two audits ever share a count."""
    return record.values("self").count(breaker)


def record_spawns(patch: pytest.MonkeyPatch) -> list[subprocess.Popen[bytes]]:
    """Every worker process a pool starts from now on, in order."""
    procs: list[subprocess.Popen[bytes]] = []
    spawn = pool_mod._Worker.spawn

    def recording(cmd: list[str]) -> Any:
        worker = spawn(cmd)
        procs.extend([] if worker is None else [worker.proc])
        return worker

    patch.setattr(pool_mod._Worker, "spawn", staticmethod(recording))
    return procs


def readable(proc: subprocess.Popen[bytes], seconds: float = 10.0) -> bool:
    """Whether ``proc``'s reply pipe has bytes (or its end) within ``budget(seconds)``: a
    bounded wait on the descriptor, never a sleep."""
    poller = select.poll()
    poller.register(proc.stdout.fileno(), select.POLLIN)  # type: ignore[union-attr]
    return bool(poller.poll(budget(seconds) * 1000))


class Clock:
    """``time.monotonic`` moved forward on demand: ``advance(s)`` makes every later reading
    ``s`` seconds later than the real clock's, so a test passes a deadline without waiting."""

    def __init__(self) -> None:
        self._real = time.monotonic
        self._offset = 0.0

    def __call__(self) -> float:
        return self._real() + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += seconds


# ── one audit, its skill contexts (D20) ──────────────────────────────────────


class Audit:
    """One audit of ``root``, entered in a context of its own: ``run`` calls in it, ``skill()``
    is a copy taken inside it (what a skill thread runs in), ``leave()`` leaves it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.ctx = contextvars.Context()
        self.token = self.ctx.run(ast_context.enter, root)
        self.state = self.ctx.run(ast_context.current)

    def run(self, fn: Callable[..., Any], *args: Any) -> Any:
        return self.ctx.run(fn, *args)

    def skill(self) -> contextvars.Context:
        return self.ctx.run(contextvars.copy_context)

    def leave(self) -> None:
        self.ctx.run(ast_context.leave, self.token)

    def trip(self) -> None:
        """Its breaker opened: ``CIRCUIT_BREAK_AFTER`` faults recorded on it (D10)."""
        for _ in range(limits.CIRCUIT_BREAK_AFTER):
            self.state.breaker.record()

    def snapshot(self) -> dict[str, Any]:
        """The audit's ``ast_coverage`` (§10.2)."""
        return self.state.coverage.snapshot(self.root)

    def cache_events(self) -> dict[str, int]:
        """``tallies.cache``: the audit's hits, misses and evictions (A41 (8))."""
        return self.snapshot()["tallies"]["cache"]


# ── trees ────────────────────────────────────────────────────────────────────

# One handler per file, its request value reaching a sink of one family; the number (each
# ``{i}``, replaced as ``_analysis.numbered`` replaces it) keeps every file distinct. Each also
# holds ``require("fs")``, a constant-argument path candidate.
PATH_JS = (
    'const fs = require("fs");\n'
    "function read{i}(req, res) {\n"
    "  fs.readFile(req.query.f{i}, () => res.end());\n"
    "}\n"
)
REQUEST_JS = "function proxy{i}(req) {\n  return fetch(req.query.u{i});\n}\n"
PLAIN_JS = "const value{i} = {i};\n"
PATH = frozenset({"path"})
REQUEST = frozenset({"request"})


def numbered_as(template: str, i: int) -> str:
    """``template`` with each ``{i}`` replaced by ``i``; any other brace is literal."""
    return template.replace("{i}", str(i))


def js_files(root: Path, count: int, template: str = PATH_JS, stem: str = "f") -> list[Path]:
    """``count`` files ``<stem>NNN.js`` under ``root`` (``_audit.names``: name order is number
    order), each ``template`` numbered."""
    numbered = enumerate(names(count, stem))
    return [write(root / name, numbered_as(template, i)) for i, name in numbered]


# ── the consumer (§4.1 item 6) ───────────────────────────────────────────────


def needs(path: Path, families: frozenset[str]) -> bool:
    """The head's test before it asks the tier: the file's profile owns one of ``families``
    (``profile.owns_family``, the one predicate of the head and the prefetch) and its text
    holds a sink key of one of those (§9.2's prefilter). The text is read either way."""
    owned = [family for family in families if ast_profile.owns_family(path, family)]
    text = read_file_safe(path)
    return text is not None and bool(needed_families(text, owned))


def consume(path: Path, families: frozenset[str]) -> Any:
    """What the cwe head does for one walked file: nothing unless it ``needs`` the file, else
    ``prefetch.advance(path)`` and then ``owns_answer(path)`` — the answer, or None."""
    if not needs(path, families):
        return None
    prefetch_mod().advance(path)
    return owns_answer(path)


class Pace:
    """When a walking consumer may ask for its next file, and what it does after: the base
    never holds it."""

    def before(self, index: int) -> None:
        """Called before the consumer asks for the walk's ``index``-th file."""

    def after(self, index: int) -> None:
        """Called once it has."""


def walk_all(files: Sequence[Path], families: frozenset[str], pace: Pace | None = None) -> list[Any]:
    """``files`` walked as a skill walks them (``prefetch.walk``), each consumed in turn."""
    paced = pace or Pace()
    with prefetch_mod().walk(files, families) as walked:
        return [_paced(paced, index, path, families) for index, path in enumerate(walked)]


def _paced(pace: Pace, index: int, path: Path, families: frozenset[str]) -> Any:
    pace.before(index)
    answer = consume(path, families)
    pace.after(index)
    return answer


_WAIT_S = 30.0  # a turn that never comes fails the test instead of wedging the run


class Lockstep(Pace):
    """One of two consumers taking turns, one file at a time: for each file the consumer that
    goes first asks before the other, which asks before the first moves on (``Event``s, never
    sleeps). ``pair(count, first)`` is the two paces, consumer 0's then consumer 1's."""

    def __init__(self, turns: list[threading.Event], second: bool) -> None:
        self._turns = turns
        self._second = second

    @classmethod
    def pair(cls, count: int, first: int) -> tuple[Lockstep, Lockstep]:
        turns = [threading.Event() for _ in range(2 * count + 1)]
        turns[0].set()
        return cls(turns, first != 0), cls(turns, first != 1)

    def _step(self, index: int) -> int:
        return 2 * index + self._second

    def before(self, index: int) -> None:
        assert self._turns[self._step(index)].wait(budget(_WAIT_S)), f"turn {index} never came"

    def after(self, index: int) -> None:
        self._turns[self._step(index) + 1].set()


_BURN = 150_000  # a trailing consumer's extra CPU per file: several times a cold answer's


def burn() -> int:
    """CPU work, never a sleep: what makes a trailing consumer the slower one."""
    return sum(i * i for i in range(_BURN))


class Leader(Pace):
    """The leading consumer: ``ahead`` is set once it has asked for ``lead`` files."""

    def __init__(self, ahead: threading.Event, lead: int) -> None:
        self.ahead, self._lead = ahead, lead

    def after(self, index: int) -> None:
        if index + 1 >= self._lead:
            self.ahead.set()


class Trailer(Pace):
    """The trailing consumer: it starts once the leader is ``lead`` files in, and burns CPU
    after every file, so it stays behind."""

    def __init__(self, ahead: threading.Event) -> None:
        self._ahead = ahead

    def before(self, index: int) -> None:
        if index == 0:
            assert self._ahead.wait(budget(_WAIT_S)), "the leader never got ahead"

    def after(self, index: int) -> None:
        burn()


# ── runs on threads ──────────────────────────────────────────────────────────


def in_threads(*runs: Callable[[], Any]) -> list[Any]:
    """Each of ``runs`` on its own daemon thread at once; their results, in order, once every
    run has ended. A run that raised raises here; one that never ends fails the test after a
    bounded wait."""
    futures = [_started(run) for run in runs]
    _, pending = wait(futures, budget(60.0))
    assert not pending, f"{len(pending)} of {len(futures)} threads never ended"
    return [future.result() for future in futures]


def _started(run: Callable[[], Any]) -> Future[Any]:
    future: Future[Any] = Future()
    threading.Thread(target=_settle, args=(run, future), daemon=True).start()
    return future


def _settle(run: Callable[[], Any], future: Future[Any]) -> None:
    try:
        future.set_result(run())
    except BaseException as exc:  # recorded, so the test reports it instead of a silent death
        future.set_exception(exc)


def at_once(audit: Audit, fn: Callable[[], Any], count: int) -> list[Any]:
    """``fn`` on ``count`` skill threads of ``audit``, released together by one barrier
    (``in_threads``): their results, in order."""
    start = threading.Barrier(count)
    return in_threads(*(partial(audit.skill().run, _released, start, fn) for _ in range(count)))


def _released(start: threading.Barrier, fn: Callable[[], Any]) -> Any:
    start.wait(budget(_WAIT_S))
    return fn()


# ── the one model cache, the answer key, a worker's answer ───────────────────


def model_cache() -> ast_cache.ModelCache:
    """The one ``ModelCache`` (D5: one cache), found by type (``test_0102_cache``'s
    ``_model_cache``, which a tracked test keeps)."""
    found = [v for v in vars(ast_cache).values() if isinstance(v, ast_cache.ModelCache)]
    assert len(found) == 1, f"D5 names one model cache; shared.ast.cache holds {len(found)}"
    return found[0]


@contextmanager
def cold_caches() -> Iterator[None]:
    """An empty model cache and empty read caches (``clear_caches`` also resets the
    process-default audit) when the block starts and when it ends."""
    _clear_caches()
    try:
        yield
    finally:
        _clear_caches()


def _clear_caches() -> None:
    ast_cache.clear()
    clear_caches()


def cache_state() -> dict[str, Any]:
    """The cache's entries' keys in LRU order (its one ordered map, found by type) and its
    bytes: what prefetch must never move (A44 (2))."""
    cache = model_cache()
    (entries,) = [v for v in vars(cache).values() if isinstance(v, OrderedDict)]
    return {"keys": list(entries), "bytes": cache.bytes}


def known(key: tuple[Any, ...]) -> bool:
    """``ModelCache.known(key)``: stored or in flight, with no LRU touch and no event."""
    return model_cache().known(key)


def model_key(path: Path) -> tuple[Any, ...]:
    """D5's key of ``path`` as A14 extends it, read off the file now."""
    profile = profile_for(path)
    assert profile is not None, path
    return model_cache_key(path, profile.language, profile.grammar_for(path))


def answer_key(path: Path) -> tuple[Any, ...]:
    """The answer key (§4.1 item 4): the model key with ``ANSWER_SCHEMA`` appended."""
    return (*model_key(path), shared.ast.ANSWER_SCHEMA)


def wire_request(path: Path) -> tuple[str, bytes, str | None]:
    """What the cache ships for ``path`` (§4): its language, its text's UTF-8 bytes, and the
    grammar entry point on the wire (None for the language's own)."""
    profile, text = profile_for(path), read_file_safe(path)
    assert profile is not None and text is not None, path
    grammar = profile.grammar_for(path)
    return profile.language, text.encode("utf-8"), None if grammar == profile.grammar_attr else grammar


def raw_answer(pool: WorkerPool, path: Path) -> Any:
    """A worker's reply to ``path``'s ANSWER request (``"answer": true``), through a ticket:
    the decoded document, or the pool's reason."""
    language, data, grammar = wire_request(path)
    return pool.collect(ticket(pool, data, answer=True, language=language, grammar=grammar))


def validated(doc: Any, path: Path, data: bytes | None = None) -> Any:
    """``doc``, a worker's answer document, through D3' (``validate_answer``, the one call of
    it here) against ``path``'s request: ``data`` the bytes it shipped (None: ``wire_request``'s,
    read now), and the text decoded from them."""
    sent = wire_request(path)[1] if data is None else data
    profile = profile_for(path)
    return answer_mod().validate_answer(doc, profile, profile.grammar_for(path), sent,
                                        sent.decode("utf-8"))
