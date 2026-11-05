"""Feature 0102, A44 (2) (LLD §4.1, plan task 3.9, tests 1-19): parse prefetch — tickets below
the cache, issued ahead on the consumer's own thread.

User decision D-I (ii) keeps the A7 relative gate and asks for prefetch. The lead's panel chose
the design recorded in LLD §4.1 before these tests: the workers build each file's ANSWER, and a
skill's walk sends its next files to idle workers before it reaches them. Pinned here, through
real workers (hook workers where a broken one is the point):

* **The bounds are ``limits`` constants (test 1).** ``PREFETCH_AHEAD = 2 * MAX_WORKERS`` and
  ``PREFETCH_RESERVE = 1``, commented, bound nowhere else; ``prefetch`` and ``answer`` read no
  environment; no ``VULTURE_`` name enters the layer (CLAUDE.md rule 6).
* **The pool's tickets (tests 2-9).** ``issue`` takes a free slot without waiting and only while
  the exact outstanding-ticket count is below ``W - PREFETCH_RESERVE`` with the breaker closed,
  so W = 1 never issues and a synchronous request always finds a slot (no deadlock).
  ``collect(issue(x))`` answers what ``parse(x)`` answers, faults and recycles included, with
  the read deadline armed at collect and the events recorded on the COLLECTING audit; a tripped
  breaker makes it ``circuit_open``. ``discard`` never waits on a silent worker, records nothing
  and frees the slot.
* **The walk (tests 10-12, 16-19).** Entering it is passive. ``advance`` issues only what its
  consumer would parse, in walk order, each position considered once and never more than
  ``PREFETCH_AHEAD`` past the cursor. Only the key's flight leader claims a ticket, by its exact
  key (a rewritten file goes synchronous; a file changed while claimed is served, not stored,
  A9). The walk drains its tickets on exit and on raise; ``context.leave`` and
  ``reset_default`` close the audit's index. No thread is started, ``import
  shared.ast.prefetch`` stays light, and a completed walk reads what the synchronous run reads.
* **The cache (tests 13-15).** Tickets read only ``known`` and write nothing, so prefetch never
  evicts and never moves an LRU position; two consumers parse each needed file once when the
  budget holds the answers but not the models; ``tallies.cache`` is the synchronous run's on
  any interleaving, cold and warm (A41 (8)).

Every wait is a bounded join or an ``Event``, never a sleep; time bounds go through
``shared.testing.timing.budget``. A deadline is passed by moving a monotonic clock forward
(``_prefetch.Clock``), not by waiting for it.

RED until task 3.9: ``limits.PREFETCH_AHEAD``, ``WorkerPool.issue`` / ``collect`` / ``discard``,
``shared.ast.prefetch`` and ``cache.owns_answer`` do not exist, so each test fails on the
``AttributeError`` or ``ModuleNotFoundError`` of the first of them it reaches.
"""

from __future__ import annotations

import ast
import contextvars
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import closing, contextmanager
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from shared.ast import cache as ast_cache
from shared.ast import context as ast_context
from shared.ast import get_model, limits
from shared.ast.limits import FRAME_CAP, MAX_DEPTH, MAX_FILE_SIZE
from shared.ast.pool import WorkerPool
from shared.testing.timing import budget
from shared.tools import file_scanner
from shared.tools.file_scanner import record_reads
from tests.support.fresh_import import loaded_after_import
from tests.unit.ast._audit import CRASH_HOOK
from tests.unit.ast._prefetch import (
    BOMB,
    ON_LINUX,
    PATH,
    PATH_JS,
    PLAIN_JS,
    PROBE_JS,
    REQUEST,
    REQUEST_JS,
    Audit,
    Clock,
    Leader,
    Lockstep,
    Pace,
    Spy,
    Trailer,
    answer_key,
    answer_mod,
    at_once,
    cache_state,
    cold_caches,
    discard_all,
    drained,
    faults_of,
    idle,
    in_threads,
    issue_all,
    js_files,
    known,
    model_cache,
    numbered_as,
    owns_answer,
    pool_spies,
    prefetch_mod,
    process_pool,
    readable,
    record_spawns,
    set_ahead,
    shipped,
    sized_pool,
    spy_on,
    ticket,
    walk_all,
)
from tests.unit.ast._support import TRIP_S, hook_command, wall_timeout, write
from tests.unit.ast.test_0102_limits import (
    _ENV_NAMES,
    _LIMITS_PATH,
    _PACKAGE,
    _assigned_names,
    _binding_statement,
    _comments,
    _identifiers,
    _is_commented,
    _limits_tree,
    _names_imported_from_elsewhere,
)

_JS = b"const a = 1;\n"
_TOO_DEEP = b"x = " + b"[" * (MAX_DEPTH + 16) + b"]" * (MAX_DEPTH + 16) + b";\n"
_AGENTS = _PACKAGE.parents[2]  # agents/


@pytest.fixture
def pool4() -> Iterator[WorkerPool]:
    """A fresh four-slot PROCESS pool (``W - PREFETCH_RESERVE`` = 3 tickets at most), an empty
    model cache and a fresh default audit, around the test."""
    with cold_caches(), process_pool(4) as pool:
        yield pool


@contextmanager
def _advanced(ctx: contextvars.Context, files: list[Path]) -> Iterator[None]:
    """A ``PATH`` walk of ``files`` (``prefetch.walk``) entered inside ``ctx`` (a skill thread's
    context) and advanced past its first file, then exited there, so the test can act on other
    contexts while the walk is open."""
    walk = ctx.run(prefetch_mod().walk, files, PATH)
    ctx.run(walk.__enter__)
    try:
        ctx.run(prefetch_mod().advance, files[0])
        yield
    finally:
        ctx.run(walk.__exit__, None, None, None)


# ── 1. the bounds are limits constants ───────────────────────────────────────


# Every environment accessor ``test_0102_limits`` knows; importing ``os`` alone reads nothing.
_ENV_READS = _ENV_NAMES - {"os"}
# The environment prefix, and the one name family the layer must never grow: spelled in two
# parts so this file is not itself a hit of the plan's ``grep`` for that family.
_PREFIX = "VULTURE_"
_LAYER_FLAGS = _PREFIX + "AST"


def _sources(*roots: Path) -> dict[Path, str]:
    """Every Python module under ``roots``, read once, in path order."""
    paths = [path for root in roots for path in sorted(root.rglob("*.py"))]
    return {path: path.read_text(encoding="utf-8") for path in paths}


def _commented(names: tuple[str, ...]) -> list[str]:
    """The ``names`` whose binding in ``limits.py`` carries a comment, by
    ``test_0102_limits``' rule (on its own lines, or a whole-line comment just above it)."""
    tree, comments = _limits_tree(), _comments(_LIMITS_PATH)
    return [name for name in names if _is_commented(_binding_statement(tree, name), comments)]


def _foreign(text: str) -> set[str]:
    """The names a module binds other than by importing them from ``limits``."""
    tree = ast.parse(text)
    return _names_imported_from_elsewhere(tree) | _assigned_names(tree)


def _bound_elsewhere(layer: dict[Path, str], names: tuple[str, ...]) -> list[str]:
    """``module:name`` for each of ``names`` a ``layer`` module other than ``limits.py`` binds."""
    return [f"{path.name}:{name}" for path, text in layer.items() if path != _LIMITS_PATH
            for name in sorted(_foreign(text) & set(names))]


def _environment_reads(paths: list[Path]) -> list[str]:
    """``module:name`` for each environment accessor the modules at ``paths`` name."""
    return [f"{p.name}:{name}" for p in paths
            for name in sorted(_identifiers(ast.parse(p.read_text(encoding="utf-8"))) & _ENV_READS)]


def _naming(texts: dict[Path, str], paths: Iterable[Path], needle: str) -> list[str]:
    return [path.name for path in paths if needle in texts[path]]


def _vulture_names(sources: dict[Path, str], layer: dict[Path, str]) -> list[str]:
    """Every ``layer`` module (and the cwe head) naming a ``VULTURE_`` variable, and every
    agents source naming a layer flag (``_LAYER_FLAGS``): none may (no environment flag, D12)."""
    head = _AGENTS / "cwe" / "cwe_agent" / "skills" / "_ast_head.py"
    return _naming(sources, [*layer, head], _PREFIX) + _naming(sources, sources, _LAYER_FLAGS)


def _layer(sources: dict[Path, str]) -> dict[Path, str]:
    """The layer's own modules (``shared/ast`` and its subpackages) among ``sources``."""
    return {path: text for path, text in sources.items() if path.is_relative_to(_PACKAGE)}


def test_prefetch_caps_are_limits_constants() -> None:
    """Test 1 (§8.7, D18): two ``limits.py`` constants, each commented and bound nowhere else;
    ``prefetch`` and ``answer`` read no environment; no ``VULTURE_`` name enters the layer."""
    names = ("PREFETCH_AHEAD", "PREFETCH_RESERVE")
    modules = [Path(prefetch_mod().__file__), Path(answer_mod().__file__)]
    sources = _sources(_AGENTS / "shared" / "shared", _AGENTS / "cwe" / "cwe_agent")
    layer = _layer(sources)
    observed = {
        "values": (limits.PREFETCH_AHEAD, limits.PREFETCH_RESERVE),
        "types": {type(limits.PREFETCH_AHEAD), type(limits.PREFETCH_RESERVE)},
        "commented": _commented(names),
        "bound elsewhere": _bound_elsewhere(layer, names),
        "environment reads": _environment_reads(modules),
        "VULTURE_ names": _vulture_names(sources, layer),
    }
    assert observed == {
        "values": (2 * limits.MAX_WORKERS, 1),
        "types": {int},
        "commented": list(names),
        "bound elsewhere": [],
        "environment reads": [],
        "VULTURE_ names": [],
    }


# ── 2-9. the pool's tickets ──────────────────────────────────────────────────


def _issue_at_once(audit: Audit, pool: WorkerPool, threads: int = 8) -> int:
    """``threads`` skill threads of ``audit`` each issue one ticket at the same instant; how
    many were issued. Every ticket is discarded before this returns."""
    tickets = [each for each in at_once(audit, partial(ticket, pool), threads) if each is not None]
    discard_all(audit.run, pool, tickets)
    return len(tickets)


def _issued_when_tripped(root: Path, pool: WorkerPool) -> int:
    """Tickets an audit whose breaker tripped still issues (discarded at once)."""
    audit = Audit(root)
    audit.trip()
    return _issue_at_once(audit, pool)


def _issued_after_close(root: Path, issue_spy: Spy) -> int:
    """Tickets a skill thread's walk issues after its audit was left (its index closed)."""
    files = js_files(root, 4)
    audit = Audit(root)
    skill = audit.skill()
    audit.leave()
    made = issue_spy.made()
    skill.run(walk_all, files, PATH)
    return issue_spy.made() - made


@pytest.mark.parametrize("workers", [4, 2, 1])
def test_issue_never_takes_the_reserved_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workers: int
) -> None:
    """Test 2: eight threads issuing at once on a pool of W slots get exactly ``W -
    PREFETCH_RESERVE`` tickets (an exact counter, never a racy queue size: W = 1 issues
    nothing); a tripped breaker issues nothing, and neither does a closed ticket index."""
    issue = pool_spies(monkeypatch)["issue"]
    with process_pool(workers) as pool:
        observed = {
            "issued at once": _issue_at_once(Audit(tmp_path), pool),
            "breaker tripped": _issued_when_tripped(tmp_path, pool),
            "index closed": _issued_after_close(tmp_path / "closed", issue),
            "pool": drained(pool),
        }
        expected = {
            "issued at once": max(0, workers - limits.PREFETCH_RESERVE),
            "breaker tripped": 0,
            "index closed": 0,
            "pool": idle(pool),
        }
    assert observed == expected


def _held_then_parsed(pool: WorkerPool, audit: Audit) -> tuple[int, Any, float]:
    """``W - 1`` tickets held by a consumer that never collects them, then one synchronous
    parse on another thread: the tickets held, the parse's answer and its seconds."""
    tickets = audit.run(issue_all, pool)
    started = time.perf_counter()
    try:
        (answer,) = in_threads(partial(audit.skill().run, pool.parse, "javascript", PROBE_JS))
    finally:
        discard_all(audit.run, pool, tickets)
    return len(tickets), answer, time.perf_counter() - started


def _discard(pool: WorkerPool, held: Any) -> None:
    if held is not None:
        pool.discard(held)


def _crossing(audit: Audit, pool: WorkerPool, files: list[Path], parse_spy: Any) -> list[Any]:
    """Two consumers of ``audit``, each holding one ticket, each leading the flight of its own
    file while the other leads its own (both held inside ``parse`` until both are there), then
    each asking for the other's file: the flight it waits on, or its stored answer. Each
    consumer's (tickets held, own answer given, other's answer given)."""
    both = threading.Barrier(2)
    parse_spy.before = lambda _arguments: both.wait(budget(30.0))
    ticket_turn = [threading.Event(), threading.Event()]
    ticket_turn[0].set()

    def consumer(mine: int) -> tuple[int, bool, bool]:
        assert ticket_turn[mine].wait(budget(30.0))
        held = ticket(pool)
        ticket_turn[1 - mine].set()
        try:
            own, other = owns_answer(files[mine]), owns_answer(files[1 - mine])
        finally:
            _discard(pool, held)
        return int(held is not None), own is not None, other is not None

    return in_threads(*(partial(audit.skill().run, consumer, i) for i in (0, 1)))


def test_a_synchronous_request_completes_while_tickets_are_outstanding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 3 (no deadlock): with ``W - 1`` tickets held by a paused consumer a synchronous
    ``parse`` still finds the reserved slot and returns within ``WALL_TIMEOUT_S``; two
    consumers each holding a ticket and each leading a flight the other then asks for both
    finish."""
    spies = pool_spies(monkeypatch)
    with process_pool(4) as pool:
        held, answer, seconds = _held_then_parsed(pool, Audit(tmp_path))
    with process_pool(3) as pool:
        crossed = _crossing(Audit(tmp_path), pool, js_files(tmp_path, 2), spies["parse"])
    observed = {
        "held": held,
        "parsed": isinstance(answer, dict),
        "within the wall timeout": seconds < limits.WALL_TIMEOUT_S,
        "crossing consumers": crossed,
    }
    assert observed == {
        "held": 3,
        "parsed": True,
        "within the wall timeout": True,
        "crossing consumers": [(1, True, True), (1, True, True)],
    }


# Each hook (None: the real worker; "missing": a command that cannot start), the bytes shipped,
# and what the synchronous request answers.
_FAULTS: dict[str, tuple[tuple[str, ...] | str | None, bytes, str]] = {
    "ok": (None, _JS, "document"),
    "crash": (CRASH_HOOK, _JS, "worker_crashed"),
    "hang": (("hang.py",), _JS, "timeout"),
    "half frame": (("half_frame.py",), _JS, "worker_crashed"),
    "bad_model": (("half_frame.py", "16", "16"), _JS, "bad_model"),
    "too_deep": (None, _TOO_DEEP, "too_deep"),
    "ir_too_large": (("half_frame.py", str(FRAME_CAP + 1), "16"), _JS, "ir_too_large"),
    "spawn failure": ("missing", _JS, "spawn_failed"),
}


def _command(hook: tuple[str, ...] | str | None, root: Path) -> list[str] | None:
    """The worker command of a ``_FAULTS`` hook."""
    if hook == "missing":
        return [str(root / "missing-worker")]
    return None if hook is None else hook_command(*hook)


def _by_parse(pool: WorkerPool, data: bytes) -> Any:
    return pool.parse("javascript", data)


def _by_ticket(pool: WorkerPool, data: bytes) -> Any:
    return pool.collect(ticket(pool, data))


def _events_of(audit: Audit, faults: Spy) -> tuple[int, int]:
    """``audit``'s breaker faults (``faults``: a spy on ``Breaker.record``) and its
    ``workers.recycled``."""
    return faults_of(faults, audit.state.breaker), audit.snapshot()["workers"]["recycled"]


def _requested(
    patch: pytest.MonkeyPatch, root: Path, case: str, ask: Callable[[WorkerPool, bytes], Any],
    faults: Spy,
) -> tuple[Any, int, int]:
    """``case``'s request through ``ask`` on a fresh two-slot pool, in an audit of its own:
    the answer, then the audit's breaker faults and ``workers.recycled`` (``_events_of``)."""
    hook, data, _ = _FAULTS[case]
    with closing(sized_pool(patch, 2, _command(hook, root))) as pool:
        audit = Audit(root)
        answer = audit.run(ask, pool, data)
    return answer, *_events_of(audit, faults)


def _shape(answer: Any) -> str:
    return "document" if isinstance(answer, dict) else answer


@pytest.mark.parametrize("case", sorted(_FAULTS))
def test_collect_answers_what_parse_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Test 4: for every hook worker, ``collect(issue(x))`` answers what ``parse(x)`` answers,
    with the same breaker count and ``workers.recycled`` on the requesting audit."""
    wall_timeout(monkeypatch, TRIP_S)
    faults = spy_on(monkeypatch, ast_context.Breaker, "record")
    synchronous = _requested(monkeypatch, tmp_path, case, _by_parse, faults)
    ticketed = _requested(monkeypatch, tmp_path, case, _by_ticket, faults)
    assert (_shape(synchronous[0]), ticketed) == (_FAULTS[case][2], synchronous)


def test_a_tickets_deadline_is_armed_at_collect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 5: a reply collected after an idle longer than the wall timeout still answers its
    document (the deadline is armed at collect, not at issue; the idle is a monotonic clock
    moved forward, not a wait); a hung worker answers ``timeout`` within the wall timeout plus
    grace of the collect."""
    wall_timeout(monkeypatch, TRIP_S)
    clock = Clock()
    monkeypatch.setattr(time, "monotonic", clock)
    procs = record_spawns(monkeypatch)
    audit = Audit(tmp_path)
    with (closing(sized_pool(monkeypatch, 2)) as pool,
          closing(sized_pool(monkeypatch, 2, hook_command("hang.py"))) as hung):
        issued = audit.run(ticket, pool)
        replied = readable(procs[0])
        clock.advance(2 * TRIP_S)
        late = audit.run(pool.collect, issued)
        stuck = audit.run(ticket, hung, _JS)
        started = time.perf_counter()
        reason = audit.run(hung.collect, stuck)
        waited = time.perf_counter() - started
    observed = {"replied": replied, "late": _shape(late), "hung": reason,
                "in time": waited <= TRIP_S + budget(1.0)}
    assert observed == {"replied": True, "late": "document", "hung": "timeout", "in time": True}


def test_collect_after_the_breaker_trips_is_circuit_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 6: a ticket collected once its audit's breaker has tripped answers
    ``circuit_open``, as a synchronous request would; its slot is freed."""
    with closing(sized_pool(monkeypatch, 2)) as pool:
        audit = Audit(tmp_path)
        issued = audit.run(ticket, pool)
        audit.trip()
        observed = {"issued": issued is not None, "collected": audit.run(pool.collect, issued),
                    "pool": drained(pool)}
        expected = {"issued": True, "collected": "circuit_open", "pool": idle(pool)}
    assert observed == expected


def _payload(data: bytes | Path) -> bytes:
    """A table row's request bytes: a fixture named by its path is read when the test runs."""
    return data.read_bytes() if isinstance(data, Path) else data


# The two pool events, each by the request that makes one, and what it counts on the claimant
# (breaker faults, ``workers.recycled``): a crash (a breaker fault) and the depth bomb
# (too_deep, and an RSS recycle of its worker).
_EVENTS: dict[str, tuple[tuple[tuple[str, ...] | None, bytes | Path, str], tuple[int, int]]] = {
    "crash": (_FAULTS["crash"], (1, 0)),
    "rss recycle": ((None, BOMB, "too_deep"), (0, 1)),
}


@pytest.mark.parametrize(
    "event", [pytest.param("crash"), pytest.param("rss recycle", marks=ON_LINUX)]
)
def test_pool_events_count_on_the_claimant_at_collect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    """Test 7: a ticket's pool events are recorded on the audit that collects it, when it does,
    never at issue: one audit issues, another collects."""
    (hook, data, reason), counted = _EVENTS[event]
    faults = spy_on(monkeypatch, ast_context.Breaker, "record")
    with closing(sized_pool(monkeypatch, 2, _command(hook, tmp_path))) as pool:
        issuer, claimant = Audit(tmp_path / "issuer"), Audit(tmp_path / "claimant")
        issued = issuer.run(ticket, pool, _payload(data))
        at_issue = [_events_of(issuer, faults), _events_of(claimant, faults)]
        answer = claimant.run(pool.collect, issued)
    observed = {"at issue": at_issue, "answer": answer,
                "issuer": _events_of(issuer, faults), "claimant": _events_of(claimant, faults)}
    assert observed == {"at issue": [(0, 0), (0, 0)], "answer": reason,
                        "issuer": (0, 0), "claimant": counted}


# Discards, each of a ticket whose worker is in another state: replied, crashed (EOF), past the
# RSS bound after replying (Linux), and silent (a hang). (hook, bytes, wait for the reply).
_DISCARDS: tuple[tuple[tuple[str, ...] | None, bytes | Path, bool], ...] = (
    (None, PROBE_JS, True),
    (CRASH_HOOK, _JS, True),
    (None, BOMB, True),
    (("hang.py",), _JS, False),
)


def _discarded(patch: pytest.MonkeyPatch, audit: Audit, procs: list[Any], case: tuple[Any, ...]) -> None:
    """One ticket of ``case`` issued by ``audit`` on a fresh two-slot pool, then discarded by
    it — once the worker's reply (or its end) is readable, when ``case`` waits for it."""
    hook, data, wait = case
    with closing(sized_pool(patch, 2, _command(hook, audit.root))) as pool:
        issued = audit.run(ticket, pool, _payload(data))
        assert not wait or readable(procs[-1]), "the worker never replied"
        audit.run(pool.discard, issued)


def test_issue_and_discard_record_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 8: issues and discards — a replied, a crashed, an RSS-spent and a silent worker's —
    leave the audit's coverage (``tallies.cache``, ``workers.recycled`` included), its
    ``declined`` map, its ledger and its breaker as a fresh audit's, and the cache's entries,
    bytes and LRU order as they were."""
    faults = spy_on(monkeypatch, ast_context.Breaker, "record")
    procs = record_spawns(monkeypatch)
    assert get_model(write(tmp_path / "stored.js", numbered_as(PATH_JS, 0))) is not None
    before = cache_state()
    audit = Audit(tmp_path)
    for case in _DISCARDS:
        _discarded(monkeypatch, audit, procs, case)
    observed = {
        "coverage": audit.snapshot(), "declined": dict(audit.state.declined),
        "declines": audit.state.ledger.render(tmp_path),
        "faults": faults_of(faults, audit.state.breaker),
        "cache": cache_state(),
    }
    expected = {"coverage": Audit(tmp_path).snapshot(), "declined": {}, "declines": [],
                "faults": 0, "cache": before}
    assert observed == expected


def test_discard_never_waits_on_a_silent_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 9: ``discard`` of a hung worker's ticket returns at once (``budget(0.5)``), frees
    the slot, and ends and reaps the worker."""
    procs = record_spawns(monkeypatch)
    with closing(sized_pool(monkeypatch, 2, hook_command("hang.py"))) as pool:
        audit = Audit(tmp_path)
        issued = audit.run(ticket, pool, _JS)
        started = time.perf_counter()
        audit.run(pool.discard, issued)
        waited = time.perf_counter() - started
        observed = {"prompt": waited <= budget(0.5), "free slots": pool._free.qsize(),
                    "reaped": [proc.returncode is not None for proc in procs]}
    assert observed == {"prompt": True, "free slots": pool.size, "reaped": [True]}


# ── 10-12. the walk, advance and the claim ───────────────────────────────────


def _walked(files: list[Path], families: frozenset[str]) -> list[Path]:
    with prefetch_mod().walk(files, families) as walked:
        return list(walked)


def test_a_walk_registers_passively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 10: entering (and leaving) a walk calls no pool operation and no reader, and records
    nothing on the audit; it yields its files as given."""
    files = js_files(tmp_path, 4)
    log: list[Any] = []
    pool_spies(monkeypatch, log)
    for owner, name in ((file_scanner, "read_file_safe"), (file_scanner, "read_file_uncached"),
                        (ast_cache, "read_file_uncached")):
        spy_on(monkeypatch, owner, name, log)
    audit = Audit(tmp_path)
    observed = {"walked": audit.run(_walked, files, PATH), "calls": log,
                "coverage": audit.snapshot(), "declined": dict(audit.state.declined)}
    assert observed == {"walked": files, "calls": [], "coverage": Audit(tmp_path).snapshot(),
                        "declined": {}}


_AHEAD_11 = 3  # with W = 4 (3 tickets), no position of this walk is ever refused a slot
# The walk of test 11, in order: each file and what it is. Every second file at least is one
# the consumer asks for, so every position falls in some advance's window.
_LAYOUT_11: tuple[tuple[str, str], ...] = (
    ("n00.js", "needed"), ("stored.js", "stored"), ("none.rb", "no profile"),
    ("n03.js", "needed"), ("lib.c", "not owned"), ("n05.js", "needed"),
    ("plain.js", "no sink key"), ("n07.js", "needed"), ("big.js", "too large"),
    ("n09.js", "needed"), ("dangling.js", "unreadable"), ("n11.js", "needed"),
    ("declined.js", "declined"), ("n13.js", "needed"), ("inflight.js", "in flight"),
    ("n15.js", "needed"), ("link.js", "ticketed"), ("n17.js", "needed"),
    ("n18.js", "needed"), ("n19.js", "needed"),
)


def _text(template: str) -> Callable[[Path, int], object]:
    """A writer of ``template`` numbered by the file's walk position."""
    return lambda path, index: write(path, numbered_as(template, index))


def _link(target: str) -> Callable[[Path, int], object]:
    """A writer of a symbolic link to ``target``, a name beside it."""
    return lambda path, _index: path.symlink_to(path.parent / target)


_SOURCES_11: dict[str, Callable[[Path, int], object]] = {
    "needed": _text(REQUEST_JS),
    "stored": _text(REQUEST_JS),
    "in flight": _text(REQUEST_JS),
    "no profile": _text("fetch(params[:u{i}])\n"),
    "not owned": _text("int main(void) { return fetch(url{i}); }\n"),
    "no sink key": _text(PLAIN_JS),
    "too large": _text("//" + "x" * MAX_FILE_SIZE + "\n" + REQUEST_JS),
    "unreadable": _link("missing.js"),
    "declined": _text(REQUEST_JS + _TOO_DEEP.decode()),  # the worker refuses it: too_deep
    "ticketed": _link("n15.js"),  # the same file, the same key, as n15.js
}


class _Cursor(Pace):
    """Test 11's consumer pace: it remembers the walk position being asked for, and lets the
    in-flight request finish just before the walk reaches that file."""

    def __init__(self, hold_at: int, release: threading.Event, flight: threading.Thread) -> None:
        self.index = -1
        self._hold_at, self._release, self._flight = hold_at, release, flight

    def before(self, index: int) -> None:
        self.index = index
        if index == self._hold_at:
            self._release.set()
            self._flight.join(budget(30.0))


def _layout_11(root: Path) -> list[Path]:
    files = [root / name for name, _ in _LAYOUT_11]
    for index, (path, (_, kind)) in enumerate(zip(files, _LAYOUT_11, strict=True)):
        _SOURCES_11[kind](path, index)
    return files


@contextmanager
def _held_flight(
    audit: Audit, path: Path, parse_spy: Spy
) -> Iterator[tuple[threading.Thread, threading.Event]]:
    """A skill thread of ``audit`` leading ``path``'s flight, held inside ``parse`` until the
    yielded Event is set: ``path``'s key is in flight meanwhile. However the block ends, the
    flight is let go and joined."""
    entered, release = threading.Event(), threading.Event()
    data = path.read_bytes()

    def hold(arguments: dict[str, Any]) -> None:
        if arguments["data"] == data:
            entered.set()
            release.wait(budget(30.0))

    parse_spy.before = hold
    flight = threading.Thread(target=audit.skill().run, args=(owns_answer, path), daemon=True)
    flight.start()
    try:
        assert entered.wait(budget(30.0)), "the in-flight request never reached the pool"
        yield flight, release
    finally:
        release.set()
        flight.join(budget(30.0))


_NAMES_11 = [name for name, _ in _LAYOUT_11]
# What the consumer gets an answer for: every file it asks for, but the declined one.
_ANSWERED_11 = [name for name, kind in _LAYOUT_11
                if kind in {"needed", "stored", "in flight", "ticketed"}]


def _issued_names(files: list[Path], issue_spy: Spy) -> list[str]:
    """The walk file each issued ticket shipped, in issue order (``n*`` files are distinct)."""
    by_bytes = {path.read_bytes(): path.name for path in files if path.name.startswith("n")}
    return [by_bytes[data] for data in shipped(issue_spy)]


def _considered(seen: list[tuple[int, Any]]) -> list[tuple[int, int]]:
    """Each consideration as (the position being asked for, the position considered)."""
    return [(index, _NAMES_11.index(Path(file).name)) for index, file in seen]


def _outside(positions: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The considerations not in (cursor, cursor + PREFETCH_AHEAD]."""
    return [pair for pair in positions if not 0 < pair[1] - pair[0] <= _AHEAD_11]


def _answered(answers: list[Any]) -> list[str]:
    return [_NAMES_11[i] for i, answer in enumerate(answers) if answer is not None]


def test_advance_issues_only_what_its_consumer_would_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 11: ``advance`` never issues a file with no profile, a profile owning none of the
    walk's families (C has no ``request``), a file with no sink key, a ``too_large`` or
    unreadable file, or a key that is stored, in flight, declined or already ticketed; its
    tickets follow walk order; each position is considered once, and none more than
    ``PREFETCH_AHEAD`` positions past the file being asked for. (A file the skill skips never
    reaches the walk: the cwe ``test_0102_prefetch_heads.py`` pins it.)"""
    set_ahead(monkeypatch, _AHEAD_11)
    files = _layout_11(tmp_path)
    spies = pool_spies(monkeypatch)
    audit = Audit(tmp_path)
    audit.run(owns_answer, tmp_path / "stored.js")
    audit.run(owns_answer, tmp_path / "declined.js")
    seen: list[tuple[int, Any]] = []
    with _held_flight(audit, tmp_path / "inflight.js", spies["parse"]) as (flight, release):
        cursor = _Cursor(_NAMES_11.index("inflight.js"), release, flight)
        spy_on(monkeypatch, ast_cache, "issue_ahead").before = (
            lambda arguments: seen.append((cursor.index, arguments["file"])))
        issued_in_setup = spies["issue"].made()
        answers = audit.skill().run(walk_all, files, REQUEST, cursor)
    positions = _considered(seen)
    observed = {
        "issued in setup": issued_in_setup,
        "issued": _issued_names(files, spies["issue"]),
        "refused": len(spies["issue"].calls) - spies["issue"].made(),
        "considered": [_NAMES_11[position] for _, position in positions],
        "outside the window": _outside(positions),
        "answered": _answered(answers),
    }
    assert observed == {
        "issued in setup": 0,
        "issued": ["n03.js", "n05.js", "n07.js", "n09.js", "n11.js", "n13.js", "n15.js",
                   "n17.js", "n18.js", "n19.js"],
        "refused": 0,
        "considered": _NAMES_11[1:],
        "outside the window": [],
        "answered": _ANSWERED_11,
    }


# Each test-12 scenario: (its audit, the walk's two files a and b, the pool spies).


def _claimed_by_many(audit: Audit, a: Path, b: Path, spies: dict[str, Spy]) -> dict[str, Any]:
    """A ticket for ``b``, then four skill threads asking for ``b`` at once."""
    with _advanced(audit.skill(), [a, b]):
        answers = at_once(audit, partial(owns_answer, b), 4)
    return {"issued": spies["issue"].made(), "collected": len(spies["collect"].calls),
            "parsed": shipped(spies["parse"]).count(b.read_bytes()),
            "discarded": len(spies["discard"].calls), "one answer": len({id(x) for x in answers}),
            "answered": None not in answers}


def _rewritten(audit: Audit, a: Path, b: Path, spies: dict[str, Spy]) -> dict[str, Any]:
    """A ticket for ``b``, then ``b`` rewritten (a new size and mtime) before it is asked for."""
    skill = audit.skill()
    with _advanced(skill, [a, b]):
        write(b, numbered_as(PATH_JS, 1) + "// rewritten\n")
        answer = skill.run(owns_answer, b)
        discarded_before_exit = len(spies["discard"].calls)
    return {"issued": spies["issue"].made(), "collected": len(spies["collect"].calls),
            "parsed": shipped(spies["parse"]).count(b.read_bytes()), "answered": answer is not None,
            "discarded": (discarded_before_exit, len(spies["discard"].calls))}


def _changed_while_claimed(
    audit: Audit, a: Path, b: Path, spies: dict[str, Spy]
) -> dict[str, Any]:
    """A ticket for ``b``, claimed; ``b`` changes while its ticket is collected (after the
    request's stat): the answer is served, not stored (A9), and the next request ships again."""
    key = answer_key(b)
    spies["collect"].before = lambda _arguments: write(b, numbered_as(PATH_JS, 1) + "// changed\n")
    skill = audit.skill()
    with _advanced(skill, [a, b]):
        answer = skill.run(owns_answer, b)
    stored = known(key)
    spies["collect"].before = None
    again = skill.run(owns_answer, b)
    return {"collected": len(spies["collect"].calls), "answered": answer is not None,
            "stored": stored, "asked again": shipped(spies["parse"]).count(b.read_bytes()),
            "answered again": again is not None}


_CLAIMS: dict[str, tuple[Callable[..., dict[str, Any]], dict[str, Any]]] = {
    "exclusive pop": (_claimed_by_many, {"issued": 1, "collected": 1, "parsed": 0, "discarded": 0,
                                         "one answer": 1, "answered": True}),
    "rewritten before the request": (_rewritten, {"issued": 1, "collected": 0, "parsed": 1,
                                                  "answered": True, "discarded": (0, 1)}),
    "changed while claimed": (_changed_while_claimed, {"collected": 1, "answered": True,
                                                       "stored": False, "asked again": 1,
                                                       "answered again": True}),
}


@pytest.mark.parametrize("scenario", sorted(_CLAIMS))
def test_a_ticket_is_claimed_only_by_its_keys_flight_leader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool, scenario: str
) -> None:
    """Test 12: the claim is the key's flight leader's, an exclusive pop (four threads asking
    at once collect the ticket once and parse nothing); a file rewritten between issue and
    request leaves its ticket unclaimed, ships synchronously, and the ticket is discarded at
    walk exit; a file changed while its ticket is claimed is served, not stored (A9)."""
    run, expected = _CLAIMS[scenario]
    spies = pool_spies(monkeypatch)
    a, b = js_files(tmp_path, 2)
    assert run(Audit(tmp_path), a, b, spies) == expected


# ── 13-15. the cache ─────────────────────────────────────────────────────────


def _state(audit: Audit) -> tuple[dict[str, Any], dict[str, int]]:
    return cache_state(), audit.cache_events()


def test_prefetch_never_evicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 13: with a budget for two answers, issuing and discarding never change the cache's
    entries, bytes, LRU order or ``evictions``; only a claimant's build stores (and evicts)."""
    files = js_files(tmp_path, 6)
    spies = pool_spies(monkeypatch)
    audit = Audit(tmp_path)
    audit.run(owns_answer, files[0])
    monkeypatch.setattr(model_cache(), "budget", model_cache().bytes * 5 // 2)
    audit.run(owns_answer, files[1])
    before, skill = _state(audit), audit.skill()
    with _advanced(skill, files[2:]):
        at_issue = _state(audit)
    after_discard = _state(audit)
    with _advanced(skill, files[2:]):
        skill.run(owns_answer, files[3])
        at_claim = _state(audit)
    observed = {"issued": spies["issue"].made(), "at issue": at_issue == before,
                "after discard": after_discard == before,
                "at claim": (at_claim[0]["keys"], at_claim[1])}
    assert observed == {
        "issued": 2 * (pool4.size - limits.PREFETCH_RESERVE), "at issue": True,
        "after discard": True,
        "at claim": ([answer_key(files[1]), answer_key(files[3])],
                     {"hits": 0, "misses": 3, "evictions": 1}),
    }


def _ask_all(ask: Callable[[Path], Any], files: list[Path]) -> None:
    for path in files:
        ask(path)


def _analysed_model(path: Path) -> Any:
    """``get_model(path)`` with its analysis built: what the library path leaves cached."""
    model = get_model(path)
    model.analysis()
    return model


def _weights(root: Path, files: list[Path]) -> tuple[int, int]:
    """The cache weight of ``files``' answers, then of their analysed models, each measured
    cold in an audit of its own; the cache is left empty."""
    weights = []
    for ask in (owns_answer, _analysed_model):
        ast_cache.clear()
        Audit(root).run(_ask_all, ask, files)
        weights.append(model_cache().bytes)
    ast_cache.clear()
    return weights[0], weights[1]


def test_two_consumers_parse_each_needed_file_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 14: two consumer threads of one audit walk one tree — the trailer starts once the
    leader is ``PREFETCH_AHEAD`` files in and burns CPU per file, no sleeps — under a budget
    that holds the answers but not the models: the pool is asked once per needed key (a
    synchronous parse or an issued ticket), and the misses are the keys."""
    files = js_files(tmp_path, 24)
    answers, models = _weights(tmp_path, files)
    cap = (answers + models) // 2
    monkeypatch.setattr(model_cache(), "budget", cap)
    spies = pool_spies(monkeypatch)
    audit = Audit(tmp_path)
    ahead = threading.Event()
    paces = (Leader(ahead, limits.PREFETCH_AHEAD + 2), Trailer(ahead))
    walks = in_threads(*(partial(audit.skill().run, walk_all, files, PATH, p) for p in paces))
    observed = {
        "budget holds the answers, not the models": answers < cap < models,
        "answered": [None not in walk for walk in walks],
        "pool requests": len(spies["parse"].calls) + spies["issue"].made(),
        "cache": audit.cache_events(),
    }
    assert observed == {
        "budget holds the answers, not the models": True,
        "answered": [True, True],
        "pool requests": len(files),
        "cache": {"hits": len(files), "misses": len(files), "evictions": 0},
    }


def _lockstep_events(root: Path, files: list[Path], first: int) -> dict[str, int]:
    """Two consumer threads of a new audit walk ``files`` in lockstep, consumer ``first``
    asking for each file before the other: the audit's ``tallies.cache``."""
    audit = Audit(root)
    paces = Lockstep.pair(len(files), first)
    in_threads(*(partial(audit.skill().run, walk_all, files, PATH, pace) for pace in paces))
    return audit.cache_events()


def test_cache_tallies_are_unchanged_by_prefetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 15 (A41 (8) as written): two consumers walking one tree, in each of the two orders
    the ``Event``s force, cold (an empty cache) and then warm (a second audit), count the same
    hits, misses and evictions with ``PREFETCH_AHEAD`` patched to 0 as with its default."""
    files = sorted(js_files(tmp_path, 10) + js_files(tmp_path, 3, PLAIN_JS, stem="p"))
    runs: dict[tuple[int, int], tuple[dict[str, int], dict[str, int]]] = {}
    for ahead in (0, limits.PREFETCH_AHEAD):
        set_ahead(monkeypatch, ahead)
        for first in (0, 1):
            ast_cache.clear()
            cold = _lockstep_events(tmp_path, files, first)
            runs[ahead, first] = cold, _lockstep_events(tmp_path, files, first)
    needed = 10
    cold = {"hits": needed, "misses": needed, "evictions": 0}
    warm = {"hits": 2 * needed, "misses": 0, "evictions": 0}
    assert runs == dict.fromkeys(runs, (cold, warm))


# ── 16-19. the walk's end, threads, imports, reads ───────────────────────────


class _Abort(Exception):
    """Raised inside a walk: a skill that fails mid-walk."""


def _advance_then_end(files: list[Path], ending: str) -> str:
    """A walk that issues tickets, then ends normally (``exit``) or by a raise; how it ended."""
    try:
        with prefetch_mod().walk(files, PATH):
            prefetch_mod().advance(files[0])
            if ending == "raise":
                raise _Abort
    except _Abort:
        return "raise"
    return "exit"


@pytest.mark.parametrize("ending", ["exit", "raise"])
def test_a_walk_drains_its_tickets_on_exit_and_on_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool, ending: str
) -> None:
    """Test 16: tickets a walk issued and nobody claimed are discarded when it ends, normally or
    by a raise: afterwards every slot is free and the outstanding count is 0."""
    files = js_files(tmp_path, 6)
    issue = pool_spies(monkeypatch)["issue"]
    ended = Audit(tmp_path).run(_advance_then_end, files, ending)
    observed = {"issued": issue.made(), "ended": ended, "pool": drained(pool4)}
    assert observed == {"issued": pool4.size - limits.PREFETCH_RESERVE, "ended": ending,
                        "pool": idle(pool4)}


def _left(root: Path) -> tuple[contextvars.Context, Any, Callable[[], None]]:
    """A skill thread's context of an entered audit, the audit, and ``context.leave``."""
    audit = Audit(root)
    return audit.skill(), audit.state, audit.leave


def _reset(_root: Path) -> tuple[contextvars.Context, Any, Callable[[], None]]:
    """A context on the process default, the default, and ``context.reset_default``."""
    ctx = contextvars.Context()
    return ctx, ctx.run(ast_context.current), ast_context.reset_default


_CLOSERS = {"leave": _left, "reset_default": _reset}


@pytest.mark.parametrize("closer", sorted(_CLOSERS))
def test_leave_and_reset_default_close_the_ticket_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool, closer: str
) -> None:
    """Test 17: leaving an audit (or resetting the process default) closes its ticket index:
    its outstanding tickets are discarded, a later issue for it is refused, and a request goes
    synchronous — what an abandoned skill thread meets once its audit ended."""
    files = js_files(tmp_path, 6)
    spies = pool_spies(monkeypatch)
    ctx, state, close = _CLOSERS[closer](tmp_path)
    with _advanced(ctx, files):
        issued = spies["issue"].made()
        close()
        after_close = drained(pool4)
        calls = {name: len(spy.calls) for name, spy in spies.items()}
        ctx.run(ast_cache.issue_ahead, files[1], PATH, state)
        answer = ctx.run(owns_answer, files[2])
        later = {name: len(spy.calls) - calls[name] for name, spy in spies.items()}
    assert {"issued": issued, "after close": after_close, "later": later,
            "answered": answer is not None} == {
        "issued": pool4.size - limits.PREFETCH_RESERVE, "after close": idle(pool4),
        "later": {"parse": 1, "issue": 0, "collect": 0, "discard": 0}, "answered": True,
    }


class _Census(Pace):
    """Every thread alive at any step of a walk."""

    def __init__(self) -> None:
        self.seen: set[int | None] = set()

    def after(self, index: int) -> None:
        self.seen.update(thread.ident for thread in threading.enumerate())


_HEAVY = ("shared.ast.pool", "shared.ast.cache", "shared.ast.model", "shared.ast.flow",
          "tree_sitter")


def test_prefetch_starts_no_thread_and_stays_light(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 18: no thread appears during a walked two-skill run (two walks of one audit, one
    after the other, as two skills; tickets issued), and a fresh ``import shared.ast.prefetch``
    loads none of the pool, the cache, the model, the flow pass or ``tree_sitter``
    (``test_0102_imports.py`` unchanged)."""
    files = js_files(tmp_path, 10)
    issue = pool_spies(monkeypatch)["issue"]
    before = {thread.ident for thread in threading.enumerate()}
    census = _Census()
    audit = Audit(tmp_path)
    for _skill in range(2):
        audit.run(walk_all, files, PATH, census)
    observed = {"issued": bool(issue.made()), "new threads": sorted(census.seen - before),
                "loaded": loaded_after_import("shared.ast.prefetch", _HEAVY)}
    assert observed == {"issued": True, "new threads": [], "loaded": []}


def _read_by_walk(files: list[Path]) -> set[str]:
    with record_reads() as reads:
        walk_all(files, PATH)
    return set(reads)


def test_prefetch_reads_match_the_synchronous_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pool4: WorkerPool
) -> None:
    """Test 19 (§16 risk 23 (g)): a completed walk reads (``record_reads()``) exactly the files
    the ``PREFETCH_AHEAD = 0`` run reads — a too-large file, a file with no profile and a file
    with no sink key among them."""
    files = sorted([
        *js_files(tmp_path, 8),
        write(tmp_path / "f003b.js", numbered_as(PLAIN_JS, 3)),
        write(tmp_path / "f004b.rb", "File.read(params[:f])\n"),
        write(tmp_path / "f005b.js", "//" + "x" * MAX_FILE_SIZE + "\n" + numbered_as(PATH_JS, 5)),
    ])
    issue = pool_spies(monkeypatch)["issue"]
    default = limits.PREFETCH_AHEAD
    reads: dict[int, set[str]] = {}
    for ahead in (0, default):
        set_ahead(monkeypatch, ahead)
        with cold_caches():
            reads[ahead] = Audit(tmp_path).run(_read_by_walk, files)
    observed = {"issued": bool(issue.made()), "read": len(reads[0]), "same": reads[default] == reads[0]}
    assert observed == {"issued": True, "read": len(files) - 1, "same": True}
