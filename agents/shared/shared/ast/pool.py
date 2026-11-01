"""The worker pool: isolated parse workers, limits, timeouts, recycling, breaker (feature 0102).

The only door between an adversarial repository and the agent process (LLD D2, D3, D10, §4,
§8.7, §11). tree-sitter runs in spawned workers, never forked and never in this process: each
worker is ``[sys.executable, "-I", "-c", BOOTSTRAP]`` in a private empty cwd with env
``{PATH, LANG}`` and stderr on ``DEVNULL`` (a worker under ``RLIMIT_FSIZE = 0`` would die on its
first stderr byte to a regular file). The parent ships a JSON header frame and the file bytes
and reads ONE JSON frame back.

``WorkerPool.parse`` never raises. Every fault is a ``FallbackReason`` (each its own §10.2
bucket; ``unsupported``, ``parse_error`` and ``too_large`` are decided before the pool):

* ``worker_crashed`` — the reply ended early (EOF, including mid-frame);
* ``timeout`` — the whole round trip, write and read, passed ``WALL_TIMEOUT_S``; the deadline
  is re-armed around every chunk, so a worker that stops reading or stalls mid-frame is
  SIGKILLed and reaped instead of wedging its slot;
* ``ir_too_large`` / ``too_deep`` / ``worker_error`` — the worker's own per-file answer, or
  (``ir_too_large``) a reply announced above ``FRAME_CAP``, refused from its length alone;
* ``bad_model`` — a complete frame that is not a JSON document for this request;
* ``spawn_failed`` — no private cwd, ``Popen`` refused (EMFILE, EAGAIN, ENOSPC, exec), or the
  file could not be shipped (EPIPE to a worker reaped between files);
* ``circuit_open`` — this audit's breaker tripped: ``CIRCUIT_BREAK_AFTER`` timeouts or crashes
  (D10). Per-file worker errors and a SIGXCPU exit (risk 14: a lifecycle exit of the
  cumulative ``RLIMIT_CPU``) do not count. The breaker is the current ``AuditContext``'s
  (``context.current()``, D20), so a fault counts against the audit whose request met it.

The pool and its workers live for the PROCESS (§4): ``get_pool()`` is one pool, and the
per-audit reset (``file_scanner.clear_caches()``) never ends or respawns a worker. Requests
queue FIFO for ``worker_count()`` slots; a slot starts its worker on first use and replaces
it after ``RECYCLE_AFTER`` files, after a request that left its resident high-water above
``MAX_WORKER_RSS_MB`` (A5, A43 (5): read from ``/proc`` on Linux, skipped elsewhere), or after
any fault that leaves it untrusted.

**Tickets (§4.1 item 5, A44 (2)).** A round trip is a ``send`` and a ``receive`` under one
deadline; ``parse`` runs both on a slot it waits for. ``issue`` runs the send alone, on a slot
taken without waiting, and returns its ``Ticket``: ``collect`` runs the receive later — its
deadline armed then, its breaker fault and recycle recorded on the collecting audit, exactly as
``parse`` records them — and ``discard`` drops the request, recording nothing and never waiting
on a silent worker. Tickets never take the last ``PREFETCH_RESERVE`` slots (an exact count
under a lock), so W = 1 never issues and a synchronous request always finds a slot.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import shared
from shared.ast._frames import ModelError, decode_json, read_frame, write_frame
from shared.ast.context import Breaker, current
from shared.ast.coverage import BREAKER_FAULTS, FallbackReason
from shared.ast.limits import (
    FRAME_CAP,
    MAX_WORKER_RSS_MB,
    MAX_WORKERS,
    MODEL_CACHE_CAP,
    MODEL_CACHE_SHARE,
    PREFETCH_RESERVE,
    RECYCLE_AFTER,
    WALL_TIMEOUT_S,
    WORKER_RESERVE,
)
from shared.tools import membudget

__all__ = [
    "BOOTSTRAP",
    "SHARED_ROOT",
    "FallbackReason",
    "Limits",
    "ParseResult",
    "Ticket",
    "WorkerPool",
    "get_pool",
    "model_cache_budget",
    "pool_size",
    "reset_pool_for_tests",
    "worker_count",
]

logger = logging.getLogger(__name__)

ParseResult = dict[str, Any] | FallbackReason

# D2: the parent's own ``shared`` root, the one entry the bootstrap puts on the worker's
# sys.path. ``-I`` drops PYTHONPATH, the user site and the cwd, so a scanned tree never
# supplies a module.
SHARED_ROOT = str(Path(shared.__file__).resolve().parent.parent)
BOOTSTRAP = (
    f"import sys; sys.path.insert(0, {SHARED_ROOT!r}); from shared.ast._worker import main; main()"
)

# The worker's answers that name a per-file reason; anything else is not a document.
_ANSWERED: frozenset[str] = frozenset({"ir_too_large", "too_deep", "worker_error"})
# A round trip that raised: the first matching class names the reason. TimeoutError is an
# OSError, so it comes first; any other OSError is a worker that could not take the file.
_TRANSPORT_FAULTS: tuple[tuple[type[Exception], FallbackReason], ...] = (
    (TimeoutError, "timeout"),
    (ModelError, "ir_too_large"),
    (OSError, "spawn_failed"),
)
_TRANSPORT_CLASSES = tuple(kind for kind, _ in _TRANSPORT_FAULTS)
# Risk 14: the exit of a worker killed by its cumulative RLIMIT_CPU (a lifecycle exit).
_XCPU_EXIT = -signal.SIGXCPU if hasattr(signal, "SIGXCPU") else None


# ── how many workers (§4) ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Limits:
    """What sizes the pool: the CPU quota, the deployment memory limit and this process's
    resident size now, all in the units ``worker_count`` reads (CPUs, bytes, bytes)."""

    cpu_quota: float
    memory_limit: int
    rss_now: int

    @classmethod
    def read(cls, root: Path = membudget.CGROUP_ROOT) -> Limits:
        """The limits through feature 0103's one reader, plus this process's RSS."""
        return cls(
            cpu_quota=membudget.cpu_quota(root=root),
            memory_limit=membudget.deployment_memory_limit(root=root),
            rss_now=membudget.rss_now(),
        )


def model_cache_budget(limit: int) -> int:
    """D5: the model cache's byte budget, ``min(128 MB, 25 % of the limit)``."""
    return min(MODEL_CACHE_CAP, limit // MODEL_CACHE_SHARE)


def worker_count(limits: Limits) -> int:
    """§4: ``clamp(1, min(cpu_quota, (limit - rss_now - cache_budget) // WORKER_RESERVE),
    MAX_WORKERS)``; ``cache_budget`` is BOTH content caches (the model cache and the read
    cache), and a fractional quota is never rounded up."""
    limit = limits.memory_limit
    caches = model_cache_budget(limit) + membudget.read_cache_budget(limit)
    by_memory = (limit - limits.rss_now - caches) // WORKER_RESERVE
    return membudget.clamp(1, min(int(limits.cpu_quota), by_memory), MAX_WORKERS)


# ── the breaker (D10, D20) ───────────────────────────────────────────────────


def _breaker() -> Breaker:
    """The current audit's breaker (D20): the one place the pool reaches one. It bounds that
    audit, never the process (D10)."""
    return current().breaker


# ── one worker process (D2, D3) ──────────────────────────────────────────────


def _worker_env() -> dict[str, str]:
    """D2: a worker's whole environment — no key, no PYTHONPATH."""
    return {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}


def _end_process(proc: subprocess.Popen[bytes], home: str) -> None:
    """SIGKILL (if still running), reap, close the pipes, remove the private cwd."""
    if proc.poll() is None:
        proc.kill()
    proc.wait()
    for stream in (proc.stdin, proc.stdout):
        with suppress(OSError, AttributeError):
            stream.close()  # type: ignore[union-attr]
    shutil.rmtree(home, ignore_errors=True)


def _header(request_id: int, language: str, grammar: str | None, answer: bool) -> bytes:
    """A request's header frame (D3): its id and language, the grammar entry point when it is
    not the language's own, and ``"answer": true`` when it asks for the file's answer (§4.1
    item 1; a skeleton request's header is unchanged)."""
    named = {} if grammar is None else {"grammar": grammar}
    asked = {"answer": True} if answer else {}
    return json.dumps({"id": request_id, "language": language, **named, **asked}).encode()


def _decode(payload: bytes | bytearray, request_id: int) -> ParseResult:
    """The worker's reply: its document, its per-file reason, or ``bad_model`` (D3)."""
    try:
        doc = decode_json(payload)
    except ModelError:
        return "bad_model"
    if not isinstance(doc, dict) or doc.get("id") != request_id:
        return "bad_model"
    return _answer(doc)


def _transport_reason(exc: Exception) -> FallbackReason:
    return next(reason for kind, reason in _TRANSPORT_FAULTS if isinstance(exc, kind))


def _answer(doc: dict[str, Any]) -> ParseResult:
    error = doc.get("error")
    if error is None:
        return doc
    reason = str(error).partition(":")[0]
    return reason if reason in _ANSWERED else "bad_model"  # type: ignore[return-value]


# A5, A43 (5): a worker's resident high-water, bounded by ``MAX_WORKER_RSS_MB``. Linux reports
# it as the ``VmHWM`` row of ``/proc/<pid>/status``, in kB; elsewhere nothing is read.
_HIGH_WATER_ROW = b"VmHWM:"
_RSS_BOUND_KB = MAX_WORKER_RSS_MB * 1024


def _proc_high_water_kb(pid: int) -> int:
    """``pid``'s resident high-water in kB: one open and one read of its ``status``; 0 when
    the process is gone or the row is missing."""
    try:
        with open(f"/proc/{pid}/status", "rb", buffering=0) as status:
            _, _, row = status.read().partition(_HIGH_WATER_ROW)
        return int(row.partition(b"kB")[0] or 0)
    except (OSError, ValueError):
        return 0


def _no_high_water_kb(_pid: int) -> int:
    """Off Linux there is no ``/proc`` high-water: the RSS check is skipped (never spent)."""
    return 0


_high_water_kb = _proc_high_water_kb if sys.platform.startswith("linux") else _no_high_water_kb


# Every worker not yet ended. A worker ends when its slot retires it, never because its pool
# was dropped; whatever is still here when the interpreter exits is ended then (finalize).
_LIVE: set[_Worker] = set()


class _Worker:
    """One spawned worker. ``end`` is idempotent; a worker never ended explicitly is ended at
    interpreter exit, so no process or private cwd outlives the agent."""

    def __init__(self, proc: subprocess.Popen[bytes], home: str) -> None:
        self.proc = proc
        self.served = 0
        self._finalizer = weakref.finalize(self, _end_process, proc, home)
        _LIVE.add(self)

    def end(self) -> None:
        """SIGKILL, reap, close, remove the private cwd — once."""
        _LIVE.discard(self)
        self._finalizer()

    @classmethod
    def spawn(cls, cmd: list[str]) -> _Worker | None:
        """A started worker, or ``None`` (``spawn_failed``) when the platform refuses."""
        try:
            home = tempfile.mkdtemp(prefix="ast-worker-")
        except OSError:
            return None
        worker = cls._start(cmd, home)
        if worker is None:
            shutil.rmtree(home, ignore_errors=True)
        return worker

    @classmethod
    def _start(cls, cmd: list[str], home: str) -> _Worker | None:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=home,
                env=_worker_env(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        worker = cls(proc, home)
        os.set_blocking(proc.stdin.fileno(), False)  # type: ignore[union-attr]
        return worker

    @property
    def alive(self) -> bool:
        return self._finalizer.alive and self.proc.poll() is None

    @property
    def spent(self) -> bool:
        """Dead, ended, done with its ``RECYCLE_AFTER`` files (D2), or grown past A5's bound."""
        return not self.alive or self.served >= RECYCLE_AFTER or self._past_rss_bound()

    def _past_rss_bound(self) -> bool:
        """A43 (5): its resident high-water passed ``MAX_WORKER_RSS_MB`` (a depth bomb takes a
        worker to about 65 MB); read only of a live worker, after its request."""
        return _high_water_kb(self.proc.pid) > _RSS_BOUND_KB

    def breaker_fault(self, result: ParseResult) -> bool:
        """D10: a timeout or a crash counts; a SIGXCPU exit is a lifecycle exit (risk 14:
        the cumulative RLIMIT_CPU, not the file being parsed) and does not."""
        return result in BREAKER_FAULTS and self.proc.returncode != _XCPU_EXIT

    def request(
        self, language: str, data: bytes, grammar: str | None = None, answer: bool = False
    ) -> ParseResult:
        """One file's round trip, ``send`` then ``receive``, bounded as a whole by
        ``WALL_TIMEOUT_S``. ``grammar`` is the profile's entry point for the file (None: the
        language's own, §6.3); ``answer`` asks for the file's answer (§4.1 item 1)."""
        deadline = _deadline()
        return self.send(language, data, grammar, answer, deadline) or self.receive(deadline)

    def send(
        self, language: str, data: bytes, grammar: str | None, answer: bool, deadline: float
    ) -> FallbackReason | None:
        """Ship one request, numbered by ``served`` (D3): None, or the fault that ended the
        worker on the way out (a full pipe past ``deadline``, a worker gone)."""
        self.served += 1
        header = _header(self.served, language, grammar, answer)
        try:
            write_frame(self.proc.stdin, header, deadline)  # type: ignore[arg-type]
            write_frame(self.proc.stdin, data, deadline)  # type: ignore[arg-type]
        except _TRANSPORT_CLASSES as exc:
            return self._fail(_transport_reason(exc))
        return None

    def receive(self, deadline: float) -> ParseResult:
        """The reply to the request ``send`` shipped last, read by ``deadline``."""
        try:
            payload = read_frame(self.proc.stdout, FRAME_CAP, deadline)  # type: ignore[arg-type]
        except _TRANSPORT_CLASSES as exc:
            return self._fail(_transport_reason(exc))
        return self._crashed(deadline) if payload is None else self._reply(payload)

    def _reply(self, payload: bytes | bytearray) -> ParseResult:
        result = _decode(payload, self.served)
        return self._fail(result) if result == "bad_model" else result

    def _crashed(self, deadline: float) -> FallbackReason:
        """EOF: let the process finish dying (within the file's deadline) so its exit status
        is its own, then end it."""
        with suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        return self._fail("worker_crashed")

    def _fail(self, reason: FallbackReason) -> FallbackReason:
        """A fault leaves the worker untrusted (desynchronised, hung or dead): end it."""
        self.end()
        return reason


# ── the pool (§4) ────────────────────────────────────────────────────────────


def _deadline() -> float:
    """One request's deadline from now: ``WALL_TIMEOUT_S`` (a whole round trip, or a ticket's
    read armed at collect)."""
    return time.monotonic() + WALL_TIMEOUT_S


def _refused(size: int) -> FallbackReason | None:
    """Why no request of ``size`` bytes may go to a worker now — the breaker is open, or the
    request would not fit a frame — else None."""
    if _breaker().tripped:
        return "circuit_open"
    return "ir_too_large" if size > FRAME_CAP else None


def _note_recycled(worker: _Worker) -> None:
    """A worker still alive when it is spent served its ``RECYCLE_AFTER`` files (D2) or grew
    past ``MAX_WORKER_RSS_MB`` (A43 (5))."""
    if worker.alive:
        current().coverage.record_recycled()


def _replied(worker: _Worker) -> bool:
    """Whether ``worker``'s reply pipe holds bytes, or its end, now: one poll that never
    waits."""
    poller = select.poll()
    poller.register(worker.proc.stdout.fileno(), select.POLLIN)  # type: ignore[union-attr]
    return bool(poller.poll(0))


class _Slot:
    """One of the pool's ``worker_count`` places for a worker, used by one request at a time:
    a synchronous ``parse``, or a ticket from ``issue`` until it is collected or discarded."""

    def __init__(self, cmd: list[str]) -> None:
        self._cmd = cmd
        self._worker: _Worker | None = None

    def parse(
        self, language: str, data: bytes, grammar: str | None = None, answer: bool = False
    ) -> ParseResult:
        if _breaker().tripped:
            return "circuit_open"
        worker = self._ready()
        if worker is None:
            return "spawn_failed"
        result = worker.request(language, data, grammar, answer)
        self._settle(worker, result)
        return result

    def issue(
        self, pool: WorkerPool, language: str, data: bytes, grammar: str | None, answer: bool
    ) -> Ticket:
        """``parse``'s send, now: the ticket of the request it shipped, or of the fault that
        met it (no worker could be started; the worker was lost on the way out), which
        ``collect`` answers."""
        worker = self._ready()
        if worker is None:
            return Ticket(pool, self, None, "spawn_failed")
        return Ticket(pool, self, worker, worker.send(language, data, grammar, answer, _deadline()))

    def collect(self, ticket: Ticket) -> ParseResult:
        """``parse``'s receive, for ``ticket``: ``circuit_open`` (the ticket discarded) once the
        collecting audit's breaker tripped; else the reply, read by a deadline armed NOW, its
        breaker fault and recycle recorded on the collecting audit (§4.1 item 5)."""
        if _breaker().tripped:
            self.discard(ticket)
            return "circuit_open"
        worker = ticket.worker
        if worker is None:
            return "spawn_failed"
        result = ticket.fault or worker.receive(_deadline())
        self._settle(worker, result)
        return result

    def discard(self, ticket: Ticket) -> None:
        """Drop ``ticket``'s request, recording nothing (no breaker fault, no recycle): a reply
        already readable is read and dropped; a worker with none yet is retired, never waited
        on. A worker left spent is replaced."""
        worker = ticket.pending
        if worker is None:
            return
        if _replied(worker):
            worker.receive(_deadline())
        else:
            worker.end()
        if worker.spent:
            self.retire()

    def retire(self) -> None:
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.end()

    def _ready(self) -> _Worker | None:
        """The slot's live worker, started (or replaced) on demand."""
        if self._worker is not None and not self._worker.alive:
            self.retire()
        if self._worker is None:
            self._worker = _Worker.spawn(self._cmd)
        return self._worker

    def _settle(self, worker: _Worker, result: ParseResult) -> None:
        """Count a breaker fault (D10) and replace a spent worker (D2), a recycled one
        counted on the current audit (§10.2 ``workers.recycled``)."""
        if worker.breaker_fault(result):
            _breaker().record()
        if worker.spent:
            _note_recycled(worker)
            self.retire()


@dataclass(frozen=True, slots=True, eq=False)
class Ticket:
    """A request sent ahead (§4.1 item 5): its pool and the slot it holds until ``collect`` or
    ``discard``; the worker that has it, None when none could be started; and the fault that
    met it on the way out, which ``collect`` answers instead of a reply."""

    pool: WorkerPool
    slot: _Slot
    worker: _Worker | None
    fault: FallbackReason | None = None

    @property
    def pending(self) -> _Worker | None:
        """The worker that owes this ticket a reply, or None."""
        return self.worker if self.fault is None else None


def _guarded[R](slot: _Slot, fallback: R, operation: Callable[..., R], *args: Any) -> R:
    """``operation(*args)`` on ``slot``, never raising: an unexpected fault retires the slot's
    worker and answers ``fallback`` (the pool's last guard)."""
    try:
        return operation(*args)
    except Exception as exc:  # a pool operation never raises
        logger.warning("ast worker pool: unexpected %s; file falls back", type(exc).__name__)
        slot.retire()
        return fallback


class WorkerPool:
    """Isolated parse workers behind a FIFO queue of ``worker_count()`` slots (§4).

    A request either waits for a free slot (``parse``) or is sent ahead on one taken without
    waiting (``issue``), answered later by ``collect`` or dropped by ``discard`` (§4.1 item 5).
    The outstanding tickets are counted exactly, under a lock, and never take the last
    ``PREFETCH_RESERVE`` slots: a synchronous request always finds one within
    ``WALL_TIMEOUT_S``, so a ticket holder never starves a request it waits on.

    ``cmd`` replaces the worker command (tests inject hook workers); every other part of the
    spawn — private cwd, env, pipes, stderr — is the same for any command.
    """

    def __init__(self, cmd: list[str] | None = None) -> None:
        command = list(cmd) if cmd else [sys.executable, "-I", "-c", BOOTSTRAP]
        self._slots: list[_Slot] = [_Slot(command) for _ in range(worker_count(Limits.read()))]
        self._free: queue.Queue[_Slot] = queue.Queue()
        for slot in self._slots:
            self._free.put(slot)
        self._tickets_lock = threading.Lock()
        self._tickets = 0

    def parse(
        self, language: str, data: bytes, grammar: str | None = None, answer: bool = False
    ) -> ParseResult:
        """The worker document for ``data`` in ``language``, parsed with the grammar entry
        point ``grammar`` (None: the language's own) — the file's answer when ``answer`` (§4.1
        item 1) — or why there is none. Never raises; never waits past one file's
        ``WALL_TIMEOUT_S`` once a slot is free."""
        refused = _refused(len(data))
        if refused is not None:
            return refused
        slot = self._free.get()
        try:
            return _guarded(slot, "worker_error", slot.parse, language, data, grammar, answer)
        finally:
            self._free.put(slot)

    def issue(
        self, language: str, data: bytes, grammar: str | None = None, answer: bool = False
    ) -> Ticket | None:
        """``parse``'s request sent now, on a slot taken without waiting: its ticket, or None —
        the breaker is open, ``data`` would not fit a frame, or no slot may be taken (§4.1
        item 5). It records nothing: what the request meets is recorded at ``collect``."""
        slot = self._take(len(data))
        if slot is None:
            return None
        ticket = _guarded(slot, None, slot.issue, self, language, data, grammar, answer)
        if ticket is None:
            self._release(slot)
        return ticket

    def issuable(self) -> bool:
        """Whether ``issue`` would find a slot now: a hint read without waiting, so a caller
        skips its read when none is free (another thread may still take it first; ``issue``
        decides)."""
        with self._tickets_lock:
            return not self._counted_out() and not self._free.empty()

    def collect(self, ticket: Ticket) -> ParseResult:
        """What ``parse`` answers ``ticket``'s request, its breaker fault and recycle recorded
        on the collecting audit; the slot freed. Never raises."""
        try:
            return _guarded(ticket.slot, "worker_error", ticket.slot.collect, ticket)
        finally:
            self._release(ticket.slot)

    def discard(self, ticket: Ticket) -> None:
        """Drop ``ticket``'s request and free its slot, recording nothing; never waits on a
        silent worker. Never raises."""
        try:
            _guarded(ticket.slot, None, ticket.slot.discard, ticket)
        finally:
            self._release(ticket.slot)

    @property
    def size(self) -> int:
        """W: the pool's slots, each one worker at most (§4)."""
        return len(self._slots)

    def close(self) -> None:
        """End every worker of this pool (a slot in use ends its worker mid-file)."""
        for slot in self._slots:
            slot.retire()

    def _take(self, size: int) -> _Slot | None:
        """A free slot for a ticket of ``size`` bytes, counted out; None while the breaker is
        open or the request would not fit a frame (``_refused``)."""
        if _refused(size) is not None:
            return None
        with self._tickets_lock:
            return self._spare()

    def _spare(self) -> _Slot | None:
        """Under the tickets lock: a free slot taken without waiting, and counted out, while
        fewer than ``size - PREFETCH_RESERVE`` tickets are out (W = 1 never has one)."""
        if self._counted_out():
            return None
        try:
            slot = self._free.get_nowait()
        except queue.Empty:
            return None
        self._tickets += 1
        return slot

    def _counted_out(self) -> bool:
        """Under the tickets lock: ``size - PREFETCH_RESERVE`` tickets are out already."""
        return self._tickets >= self.size - PREFETCH_RESERVE

    def _release(self, slot: _Slot) -> None:
        """A ticket's slot back in the queue, and the ticket counted in."""
        with self._tickets_lock:
            self._tickets -= 1
        self._free.put(slot)


_POOL: WorkerPool | None = None
_POOL_LOCK = threading.Lock()


def get_pool() -> WorkerPool:
    """The process's one pool, built on first use; it lives as long as the process."""
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = WorkerPool()
        return _POOL


def pool_size() -> int:
    """W of the process's pool (§10.2 ``workers.count``); 0 before it is built."""
    pool = _POOL
    return 0 if pool is None else pool.size


def reset_pool_for_tests() -> None:
    """End the process pool's workers and drop it. Never called by production code; the
    per-audit state (the breaker included) is the ``AuditContext``'s (D20)."""
    global _POOL
    with _POOL_LOCK:
        pool, _POOL = _POOL, None
    if pool is not None:
        pool.close()
