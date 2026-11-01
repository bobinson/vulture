"""Feature 0102, plan task 1.3 — the worker pool: isolation, limits, timeouts, recycling, breaker.

LLD D2, D3, D10, D18, D20, §4, §8.7, §11 (T1, T3, T4, T12, T13) and §16 risks 13-14. The pool
is the only door between an adversarial repository and the agent process: tree-sitter runs in
spawned, isolated workers; the parent ships bytes and reads one length-prefixed JSON frame back.
Pinned here:

* **``parse`` never raises and never wedges.** Every fault is a ``FallbackReason``: a crash
  (``worker_crashed``), a reply cut short (``worker_crashed``), a hang or a stall mid-frame
  (``timeout``, SIGKILL + reap, within ``WALL_TIMEOUT_S + 1``), a frame announced above
  ``FRAME_CAP`` (``ir_too_large``, from the length alone), a frame that is not a document
  (``bad_model``), a worker that cannot start or dies between files (``spawn_failed``), and
  the per-file worker errors ``too_deep`` / ``ir_too_large``. A syntax error is still a model:
  ``parse_error`` is decided in ``get_model``/``owns``, not here.
* **Isolation (D2, T4, T12).** The worker command is ``[sys.executable, "-I", "-c", BOOTSTRAP]``,
  its env exactly ``{PATH, LANG}``, its cwd a private empty directory, its stderr never a
  regular file, its limits ``NPROC = FSIZE = 0`` (Linux also ``AS = 256 MB``, ``CPU = 30 s``,
  ``PR_SET_NO_NEW_PRIVS``). A scanned tree that plants ``shared/ast/_worker.py`` and
  ``tree_sitter/__init__.py`` in the agent's cwd and on its ``PYTHONPATH`` supplies nothing.
* **Recycling (D2).** One worker serves ``RECYCLE_AFTER`` files; the next file is served by a
  new process and the old one is reaped. A replacement that cannot start is ``spawn_failed``.
* **Circuit breaker (D10, T13, review focus 5).** Twenty timeouts or crashes in one audit make
  every remaining file ``circuit_open`` at once, with no worker started, for every pool of that
  audit; per-file worker errors and a SIGXCPU lifecycle exit (risk 14) do not count; the next
  audit starts closed.
* **Sharing (§4).** Concurrent requests on a one-worker pool are served by that worker, each
  caller receiving its own document; a pool never runs more workers than ``worker_count``; and
  ``file_scanner.clear_caches()`` (the per-audit reset) never ends or respawns a worker.

Contracts this file relies on, each named by the plan or the LLD:

* Hook workers under ``_workers/`` are injected with ``WorkerPool(cmd=[...])`` (plan 1.3) and
  every spawn is observed by monkeypatching ``subprocess.Popen`` (plan 1.3).
* The probe frames ``{"id": 0, "probe": "modules"}`` (plan 1.3) and ``{"id": 0, "probe":
  "rlimits"}`` are answered by the real worker with one frame: ``{"id": 0, "modules": {name:
  __file__}}`` and ``{"id": 0, "rlimits": {"RLIMIT_<NAME>": [soft, hard]}}``. darwin cannot read
  another process's limits, so the worker reports its own (plan 1.3: "on darwin, RLIMIT_NPROC /
  RLIMIT_FSIZE are asserted set"); on Linux ``prlimit`` cross-checks them from outside.
* Caps are constants of ``shared.ast.limits`` (D18) read at call time: a test that needs a short
  wall timeout patches ``WALL_TIMEOUT_S`` there (and in ``shared.ast.pool``'s namespace, should
  the pool have imported it by name); the real values are pinned separately.
* The pool sizes itself with ``worker_count`` (§4). Every test pins W = 1, the compose shape
  (``cpus: '1'``), by patching it, so spawn counts are exact on any machine.
* The breaker counts on the current ``AuditContext`` (D20; a module-level stub until plan task
  2.4). One audit is reset by ``clear_caches()``, which resets the process-default context (D20),
  together with ``reset_pool_for_tests()``, which ends the pool's workers and, until 2.4, the
  stub. The reset runs before and after every test.

Real workers and grammars throughout, except where a hook worker stands in for a broken one.
RED until ``shared.ast`` exists.
"""

from __future__ import annotations

import contextvars
import errno
import importlib
import importlib.util
import json
import os
import resource
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar, get_args

import pytest

import shared
from shared.ast import limits
from shared.ast import pool as pool_mod
from shared.ast.limits import (
    CIRCUIT_BREAK_AFTER,
    FRAME_CAP,
    MAX_DEPTH,
    MAX_NODES,
    RECYCLE_AFTER,
    WALL_TIMEOUT_S,
)
from shared.ast.pool import BOOTSTRAP, FallbackReason, WorkerPool, get_pool, reset_pool_for_tests
from shared.testing.timing import budget
from shared.tools.file_scanner import clear_caches
from tests.unit.ast._support import (
    SHARED_ROOT,
    TRIP_S,
    hook_command,
    isolated_python,
    new_audit,
    request_frames,
    wall_timeout,
    worker_env,
    workers_of,
)
from tests.unit.ast._support import one_audit as audit_on_one_worker

T = TypeVar("T")
Result = dict[str, Any] | str

_REAL_POPEN = subprocess.Popen

_PLAN_REASONS = frozenset(
    {
        "worker_crashed",
        "worker_error",
        "timeout",
        "ir_too_large",
        "too_deep",
        "bad_model",
        "spawn_failed",
        "circuit_open",
    }
)
_REASONS = frozenset(get_args(FallbackReason))

_JS = b"const a = 1;\n"
# Larger than any pipe buffer (64 KB on Linux), smaller than MAX_FILE_SIZE (512 KB).
_BIG_JS = b"// " + b"x" * (256 << 10) + b"\n"
_NESTED_OK = b"x = " + b"[" * (MAX_DEPTH // 2) + b"]" * (MAX_DEPTH // 2) + b";\n"
_TOO_DEEP = b"x = " + b"[" * (MAX_DEPTH + 16) + b"]" * (MAX_DEPTH + 16) + b";\n"
# Every `a;` is at least two nodes (an expression_statement and its identifier).
_TOO_MANY_NODES = b"a;" * (MAX_NODES // 2 + 1000)
_INVALID_UTF8 = b"\x00\xff\xfe const s = '\xc3\x28';\n// \xe2\x80\xa8 line separator\n"
_TRAVERSAL_JS = (
    b'const fs = require("fs");\n'
    b'app.get("/doc", (req, res) => {\n'
    b"  fs.readFile(req.query.file, (e, d) => res.send(d));\n"
    b"});\n"
)
_FAKE_KEY = "sk-test-0102-not-a-real-key"

_HANG_S = 1.0  # WALL_TIMEOUT_S patched for the single-timeout tests
_GRACE_S = 1.0  # plan 1.3: "timeout within WALL_TIMEOUT_S + 1"
_WEDGE_S = 120.0  # a call still running after this has wedged the pool
_SHORT_WEDGE_S = 10.0  # the same, for a test that patched WALL_TIMEOUT_S down to _HANG_S

# Variables a platform may add to a child's environment that the pool did not pass:
# PEP 538 locale coercion, and macOS CoreFoundation.
_PLATFORM_ENV = frozenset({"LC_CTYPE", "__CF_USER_TEXT_ENCODING"})
# Planted in the scanned tree. Each writes its module name to the marker file when imported.
_PLANTED = (
    "shared/__init__.py",
    "shared/ast/__init__.py",
    "shared/ast/_worker.py",
    "tree_sitter/__init__.py",
    "json.py",
    "struct.py",
)


@dataclass(frozen=True)
class _Spawn:
    cmd: list[str]
    kwargs: dict[str, Any]
    proc: subprocess.Popen[bytes]


@dataclass
class _Spawns:
    """Every worker process started during one test (``subprocess.Popen`` patched, plan 1.3)."""

    done: list[_Spawn] = field(default_factory=list)
    fail: int | None = None  # an errno: while set, every spawn raises it as Popen would

    def of(self, cmd: list[str]) -> list[subprocess.Popen[bytes]]:
        return [spawn.proc for spawn in self.done if spawn.cmd == cmd]

    def exits(self, cmd: list[str]) -> list[int | None]:
        return [proc.returncode for proc in self.of(cmd)]


def _recording_popen(record: _Spawns) -> type[subprocess.Popen[bytes]]:
    class _Recording(_REAL_POPEN):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            if record.fail is not None:
                raise OSError(record.fail, os.strerror(record.fail))
            super().__init__(*args, **kwargs)
            record.done.append(_Spawn(list(args[0] if args else kwargs["args"]), kwargs, self))

    return _Recording


def _kill(proc: subprocess.Popen[bytes]) -> None:
    """SIGKILL (if still running) and reap."""
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=10)


@pytest.fixture(autouse=True)
def spawns(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Spawns]:
    """Record every spawn; end any worker still running when the test is over."""
    record = _Spawns()
    monkeypatch.setattr(subprocess, "Popen", _recording_popen(record))
    yield record
    for spawn in record.done:
        _kill(spawn.proc)


@pytest.fixture(autouse=True)
def one_audit(spawns: _Spawns, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test is one audit on a W = 1 pool, the compose shape (§4). Per test, not per module
    (``conftest.py``'s ``real_pool``): spawn counts, hook workers and the breaker need a fresh
    pool and a fresh audit."""
    with audit_on_one_worker(monkeypatch):
        yield


def _run_into(ctx: contextvars.Context, call: Callable[[], Any], box: list[Any]) -> None:
    start = time.monotonic()
    try:
        value = ctx.run(call)
    except BaseException as exc:
        box.append(exc)
        return
    box.append((value, time.monotonic() - start))


def _timed(call: Callable[[], T], limit_s: float = _WEDGE_S) -> tuple[T, float]:
    """``call()`` and its duration, run on a daemon thread inside a copy of this context, as a
    skill thread runs (D20). Fails instead of wedging the suite when the call is still running
    after ``limit_s``, and when it raises: the pool never raises out of ``parse`` (plan 1.3)."""
    box: list[Any] = []
    worker = threading.Thread(
        target=_run_into, args=(contextvars.copy_context(), call, box), daemon=True
    )
    worker.start()
    worker.join(limit_s)
    assert box, f"still running after {limit_s:.0f}s: the pool wedged"
    assert not isinstance(box[0], BaseException), f"raised {box[0]!r} (parse never raises)"
    return box[0]


def _parse(
    pool: WorkerPool,
    data: bytes = _JS,
    language: str = "javascript",
    limit_s: float = _WEDGE_S,
) -> tuple[Result, float]:
    return _timed(lambda: pool.parse(language, data), limit_s)


def _parse_many(
    pool: WorkerPool, count: int, data: bytes = _JS, limit_s: float = _WEDGE_S
) -> list[Result]:
    results, _ = _timed(lambda: [pool.parse("javascript", data) for _ in range(count)], limit_s)
    return results


def _doc(data: bytes, language: str = "javascript") -> dict[str, Any]:
    """The identity fields a worker document carries for ``data`` (§6.2)."""
    return {"language": language, "size": len(data), "schema": 2}  # A28 (9)


def _shape(result: Result) -> Result:
    """``result``'s identity fields (§6.2), or the fallback reason itself."""
    if isinstance(result, str):
        return result
    return {key: result.get(key) for key in ("language", "size", "schema")}


def _read_exact(stream: Any, size: int) -> bytes:
    """``size`` bytes, or fewer if the stream ends first."""
    data = b""
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _send_probe(proc: subprocess.Popen[bytes], probe: str) -> bool:
    """One probe frame: a D3 header and an empty body. False if the worker is already gone."""
    assert proc.stdin is not None
    try:
        proc.stdin.write(request_frames({"id": 0, "probe": probe}, b""))
        proc.stdin.flush()
    except OSError:
        return False
    return True


def _ask(proc: subprocess.Popen[bytes], probe: str) -> dict[str, Any]:
    """The worker's one reply frame to ``probe``, or ``{"closed": ...}`` when it dies instead."""
    assert proc.stdout is not None
    head = _read_exact(proc.stdout, 4) if _send_probe(proc, probe) else b""
    if len(head) < 4:
        return {"closed": f"the worker exited ({proc.wait()}) instead of answering {probe!r}"}
    return json.loads(_read_exact(proc.stdout, struct.unpack(">I", head)[0]))


def _probe(cmd: list[str], kwargs: dict[str, Any], probe: str) -> dict[str, Any]:
    """Start a worker exactly as ``cmd``/``kwargs`` say and ask it ``probe``."""
    proc = _REAL_POPEN(cmd, **kwargs)
    try:
        reply, _ = _timed(lambda: _ask(proc, probe), limit_s=60)
    finally:
        _kill(proc)
    return reply


def _resolved(path: object) -> Path | None:
    return None if path is None else Path(str(path)).resolve()


def _parent_origins() -> dict[str, object]:
    """What the ``modules`` probe must answer: where THIS process resolves ``shared`` and
    ``tree_sitter`` (found, not imported: the parent side never imports tree_sitter)."""
    spec = importlib.util.find_spec("tree_sitter")
    origin = spec.origin if spec is not None else None
    return {"id": 0, "shared": _resolved(shared.__file__), "tree_sitter": _resolved(origin)}


def _origins(cmd: list[str], kwargs: dict[str, Any]) -> dict[str, object]:
    """The ``modules`` probe's answer, in the shape of ``_parent_origins`` (plus ``closed``
    when the worker died instead of answering)."""
    reply = _probe(cmd, kwargs, "modules")
    modules = reply.get("modules", {})
    names = {name: _resolved(modules.get(name)) for name in ("shared", "tree_sitter")}
    return {
        "id": reply.get("id"),
        **names,
        **({"closed": reply["closed"]} if "closed" in reply else {}),
    }


def _plant(tree: Path, marker: Path) -> None:
    body = f"open({str(marker)!r}, 'a').write(__name__ + '\\n')\n\n\ndef main():\n    pass\n"
    for relative in _PLANTED:
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def _private_dir_facts(cwd: object) -> dict[str, object]:
    if cwd is None:
        return {"cwd": None}
    path = Path(str(cwd))
    return {
        "is_dir": path.is_dir(),
        "is_the_agent_cwd": path.resolve() == Path.cwd().resolve(),
        "group_or_other_bits": stat.S_IMODE(path.stat().st_mode) & 0o077,
        "entries": sorted(os.listdir(path)),
    }


def _default_and_singleton() -> list[Result]:
    """One file through a fresh default pool, one through the process singleton (built here)."""
    return [WorkerPool().parse("javascript", _JS), get_pool().parse("javascript", _JS)]


def _each_pool_parses(pools: tuple[WorkerPool, ...], count: int) -> list[Result]:
    return [pool.parse("javascript", _JS) for pool in pools for _ in range(count)]


def _cwe22_rows(findings: list[dict[str, Any]]) -> list[tuple[str, int, bool]]:
    """(file name, line, carries ``validation.ast``) for each CWE-22 row."""
    return [
        (Path(f["file_path"]).name, f["line_start"], "ast" in (f.get("validation") or {}))
        for f in findings
        if f["category"] == "CWE-22"
    ]


def _sizes_in_parallel(pool: WorkerPool, payloads: list[bytes]) -> list[object]:
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda data: pool.parse("javascript", data), payloads))
    return [result["size"] if isinstance(result, dict) else result for result in results]


# --------------------------------------------------------------------------- surface and constants


def test_fallback_reasons_are_the_plan_set() -> None:
    """Each reason is its own §10.2 bucket. ``unsupported``, ``parse_error`` and ``too_large``
    are decided before the pool is asked (``test_0102_fallback.py`` pins the superset)."""
    assert _REASONS == _PLAN_REASONS


def test_pool_caps_are_the_lld_constants() -> None:
    """D2: wall timeout 10 s, recycle after 2,000 files; D10: breaker after 20; §8.7: 8 MB frames."""
    assert (WALL_TIMEOUT_S, RECYCLE_AFTER, CIRCUIT_BREAK_AFTER, FRAME_CAP) == (
        10,
        2000,
        20,
        8 << 20,
    )


def test_default_pool_returns_the_worker_document() -> None:
    result, _ = _parse(WorkerPool())
    assert _shape(result) == _doc(_JS)


def test_get_pool_is_one_pool_until_reset() -> None:
    first = get_pool()
    again = get_pool()
    reset_pool_for_tests()
    assert (again is first, get_pool() is first) == (True, False)


# --------------------------------------------------------------------------- faults: crash, hang, frames


def test_crash_is_worker_crashed_and_a_fresh_default_pool_succeeds(spawns: _Spawns) -> None:
    """T1: a worker that segfaults is a fallback for its file; the pool starts a new worker for
    the next file (two files, two processes, both reaped) and a fresh default pool parses."""
    crash = hook_command("crash.py")
    crashed = _parse_many(WorkerPool(cmd=crash), 2)
    fresh, _ = _parse(WorkerPool())
    observed = (crashed, spawns.exits(crash), _shape(fresh))
    assert observed == (["worker_crashed"] * 2, [-signal.SIGSEGV] * 2, _doc(_JS))


def test_hang_is_timeout_within_wall_timeout_plus_one(
    monkeypatch: pytest.MonkeyPatch, spawns: _Spawns
) -> None:
    """D2/T3: a hung worker is ``timeout`` after the wall timeout, not before and not later than
    one second after; it is SIGKILLed (hang.py ignores SIGTERM) and reaped."""
    wall_timeout(monkeypatch, _HANG_S)
    hang = hook_command("hang.py")
    result, waited = _parse(WorkerPool(cmd=hang), limit_s=_SHORT_WEDGE_S)
    observed = (result, _HANG_S * 0.95 <= waited < _HANG_S + _GRACE_S, spawns.exits(hang))
    assert observed == ("timeout", True, [-signal.SIGKILL]), f"waited {waited:.2f}s"


def test_worker_that_stops_reading_is_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2: the wall timeout is per FILE. hang.py never drains its stdin, so a file larger than a
    pipe buffer blocks the parent's write; that write is bounded by the same deadline."""
    wall_timeout(monkeypatch, _HANG_S)
    result, waited = _parse(WorkerPool(cmd=hook_command("hang.py")), _BIG_JS, limit_s=_SHORT_WEDGE_S)
    assert (result, waited < _HANG_S + _GRACE_S) == ("timeout", True), f"waited {waited:.2f}s"


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(("4096", "16"), id="eof-mid-body"),
        pytest.param(("prefix",), id="eof-mid-length"),
    ],
)
def test_half_frame_is_worker_crashed(spawns: _Spawns, argv: tuple[str, ...]) -> None:
    half = hook_command("half_frame.py", *argv)
    result, _ = _parse(WorkerPool(cmd=half))
    assert (result, [code is not None for code in spawns.exits(half)]) == ("worker_crashed", [True])


@pytest.mark.parametrize(
    "size",
    [pytest.param(16, id="not-json"), pytest.param(200_000, id="nested-past-the-recursion-limit")],
)
def test_complete_frame_that_is_not_a_document_is_bad_model(size: int) -> None:
    """D3: ``json.loads`` under ``except (ValueError, RecursionError, MemoryError)``."""
    result, _ = _parse(WorkerPool(cmd=hook_command("half_frame.py", str(size), str(size))))
    assert result == "bad_model"


@pytest.mark.parametrize("hook", ["half_frame.py", "stall_body.py"])
def test_frame_over_frame_cap_is_refused_from_its_length(
    monkeypatch: pytest.MonkeyPatch, spawns: _Spawns, hook: str
) -> None:
    """§8.7: a reply announced above ``FRAME_CAP`` is ``ir_too_large``, decided from the u32
    alone (stall_body never sends the rest), and the desynchronised worker is ended."""
    wall_timeout(monkeypatch, _HANG_S)
    cmd = hook_command(hook, str(FRAME_CAP + 1), "16")
    result, waited = _parse(WorkerPool(cmd=cmd), limit_s=_SHORT_WEDGE_S)
    observed = (result, waited < _HANG_S, [code is not None for code in spawns.exits(cmd)])
    assert observed == ("ir_too_large", True, [True]), f"waited {waited:.2f}s"


def test_stall_mid_body_is_timeout_and_the_worker_recycles(
    monkeypatch: pytest.MonkeyPatch, spawns: _Spawns
) -> None:
    """Plan 1.3: a valid length then silence mid-body (no bytes, no EOF) ends at the deadline,
    re-armed around every chunk, as ``timeout``; the worker is SIGKILLed and reaped and the next
    file gets a new process."""
    wall_timeout(monkeypatch, _HANG_S)
    stall = hook_command("stall_body.py")
    pool = WorkerPool(cmd=stall)
    first, waited = _parse(pool, limit_s=_SHORT_WEDGE_S)
    second, _ = _parse(pool, limit_s=_SHORT_WEDGE_S)
    observed = (first, second, waited < _HANG_S + _GRACE_S, spawns.exits(stall))
    assert observed == ("timeout", "timeout", True, [-signal.SIGKILL] * 2), f"waited {waited:.2f}s"


# --------------------------------------------------------------------------- spawn_failed


_UNEXECUTABLE: dict[str, Callable[[Path], object]] = {
    "missing": lambda path: None,
    "not-executable": lambda path: path.write_text("print('never runs')\n", encoding="utf-8"),
    "directory": Path.mkdir,
}


@pytest.mark.parametrize("kind", sorted(_UNEXECUTABLE))
def test_cannot_exec_is_spawn_failed(tmp_path: Path, kind: str) -> None:
    target = tmp_path / kind
    _UNEXECUTABLE[kind](target)
    result, _ = _parse(WorkerPool(cmd=[str(target)]))
    assert result == "spawn_failed"


@pytest.mark.parametrize(
    "err",
    [errno.EMFILE, errno.ENFILE, errno.EAGAIN, errno.ENOSPC, errno.ENOMEM],
    ids=errno.errorcode.get,
)
def test_popen_oserror_is_spawn_failed(spawns: _Spawns, err: int) -> None:
    """Plan 1.3: fd exhaustion across audits, the agent's own NPROC, a full disk: the default
    pool and the singleton both answer ``spawn_failed``."""
    spawns.fail = err
    results, _ = _timed(_default_and_singleton)
    assert results == ["spawn_failed"] * 2


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes through a read-only mode")
def test_readonly_tmpdir_for_the_private_cwd_is_spawn_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Plan 1.3 ``readonly_cwd``: no writable temp directory for the private cwd."""
    readonly = tmp_path / "readonly-tmp"
    readonly.mkdir(mode=0o500)
    monkeypatch.setattr(tempfile, "tempdir", str(readonly))
    reset_pool_for_tests()
    results, _ = _timed(_default_and_singleton)
    assert results == ["spawn_failed"] * 2


def test_spawn_failed_file_still_gets_its_regex_rows(tmp_path: Path, spawns: _Spawns) -> None:
    """Plan 1.3: with no worker able to start, the audit completes and the file keeps the rows
    of the regex tier, which owns every file the AST tier cannot model (D10, D12)."""
    from cwe_agent.skills.input_validation_check import check_input_validation

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "doc.js").write_bytes(_TRAVERSAL_JS)
    spawns.fail = errno.EMFILE
    report, _ = _timed(lambda: check_input_validation(str(tree)))
    assert _cwe22_rows(report["findings"]) == [("doc.js", 3, False)]


def test_worker_reaped_between_parses_never_raises(spawns: _Spawns) -> None:
    """Plan 1.3: the OOM-killer reaps the worker between two files; shipping the next file meets
    EPIPE, which is ``spawn_failed`` (or a model, should the pool see the death and respawn
    first). The file after that is parsed."""
    pool = WorkerPool()
    first, _ = _parse(pool)
    _kill(spawns.done[0].proc)
    shipped, _ = _parse(pool, _BIG_JS)
    after, _ = _parse(pool)
    observed = (_shape(first), _shape(shipped) in ("spawn_failed", _doc(_BIG_JS)), _shape(after))
    assert observed == (_doc(_JS), True, _doc(_JS)), _shape(shipped)


def test_failed_respawn_after_recycle_is_spawn_failed(spawns: _Spawns) -> None:
    """Plan 1.3: the replacement of a recycled worker cannot start. The file the old worker
    served keeps its model; the next file is ``spawn_failed``; the pool recovers after."""
    pool = WorkerPool()
    warm = _parse_many(pool, RECYCLE_AFTER - 1)
    spawns.fail = errno.EAGAIN
    served, refused = _parse_many(pool, 2)
    spawns.fail = None
    recovered, _ = _parse(pool)
    observed = ({_shape(r) == _doc(_JS) for r in warm}, _shape(served), refused, _shape(recovered))
    assert observed == ({True}, _doc(_JS), "spawn_failed", _doc(_JS))


# --------------------------------------------------------------------------- isolation (D2, T4, T12)


def test_spawn_command_env_cwd_and_streams(
    monkeypatch: pytest.MonkeyPatch, spawns: _Spawns
) -> None:
    """D2 as the parent spawns it: the bootstrap under ``-I``, an env of exactly PATH and LANG
    (no key, no PYTHONPATH), a private empty cwd, pipes for the frames, and a stderr that is
    DEVNULL or a drained pipe, never a regular file."""
    monkeypatch.setenv("OPENAI_API_KEY", _FAKE_KEY)
    monkeypatch.setenv("PYTHONPATH", "/hostile/pythonpath")
    monkeypatch.setenv("VULTURE_JWT_SECRET", "hostile-jwt-secret")
    result, _ = _parse(WorkerPool())
    (spawn,) = spawns.done
    observed = {
        "model": _shape(result) == _doc(_JS),
        "cmd": spawn.cmd,
        "env": spawn.kwargs.get("env"),
        "pipes": (spawn.kwargs.get("stdin"), spawn.kwargs.get("stdout")),
        "stderr": spawn.kwargs.get("stderr") in (subprocess.DEVNULL, subprocess.PIPE),
        "cwd": _private_dir_facts(spawn.kwargs.get("cwd")),
    }
    assert observed == {
        "model": True,
        "cmd": [sys.executable, "-I", "-c", BOOTSTRAP],
        "env": worker_env(),
        "pipes": (subprocess.PIPE, subprocess.PIPE),
        "stderr": True,
        "cwd": {"is_dir": True, "is_the_agent_cwd": False, "group_or_other_bits": 0, "entries": []},
    }


@pytest.fixture
def stderr_is_a_log_file(tmp_path: Path) -> Iterator[Path]:
    """The agent's fd 2 is a regular file, as under a native launcher that logs agent stderr."""
    log = tmp_path / "agent-stderr.log"
    saved = os.dup(2)
    with log.open("wb") as fp:
        os.dup2(fp.fileno(), 2)
    try:
        yield log
    finally:
        os.dup2(saved, 2)
        os.close(saved)


@pytest.mark.usefixtures("stderr_is_a_log_file")
def test_stderr_write_after_rlimits_still_yields_a_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spawns: _Spawns
) -> None:
    """Plan 1.3: a worker that writes to stderr after ``RLIMIT_FSIZE = 0`` still yields a model,
    because its stderr is not the agent's regular-file stderr. report_path.py also records, from
    inside the child, the isolation the pool gave it: ``-I``, the env, the private empty cwd."""
    monkeypatch.setenv("OPENAI_API_KEY", _FAKE_KEY)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    report = tmp_path / "spawn_report.json"
    result, _ = _parse(WorkerPool(cmd=hook_command("report_path.py", str(report), BOOTSTRAP)))
    seen = json.loads(report.read_text(encoding="utf-8"))
    observed = {
        "model": _shape(result) == _doc(_JS),
        "stderr_regular": seen["stderr_regular"],
        "isolated": seen["isolated"],
        "env": sorted(set(seen["env"]) - _PLATFORM_ENV),
        "cwd": Path(seen["cwd"]).resolve() == Path(spawns.done[0].kwargs["cwd"]).resolve(),
        "cwd_entries": seen["cwd_entries"],
    }
    assert observed == {
        "model": True,
        "stderr_regular": False,
        "isolated": 1,
        "env": ["LANG", "PATH"],
        "cwd": True,
        "cwd_entries": [],
    }


def test_planted_module_not_imported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spawns: _Spawns
) -> None:
    """Review focus 2 / T12: the scanned tree plants ``shared/ast/_worker.py``,
    ``tree_sitter/__init__.py`` and stdlib shadows, the agent's cwd IS that tree and its
    PYTHONPATH points there. The real pool still parses, and the ``modules`` probe answers with
    the parent's own ``shared`` and the installed ``tree_sitter`` — both from the pool's own
    spawn and from the same command started with the tree as cwd and PYTHONPATH (``-I`` and the
    bootstrap's explicit ``sys.path``, not the private cwd alone). No planted module ran."""
    tree, marker = tmp_path / "scanned", tmp_path / "hijacked.log"
    _plant(tree, marker)
    expected = _parent_origins()
    monkeypatch.chdir(tree)
    monkeypatch.setenv("PYTHONPATH", str(tree))
    result, _ = _parse(get_pool())
    (spawn,) = spawns.done
    in_the_tree = {**spawn.kwargs, "cwd": str(tree), "env": dict(os.environ)}
    observed = {
        "model": _shape(result) == _doc(_JS),
        "pool_spawn": _origins(spawn.cmd, spawn.kwargs),
        "cwd_and_pythonpath_in_the_tree": _origins(spawn.cmd, in_the_tree),
        "planted_modules_run": marker.read_text(encoding="utf-8") if marker.exists() else "",
    }
    assert observed == {
        "model": True,
        "pool_spawn": expected,
        "cwd_and_pythonpath_in_the_tree": expected,
        "planted_modules_run": "",
    }


def test_worker_sets_nproc_and_fsize_to_zero(spawns: _Spawns) -> None:
    """D2 on every platform (darwin included): ``RLIMIT_NPROC = RLIMIT_FSIZE = 0``, soft and
    hard, so a compromised worker can neither fork nor write a file, nor raise either limit."""
    result, _ = _parse(get_pool())
    (spawn,) = spawns.done
    reply = _probe(spawn.cmd, spawn.kwargs, "rlimits")
    reported = reply.get("rlimits", {})
    observed = (
        _shape(result),
        reply.get("id"),
        reported.get("RLIMIT_NPROC"),
        reported.get("RLIMIT_FSIZE"),
    )
    assert observed == (_doc(_JS), 0, [0, 0], [0, 0]), reply


# D2, Linux: name -> (soft, hard). hard None: any finite value at or above soft (risk 14 lets
# RLIMIT_CPU signal SIGXCPU before its hard limit kills).
_LINUX_RLIMITS = {
    "RLIMIT_AS": (256 << 20, 256 << 20),
    "RLIMIT_CPU": (30, None),
    "RLIMIT_NPROC": (0, 0),
    "RLIMIT_FSIZE": (0, 0),
}


@pytest.mark.skipif(not hasattr(resource, "prlimit"), reason="prlimit (Linux) reads another pid")
@pytest.mark.parametrize("name", sorted(_LINUX_RLIMITS))
def test_linux_worker_rlimits_seen_from_outside(spawns: _Spawns, name: str) -> None:
    result, _ = _parse(get_pool())
    soft, hard = _LINUX_RLIMITS[name]
    got = resource.prlimit(spawns.done[0].proc.pid, getattr(resource, name))
    want = (soft, hard if hard is not None else max(got[1], soft))
    assert (_shape(result), got, got[1] != resource.RLIM_INFINITY) == (_doc(_JS), want, True)


@pytest.mark.skipif(not hasattr(resource, "prlimit"), reason="prlimit (Linux) reads another pid")
def test_linux_worker_cpu_hard_limit_sits_above_its_soft_limit(spawns: _Spawns) -> None:
    """Risk 14: Linux checks RLIMIT_CPU's HARD limit first, so a worker whose soft and hard
    limits were equal would end by SIGKILL — a crash the breaker counts — instead of the
    SIGXCPU lifecycle exit it ignores. The hard limit must sit above the soft one."""
    result, _ = _parse(get_pool())
    soft, hard = resource.prlimit(spawns.done[0].proc.pid, resource.RLIMIT_CPU)
    assert (_shape(result), soft, hard > soft) == (_doc(_JS), limits.WORKER_CPU_S, True)


_SPIN_CPU = (
    "import resource, sys\n"
    f"sys.path.insert(0, {str(SHARED_ROOT)!r})\n"
    "from shared.ast._worker import _set_limit\n"
    "_set_limit(resource.RLIMIT_CORE, 0, 0)\n"
    "_set_limit(resource.RLIMIT_CPU, 1, 2)\n"
    "while True:\n"
    "    pass\n"
)


@pytest.mark.skipif(not hasattr(signal, "SIGXCPU"), reason="SIGXCPU is POSIX")
def test_a_spent_cpu_limit_ends_the_worker_with_sigxcpu(tmp_path: Path) -> None:
    """Risk 14, end to end: a process limited by the worker's own ``_set_limit`` (soft 1 s,
    hard 2 s here) that burns its CPU budget exits by SIGXCPU — the exit ``breaker_fault``
    excludes — not by SIGKILL. (A real worker's 30 s budget is the same mechanism.)"""
    with isolated_python(_SPIN_CPU, tmp_path, stderr=subprocess.DEVNULL) as proc:
        try:
            code = proc.wait(timeout=budget(30.0))
        except subprocess.TimeoutExpired:
            proc.kill()
            code = None
    assert code == -signal.SIGXCPU


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_NO_NEW_PRIVS is Linux")
def test_linux_worker_sets_no_new_privs(spawns: _Spawns) -> None:
    result, _ = _parse(get_pool())
    status = Path(f"/proc/{spawns.done[0].proc.pid}/status").read_text(encoding="utf-8")
    assert (_shape(result), "NoNewPrivs:\t1" in status.splitlines()) == (_doc(_JS), True)


def test_bootstrap_is_d2s_command() -> None:
    """D2: the bootstrap puts exactly the parent's own ``shared`` root on the worker's path,
    then runs the worker's ``main`` — the one command every worker (and the wire suite) runs."""
    root = Path(shared.__file__).resolve().parent.parent
    expected = f"import sys; sys.path.insert(0, {str(root)!r}); from shared.ast._worker import main; main()"
    assert (pool_mod.SHARED_ROOT, BOOTSTRAP) == (str(root), expected)


# --------------------------------------------------------------------------- inputs


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        pytest.param(b"", _doc(b""), id="empty"),
        pytest.param(_INVALID_UTF8, _doc(_INVALID_UTF8), id="nul-invalid-utf8-u2028"),
        pytest.param(_NESTED_OK, _doc(_NESTED_OK), id="nested-within-max-depth"),
        pytest.param(_TOO_DEEP, "too_deep", id="nested-past-max-depth"),
        pytest.param(_TOO_MANY_NODES, "ir_too_large", id="more-nodes-than-max-nodes"),
    ],
)
def test_hostile_file_is_a_model_or_its_reason(data: bytes, expected: Result) -> None:
    result, _ = _parse(WorkerPool(), data)
    assert _shape(result) == expected


def test_syntax_error_is_a_model_with_error_nodes() -> None:
    """``parse_error`` is decided in ``get_model``/``owns`` from ``error_nodes``, never by the
    pool (plan 1.3): a file with a syntax error is a model."""
    data = b"def f(:\n    pass\n"
    result, _ = _parse(WorkerPool(), data, "python")
    errors = result.get("error_nodes") if isinstance(result, dict) else result
    assert (_shape(result), isinstance(errors, int) and errors > 0) == (_doc(data, "python"), True)


@pytest.mark.parametrize(
    ("language", "data"),
    [
        pytest.param("cobol", b"DISPLAY 'X'.\n", id="language-without-a-profile"),
        pytest.param("../../etc/passwd", b"x\n", id="path-shaped-language"),
        pytest.param("javascript", b"a" * (FRAME_CAP + 1), id="file-larger-than-a-frame"),
    ],
)
def test_unexpected_input_never_raises(language: str, data: bytes) -> None:
    result, _ = _parse(WorkerPool(), data, language)
    assert isinstance(result, dict) or result in _REASONS, result


# --------------------------------------------------------------------------- recycling and sharing (§4)


def test_recycle_after(spawns: _Spawns) -> None:
    """D2: one worker serves ``RECYCLE_AFTER`` files (the real constant); the next file is served
    by a new process and the old one is reaped."""
    pool = WorkerPool()
    warm = _parse_many(pool, RECYCLE_AFTER - 1)
    before = len(spawns.done)
    served = _parse_many(pool, 2)
    observed = {
        "every_file_a_model": {_shape(r) == _doc(_JS) for r in warm + served},
        "processes_after_recycle_after_minus_one": before,
        "processes_after_recycle_after_plus_one": len(spawns.done),
        "first_reaped": spawns.done[0].proc.returncode is not None,
    }
    assert observed == {
        "every_file_a_model": {True},
        "processes_after_recycle_after_minus_one": 1,
        "processes_after_recycle_after_plus_one": 2,
        "first_reaped": True,
    }


def test_concurrent_requests_one_worker_no_crosstalk(spawns: _Spawns) -> None:
    """§4: eight concurrent audits share the W = 1 worker FIFO; each caller gets the document of
    its own file (distinct sizes), and only one worker is started."""
    payloads = [b"const v = %d;\n" % i * (i + 1) for i in range(32)]
    sizes, _ = _timed(lambda: _sizes_in_parallel(WorkerPool(), payloads))
    assert (sizes, len(spawns.done)) == ([len(p) for p in payloads], 1)


def test_pool_never_exceeds_worker_count(monkeypatch: pytest.MonkeyPatch, spawns: _Spawns) -> None:
    monkeypatch.setattr(pool_mod, "worker_count", workers_of(2))
    sizes, _ = _timed(lambda: _sizes_in_parallel(WorkerPool(), [_JS] * 32))
    assert (sizes, len(spawns.done) <= 2) == ([len(_JS)] * 32, True)


def test_pool_survives_clear_caches(spawns: _Spawns) -> None:
    """``clear_caches()`` runs at every audit start (D20); it resets caches and the default
    context, never the workers: the same pool, the same live process, no respawn."""
    pool = get_pool()
    before, _ = _parse(pool)
    clear_caches()
    after, _ = _parse(get_pool())
    observed = (get_pool() is pool, _shape(before), _shape(after), len(spawns.done))
    assert observed == (True, _doc(_JS), _doc(_JS), 1)
    assert spawns.done[0].proc.poll() is None, "clear_caches() ended the worker"


# --------------------------------------------------------------------------- circuit breaker (D10)


def test_circuit_breaker(monkeypatch: pytest.MonkeyPatch, spawns: _Spawns) -> None:
    """Review focus 5 / T13: twenty files that each hang the worker, in one audit. The next file,
    and every file after it, on this pool and on every other pool of the audit, is
    ``circuit_open`` at once, with no worker started; the audit finishes. The next audit starts
    with the breaker closed."""
    wall_timeout(monkeypatch, TRIP_S)
    hang = hook_command("hang.py")
    pools = (WorkerPool(cmd=hang), WorkerPool(), get_pool())
    timeouts = _parse_many(pools[0], CIRCUIT_BREAK_AFTER, limit_s=_SHORT_WEDGE_S * 4)
    started = len(spawns.done)
    rest, waited = _timed(lambda: _each_pool_parses(pools, 50))
    observed = {
        "first_twenty": timeouts,
        "rest": rest,
        "waited_less_than_one_timeout": waited < TRIP_S,
        "started_after_the_trip": len(spawns.done) - started,
        "hung_workers": set(spawns.exits(hang)),
    }
    assert observed == {
        "first_twenty": ["timeout"] * CIRCUIT_BREAK_AFTER,
        "rest": ["circuit_open"] * 150,
        "waited_less_than_one_timeout": True,
        "started_after_the_trip": 0,
        "hung_workers": {-signal.SIGKILL},
    }
    new_audit()
    next_audit, _ = _parse(WorkerPool())
    assert _shape(next_audit) == _doc(_JS), "the next audit must start with the breaker closed"


def test_circuit_breaker_counts_crashes(spawns: _Spawns) -> None:
    """D10: timeouts AND crashes advance the breaker."""
    pool = WorkerPool(cmd=hook_command("crash.py"))
    crashed = _parse_many(pool, CIRCUIT_BREAK_AFTER)
    started = len(spawns.done)
    tripped = _parse_many(pool, 1)
    observed = (crashed, tripped, len(spawns.done) - started)
    assert observed == (["worker_crashed"] * CIRCUIT_BREAK_AFTER, ["circuit_open"], 0)


def test_clear_caches_starts_the_next_audit_with_the_breaker_closed(spawns: _Spawns) -> None:
    """D10/D20: the breaker bounds ONE audit. The reset an agent runs at every audit start is
    ``clear_caches()`` (never ``reset_pool_for_tests()``), and it closes the breaker again
    for a process that has loaded the layer."""
    importlib.import_module("shared.ast.cache")  # the layer is loaded, as in an agent that parsed
    tripped = _parse_many(WorkerPool(cmd=hook_command("crash.py")), CIRCUIT_BREAK_AFTER + 1)
    clear_caches()
    after, _ = _parse(WorkerPool())
    assert (tripped[-1], _shape(after)) == ("circuit_open", _doc(_JS))


def test_breaker_ignores_per_file_errors() -> None:
    """D10 counts timeouts and crashes only: a healthy worker answering ``too_deep`` for 21
    files in a row trips nothing."""
    pool = WorkerPool()
    deep = _parse_many(pool, CIRCUIT_BREAK_AFTER + 1, _TOO_DEEP)
    after, _ = _parse(pool)
    assert (deep, _shape(after)) == (["too_deep"] * (CIRCUIT_BREAK_AFTER + 1), _doc(_JS))


def test_rlimit_cpu_exit_does_not_advance_breaker(spawns: _Spawns) -> None:
    """Risk 14: a SIGXCPU exit is a lifecycle exit. Its file falls back, the breaker does not
    count it, so 25 of them leave the audit's breaker closed."""
    xcpu = hook_command("crash.py", "XCPU")
    exits = _parse_many(WorkerPool(cmd=xcpu), CIRCUIT_BREAK_AFTER + 5)
    after, _ = _parse(WorkerPool())
    observed = (
        "circuit_open" in exits,
        set(exits) <= _REASONS,
        set(spawns.exits(xcpu)),
        _shape(after),
    )
    assert observed == (False, True, {-signal.SIGXCPU}, _doc(_JS))
