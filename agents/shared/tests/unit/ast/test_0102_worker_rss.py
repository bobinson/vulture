"""Feature 0102, A43 (5) — a parse worker grown past A5's resident bound is recycled.

LLD A5 bounds one parse worker's resident high-water (``VmHWM``) by
``limits.MAX_WORKER_RSS_MB`` (48 MB since A44 (4); a healthy worker holding all nine grammars
measures 34.4 MB). A43 (5): after a request, a worker whose high-water exceeds it is recycled
the way a worker past ``RECYCLE_AFTER`` files is (D2). The slot ends it, the next file starts a new process, and the
audit counts it (§10.2 ``workers.recycled``). The high-water is read from
``/proc/<pid>/status`` on Linux and skipped elsewhere; there is no flag (CLAUDE.md rule 6).

Pinned here, through real workers on a W = 1 pool (the compose shape, §4):

* the ``ast_v1`` depth bomb (``cwe_22_19_bomb.js``, 200,000-deep nesting under 512 KB) is
  still ``too_deep`` for its own file, and its worker (about 65 MB at its high-water) is
  recycled: the next file is served by a second process and the first one is reaped;
* a normal file (``cwe_22_1.js``) keeps its worker: one process serves it and the next file;
* with the off-Linux reader, which reads nothing, the bomb keeps its worker. The RSS check is
  the only thing that recycled it above, and where it cannot read it is skipped;
* the Linux reader returns a live worker's ``VmHWM`` row, within the bound for a normal file,
  and 0 once the process is gone.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from shared.ast import pool as pool_mod
from shared.ast.context import current
from shared.ast.limits import MAX_WORKER_RSS_MB
from shared.ast.pool import get_pool, reset_pool_for_tests
from tests.unit.ast._support import AST_V1, one_audit

_BOMB = AST_V1 / "cwe_22_19_bomb.js"
_NORMAL = AST_V1 / "cwe_22_1.js"
_LINUX = sys.platform.startswith("linux")
_ON_LINUX = pytest.mark.skipif(not _LINUX, reason="the high-water is read from /proc (Linux)")

type Started = list[subprocess.Popen[bytes]]


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> Iterator[Started]:
    """One audit on a fresh W = 1 pool, and every worker process that pool starts, in order."""
    procs: Started = []
    spawn = pool_mod._Worker.spawn

    def recording(cmd: list[str]) -> Any:
        worker = spawn(cmd)
        if worker is not None:
            procs.append(worker.proc)
        return worker

    monkeypatch.setattr(pool_mod._Worker, "spawn", staticmethod(recording))
    with one_audit(monkeypatch):
        yield procs


def _answer(path: Path) -> str:
    """``path`` through the process pool: ``"model"``, or the reason it fell back."""
    result = get_pool().parse("javascript", path.read_bytes())
    return result if isinstance(result, str) else "model"


def _served(first: Path, procs: Started) -> dict[str, object]:
    """``first`` and then the normal file through the pool: each answer, the worker processes
    started, which of them still run, and the audit's ``workers.recycled``."""
    answers = [_answer(first), _answer(_NORMAL)]
    return {
        "answers": answers,
        "workers": len(procs),
        "running": [proc.poll() is None for proc in procs],
        "recycled": current().coverage.snapshot(AST_V1)["workers"]["recycled"],
    }


def _status_kb(pid: int) -> int:
    """``pid``'s ``VmHWM`` in kB, read independently of the pool's reader."""
    status = Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
    (row,) = [line.split() for line in status if line.startswith("VmHWM:")]
    return int(row[1])


@_ON_LINUX
def test_the_depth_bomb_recycles_its_worker(started: Started) -> None:
    assert _served(_BOMB, started) == {
        "answers": ["too_deep", "model"],
        "workers": 2,
        "running": [False, True],
        "recycled": 1,
    }


def test_a_normal_file_keeps_its_worker(started: Started) -> None:
    assert _served(_NORMAL, started) == {
        "answers": ["model", "model"],
        "workers": 1,
        "running": [True],
        "recycled": 0,
    }


def test_without_a_readable_high_water_the_bomb_keeps_its_worker(
    started: Started, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Off Linux the pool reads no high-water (``_no_high_water_kb``): the check is skipped."""
    monkeypatch.setattr(pool_mod, "_high_water_kb", pool_mod._no_high_water_kb)
    assert _served(_BOMB, started) == {
        "answers": ["too_deep", "model"],
        "workers": 1,
        "running": [True],
        "recycled": 0,
    }


@_ON_LINUX
def test_the_linux_reader_reads_vmhwm_and_nothing_once_the_worker_is_gone(
    started: Started,
) -> None:
    """A normal file leaves its idle worker's high-water inside the bound, as ``/proc`` shows
    it; once the worker is ended and reaped, the reader returns 0."""
    _answer(_NORMAL)
    (proc,) = started
    live = pool_mod._proc_high_water_kb(proc.pid)
    independent = _status_kb(proc.pid)
    reset_pool_for_tests()
    observed = (live == independent, 0 < live <= MAX_WORKER_RSS_MB * 1024)
    assert (*observed, pool_mod._proc_high_water_kb(proc.pid)) == (True, True, 0)
