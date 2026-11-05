"""Feature 0102, plan task 1.3 — how many workers the pool runs (LLD §4, D2, D18; feature 0103 §3).

``W = clamp(1, min(cpu_quota, floor((limit - rss_now - cache_budget) / WORKER_RESERVE)),
MAX_WORKERS)`` with ``WORKER_RESERVE = 192 MB`` and ``MAX_WORKERS = 4``. ``cache_budget`` is
BOTH same-process content caches: the model cache, ``min(128 MB, 25 % of the limit)`` (D5), and
the read cache, ``clamp(64 MB, limit // 4, 256 MB)`` (feature 0103 D2) — 384 MB at a 1 GB limit,
so the free-RAM estimate is not 256 MB optimistic. Pinned here:

* **``worker_count``.** The plan's three cases (one CPU and 1 GB is one worker; eight CPUs and
  4 GB is ``MAX_WORKERS``; half a CPU is one worker), cases where only the memory term binds,
  which tell "both caches reserved" (3) from "only the model cache" (4) and from "no cache" (4),
  and starved inputs (RSS above the limit) that still yield one worker. Over a grid of hostile
  inputs W is an ``int``, never below 1, never above ``MAX_WORKERS``, and never above the CPU
  quota unless forced up to the floor of 1.
* **``Limits.read()``** is built on ``shared.tools.membudget`` (feature 0103: the one reader of
  deployment limits) and reads the cgroup files under the ``root`` it is given. ``cpu.max = "max
  100000"`` and ``memory.max = "max"`` (no cgroup limit) fall back to ``os.cpu_count()`` and to
  the next source of 0103's chain: a finite ``RLIMIT_AS``, else physical RAM. The kernel's
  trailing newline is part of every file written here.

RED until ``shared.ast`` exists.
"""

from __future__ import annotations

import itertools
import os
import resource
from pathlib import Path

import pytest

from shared.ast.limits import MAX_WORKERS, WORKER_RESERVE
from shared.ast.pool import Limits, worker_count
from shared.tools import membudget

_MIB = 1 << 20
_GIB = 1 << 30


def _limits(cpu: float, memory: int, rss: int) -> Limits:
    return Limits(cpu_quota=cpu, memory_limit=memory, rss_now=rss)


def _cgroup(root: Path, cpu_max: str | None, memory_max: str | None) -> Path:
    """A cgroup v2 directory holding the given ``cpu.max`` / ``memory.max`` (None: absent)."""
    files = {"cpu.max": cpu_max, "memory.max": memory_max}
    for name, content in files.items():
        if content is not None:
            (root / name).write_text(content, encoding="utf-8")
    return root


def _uncgrouped_memory() -> int:
    """Feature 0103's chain past cgroup v2 and v1: a finite RLIMIT_AS, else physical RAM."""
    soft = resource.getrlimit(resource.RLIMIT_AS)[0]
    if soft != resource.RLIM_INFINITY:
        return soft
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")


def test_worker_constants() -> None:
    assert (WORKER_RESERVE, MAX_WORKERS) == (192 * _MIB, 4)


@pytest.mark.parametrize(
    ("cpu", "memory", "rss", "expected"),
    [
        pytest.param(1, _GIB, 400 * _MIB, 1, id="compose-shape"),
        pytest.param(8, 4 * _GIB, 400 * _MIB, 4, id="capped-at-max-workers"),
        pytest.param(0.5, 4 * _GIB, 400 * _MIB, 1, id="half-a-cpu-is-one"),
        pytest.param(8, _GIB, 0, 3, id="both-content-caches-reserved"),
        pytest.param(8, _GIB, 200 * _MIB, 2, id="rss-reserved"),
        pytest.param(8, _GIB, 300 * _MIB, 1, id="memory-binds-at-one"),
        pytest.param(2.5, 4 * _GIB, 400 * _MIB, 2, id="fractional-quota-never-oversubscribed"),
        pytest.param(8, 256 * _MIB, 400 * _MIB, 1, id="rss-above-limit-is-still-one"),
        pytest.param(64, 1 << 40, 0, 4, id="huge-box-capped"),
    ],
)
def test_worker_count(cpu: float, memory: int, rss: int, expected: int) -> None:
    count = worker_count(_limits(cpu, memory, rss))
    assert (type(count), count) == (int, expected)


@pytest.mark.parametrize(
    ("cpu", "memory", "rss"),
    list(
        itertools.product(
            (0.01, 0.5, 1, 1.5, 3, 7.9, 512),
            (1, 64 * _MIB, 512 * _MIB, _GIB, 16 * _GIB, 1 << 44),
            (0, 400 * _MIB, 2 * _GIB),
        )
    ),
)
def test_worker_count_bounds(cpu: float, memory: int, rss: int) -> None:
    count = worker_count(_limits(cpu, memory, rss))
    assert (type(count), 1 <= count <= MAX_WORKERS, count <= max(1, cpu)) == (int, True, True)


def test_limits_read_without_cgroup_limits_falls_back(tmp_path: Path) -> None:
    """Plan 1.3: ``cpu.max = "max 100000"``, ``memory.max = "max"``."""
    limits = Limits.read(root=_cgroup(tmp_path, "max 100000\n", "max\n"))
    observed = (limits.cpu_quota, limits.memory_limit)
    assert observed == (os.cpu_count(), _uncgrouped_memory())


def test_limits_read_without_cgroup_files_falls_back(tmp_path: Path) -> None:
    limits = Limits.read(root=tmp_path)
    assert (limits.cpu_quota, limits.memory_limit) == (os.cpu_count(), _uncgrouped_memory())


@pytest.mark.parametrize(
    ("cpu_max", "memory_max", "expected"),
    [
        pytest.param("200000 100000\n", "536870912\n", (2.0, 512 * _MIB), id="two-cpus-512m"),
        pytest.param("50000 100000\n", "1073741824\n", (0.5, _GIB), id="half-cpu-1g"),
    ],
)
def test_limits_read_cgroup_v2(
    tmp_path: Path, cpu_max: str, memory_max: str, expected: tuple[float, int]
) -> None:
    limits = Limits.read(root=_cgroup(tmp_path, cpu_max, memory_max))
    assert (limits.cpu_quota, limits.memory_limit) == expected


@pytest.mark.parametrize(
    ("cpu_max", "memory_max"),
    [
        pytest.param("max 100000\n", "max\n", id="unlimited"),
        pytest.param("150000 100000\n", "805306368\n", id="limited"),
        pytest.param(None, None, id="absent"),
    ],
)
def test_limits_read_is_membudget(
    tmp_path: Path, cpu_max: str | None, memory_max: str | None
) -> None:
    """Feature 0103 D9: membudget is the one reader of deployment limits; Limits.read() agrees
    with it on every cgroup shape instead of parsing the files a second time."""
    root = _cgroup(tmp_path, cpu_max, memory_max)
    limits = Limits.read(root=root)
    observed = (limits.cpu_quota, limits.memory_limit)
    assert observed == (
        membudget.cpu_quota(root=root),
        membudget.deployment_memory_limit(root=root),
    )


def test_limits_read_measures_this_process(tmp_path: Path) -> None:
    """``rss_now`` is this agent process's resident size in bytes: positive, below the limit."""
    limits = Limits.read(root=tmp_path)
    observed = (type(limits.rss_now), 0 < limits.rss_now < limits.memory_limit)
    assert observed == (int, True), limits


def test_worker_count_of_limits_read_is_in_bounds(tmp_path: Path) -> None:
    count = worker_count(Limits.read(root=_cgroup(tmp_path, "max 100000\n", "max\n")))
    assert (type(count), 1 <= count <= MAX_WORKERS) == (int, True)
