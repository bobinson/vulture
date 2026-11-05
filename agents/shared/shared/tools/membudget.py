"""The deployment's memory and CPU limits, read once from the platform (feature 0103, D9).

The one reader of deployment limits: the scanner's read cache (feature 0103) and the AST
layer's worker count and model cache (feature 0102) size themselves from these values, so the
two cannot disagree about how much memory the agent has.

Precedence, first source that yields a finite positive value:

* memory: cgroup v2 ``memory.max`` -> cgroup v1 ``memory/memory.limit_in_bytes`` -> a finite
  ``RLIMIT_AS`` -> physical RAM (``sysconf``) -> 1 GB. ``"max"`` (v2) and the near-2**63 value
  v1 reports for "unlimited" both mean "no cgroup limit", never a limit;
* CPU: cgroup v2 ``cpu.max`` ``"<quota> <period>"`` as ``quota / period``; ``"max"`` or an
  absent file -> ``os.cpu_count()``.

Each reader takes the cgroup ``root`` so tests stub the files, and reads it ONCE per root:
the limits are platform facts, and every component that sizes itself from them sees the same
values. ``rss_now`` and ``peak_rss`` are this process's own resident size, now and at its
peak, for the components that budget against the limit. Nothing here reads the environment
(CLAUDE.md rule 6). A leaf: it imports ``functools``, ``os``, ``resource``, ``sys`` and
``pathlib`` only.
"""

from __future__ import annotations

import functools
import os
import resource
import sys
from pathlib import Path

__all__ = [
    "CGROUP_ROOT",
    "clamp",
    "cpu_quota",
    "deployment_memory_limit",
    "peak_rss",
    "read_cache_budget",
    "rss_now",
]

_MIB = 1 << 20

CGROUP_ROOT = Path("/sys/fs/cgroup")
FALLBACK_MEMORY = 1024 * _MIB  # the limit assumed when no source yields one
# cgroup v1 reports "unlimited" as PAGE_COUNTER_MAX pages (about 2**63): no real limit is this big.
_V1_UNLIMITED = 1 << 60
_STATM = Path("/proc/self/statm")  # Linux: "<size> <resident> ..." in pages
_MAXRSS_UNIT = 1 if sys.platform == "darwin" else 1024  # ru_maxrss: bytes on macOS, else KiB

# 0103 D2: the read cache gets a quarter of the limit, never under 64 MB nor over 256 MB.
READ_CACHE_FLOOR = 64 * _MIB
READ_CACHE_CEILING = 256 * _MIB
READ_CACHE_SHARE = 4


def clamp(lo: int, value: int, hi: int) -> int:
    """``value`` bounded below by ``lo`` and above by ``hi``."""
    return max(lo, min(value, hi))


def read_cache_budget(limit: int) -> int:
    """0103 D2: the read cache's byte budget at a deployment limit of ``limit`` bytes."""
    return clamp(READ_CACHE_FLOOR, limit // READ_CACHE_SHARE, READ_CACHE_CEILING)


@functools.cache
def deployment_memory_limit(root: Path = CGROUP_ROOT) -> int:
    """The memory this process may use, in bytes (precedence in the module docstring)."""
    found = (source(root) for source in _MEMORY_SOURCES)
    return next(filter(None, found), FALLBACK_MEMORY)


@functools.cache
def cpu_quota(root: Path = CGROUP_ROOT) -> float:
    """The CPUs this process may use: the cgroup v2 quota, else ``os.cpu_count()``."""
    return _cgroup_v2_cpu(root) or float(os.cpu_count() or 1)


def rss_now() -> int:
    """This process's resident size in bytes now (Linux ``statm``; elsewhere its peak)."""
    try:
        return int(_STATM.read_bytes().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return peak_rss()


def peak_rss(who: int = resource.RUSAGE_SELF) -> int:
    """``getrusage(who)``'s peak resident size in bytes (``ru_maxrss`` in its platform unit)."""
    return resource.getrusage(who).ru_maxrss * _MAXRSS_UNIT


# ── the sources ──────────────────────────────────────────────────────────────


def _fields(path: Path) -> list[str]:
    """The whitespace-separated fields of a cgroup file; none when it cannot be read."""
    try:
        return path.read_text(encoding="ascii").split()
    except (OSError, ValueError):
        return []


def _positive_ints(path: Path) -> list[int] | None:
    """Every field of ``path`` as a positive int; ``None`` when any is not (``"max"``)."""
    try:
        numbers = [int(field) for field in _fields(path)]
    except ValueError:
        return None
    return numbers if min(numbers, default=0) > 0 else None


def _cgroup_v2_memory(root: Path) -> int | None:
    numbers = _positive_ints(root / "memory.max")
    return numbers[0] if numbers else None


def _cgroup_v1_memory(root: Path) -> int | None:
    numbers = _positive_ints(root / "memory" / "memory.limit_in_bytes")
    return numbers[0] if numbers and numbers[0] < _V1_UNLIMITED else None


def _rlimit_as(_root: Path) -> int | None:
    soft = resource.getrlimit(resource.RLIMIT_AS)[0]
    return None if soft == resource.RLIM_INFINITY else soft


def _physical_ram(_root: Path) -> int | None:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError):
        return None


_MEMORY_SOURCES = (
    _cgroup_v2_memory,
    _cgroup_v1_memory,
    _rlimit_as,
    _physical_ram,
)


def _cgroup_v2_cpu(root: Path) -> float | None:
    numbers = _positive_ints(root / "cpu.max")
    return numbers[0] / numbers[1] if numbers and len(numbers) == 2 else None
