"""Wall-clock budgets for timing tests that hold on any machine.

A budget in milliseconds is a property of the machine it was measured on. The
CI runner ran the CWE timing gates 2.4-5.4x slower than the box their budgets
were set on, so linear code with unchanged output failed 41 gates there.
``budget(ms)`` turns a figure set on that reference box into one for this
machine: it times a fixed workload of regex scanning and interpreter loops,
scales by how much slower this machine runs it (never below 1, so a faster
machine is held to the original figure), and applies ``MARGIN``.

The margin is what the reference box itself needs: several gates measured
within 1% of their figure there and failed under ordinary load. These budgets
catch pathological cost. Super-linear growth is caught by each gate's own
doubling-ratio or subprocess-timeout check, which nothing here scales.
"""

from __future__ import annotations

import functools
import re
import statistics
import time

# Median of 5 runs of _workload on the reference box (2026-10-13).
REFERENCE_MS = 23.0
MARGIN = 2.0

_LINE = "    const value = compute(err.message, items[i]) + other.call(a, b); // trailing note\n"
# ~25 ms, longer than a scheduler time slice: a run short enough to fit in one
# slice reads the same on a contended machine as on an idle one.
_TEXT = _LINE * 15000
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(\s*([^()]{0,80})\)")


def _workload() -> int:
    _CALL.findall(_TEXT)
    return sum(len(word) for line in _TEXT.splitlines() for word in line.split() if word.isidentifier())


def reference_ms(rounds: int = 5) -> float:
    """Median, not best: the timing gates feel contention, so the calibration must too."""
    runs = []
    for _ in range(rounds):
        start = time.perf_counter()
        _workload()
        runs.append(time.perf_counter() - start)
    return statistics.median(runs) * 1000.0


@functools.cache
def speed_factor() -> float:
    """How many times slower than the reference box this machine runs; at least 1."""
    return max(1.0, reference_ms() / REFERENCE_MS)


def budget(reference_value: float) -> float:
    """``reference_value``, a budget measured on the reference box, for this machine."""
    return reference_value * MARGIN * speed_factor()
