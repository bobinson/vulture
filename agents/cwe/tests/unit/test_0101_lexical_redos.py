"""Feature 0101 Phase 1 -- adversarial-input gate for `skills/_lexical.py`.

Two properties, both measured in a FRESH CHILD PROCESS with a hard wall-clock
timeout (the 0087 harness, reused rather than copied: a catastrophic `sre`
search is one uninterruptible C call, so only a process boundary can bound it):

1. **Every module-level pattern** of `_lexical`, found by introspection (never a
   hardcoded list) with a pinned floor, completes within the 0087 per-KB budget
   (0.060 ms/KB) on 512 KB single-line inputs: the five 0087 inputs plus the
   keyword-repetition inputs of LLD section 9.3 (PERF-6, PERF-12).
2. **The helpers are linear up to the cap and bounded past it** (PERF-9, RM-13,
   RM-16): for `call_argument_text`, `catch_binding`, `identifier_words` and
   `routine_header`, each doubling of the input up to `MAX_SCAN_CHARS` costs
   < 2.6x, a call at the cap costs <= 0.5 ms/KB, and a 512 KB input costs about
   what an input AT the cap costs -- so removing a helper's internal cap turns
   this file red.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from shared.testing.timing import budget
from tests.unit import test_0087_redos as gate0087
from tests.unit.test_0087_redos import BUDGET_MS, INPUT_BYTES, PROC_TIMEOUT_SEC

MODULE = "cwe_agent.skills._lexical"
AGENT_ROOT = Path(__file__).resolve().parents[2]

# Pinned at freeze (Phase 1.4): a pattern that moves out of module scope, or a
# consolidation that drops one, must turn this red, not silently shrink the gate.
MIN_PATTERNS = 15

# LLD 9.3 keyword-repetition inputs, each repeated to INPUT_BYTES.
KEYWORD_UNITS: dict[str, str] = {
    "kw_return": " return x",
    "kw_call": "x(",
    "kw_assign": "a = ",
    "kw_catch": "catch(e) ",
    "kw_for": "for ",
}
INPUT_NAMES: tuple[str, ...] = (*gate0087.INPUT_NAMES, *KEYWORD_UNITS, "kw_member_append")

DOUBLING_SIZES = (250, 500, 1000, 2000)
MAX_DOUBLING_RATIO = 2.6
HELPER_BUDGET_MS_PER_KB = budget(0.5)
# A 512 KB input must cost about what an input at the cap costs (slicing the
# subject is the only extra work). 3x leaves room for timer noise; an uncapped
# linear helper reads ~256x here, a quadratic one far more.
MAX_PAST_CAP_RATIO = 3.0


def build_input(name: str, size: int = INPUT_BYTES) -> str:
    if name in KEYWORD_UNITS:
        unit = KEYWORD_UNITS[name]
        return (unit * (size // len(unit) + 1))[:size]
    if name == "kw_member_append":
        tail = "= append("
        return ("a." * size)[: size - len(tail)] + tail
    return gate0087.build_adversarial_input(name, size)


def discover_patterns() -> dict[str, re.Pattern[str]]:
    import importlib

    module = importlib.import_module(MODULE)
    return {k: v for k, v in vars(module).items() if isinstance(v, re.Pattern)}


PATTERN_NAMES: tuple[str, ...] = tuple(sorted(discover_patterns()))


# --------------------------------------------------------------------------
# Helper subjects: (call, input builder) per helper. The builders produce the
# worst shape found for each helper: input that never matches, so every
# alternative is tried to the end of the (capped) subject.
# --------------------------------------------------------------------------

def _helper_cases() -> dict[str, tuple[Callable[[str], object], Callable[[int], str]]]:
    from cwe_agent.skills import _lexical as lx

    words = lx.identifier_words.__wrapped__  # bypass the lru_cache: time the work
    header = getattr(lx.routine_header, "__wrapped__", lx.routine_header)
    return {
        "identifier_words": (words, lambda n: ("aB1" * n)[:n]),
        "identifier_words_caps": (words, lambda n: "A" * n),
        "catch_binding": (lx.catch_binding, lambda n: ("} catch (" + "a | " * n)[:n]),
        "catch_binding_except": (lx.catch_binding, lambda n: ("except " + "x, " * n)[:n]),
        "catch_binding_promise": (lx.catch_binding, lambda n: (".catch((" + "e " * n)[:n]),
        "call_argument_text": (
            lambda s: lx.call_argument_text(s, 1, max_span=len(s)),
            lambda n: ("f(" + "g(\"x)\", " * n)[:n],
        ),
        "routine_header": (header, lambda n: ("  public " + "a " * n)[:n]),
    }


HELPER_NAMES: tuple[str, ...] = tuple(sorted(_helper_cases()))


def _loops_for(call: Callable[[str], object], subject: str) -> int:
    """Smallest power-of-two loop count whose run takes >= ~2 ms."""
    loops = 1
    while loops < 1 << 16 and _run_loops(call, subject, loops) < 0.002:
        loops *= 2
    return loops


def _run_loops(call: Callable[[str], object], subject: str, loops: int) -> float:
    start = time.perf_counter()
    for _ in range(loops):
        call(subject)
    return time.perf_counter() - start


ROUNDS = 9


def _time_sweep(call: Callable[[str], object], subjects: dict[str, str]) -> dict[str, float]:
    """Per-call milliseconds per subject: the minimum over ROUNDS ROUND-ROBIN samples.

    Interleaving the sizes is what makes the RATIO robust: a burst of load from
    another process lands on every size of a round instead of inflating one
    size's whole measurement (seen once under a concurrent suite: one step read
    2.74 and the next 1.40 with sequential min-of-5 sampling).
    """
    loops = {k: _loops_for(call, v) for k, v in subjects.items()}
    best = dict.fromkeys(subjects, float("inf"))
    for _ in range(ROUNDS):
        for k, v in subjects.items():
            best[k] = min(best[k], _run_loops(call, v, loops[k]) / loops[k])
    return {k: ms * 1000.0 for k, ms in best.items()}


# --------------------------------------------------------------------------
# Child process
# --------------------------------------------------------------------------

def _emit_to(handle):
    def emit(record: dict[str, object]) -> None:
        handle.write(json.dumps(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return emit


def _child_pattern(name: str, emit) -> int:
    pattern = discover_patterns().get(name)
    if pattern is None:
        emit({"status": "missing", "name": name})
        return 1
    for input_name in INPUT_NAMES:
        subject = build_input(input_name)
        emit({"status": "start", "input": input_name})
        emit({"status": "ok", "input": input_name, "ms": gate0087._measure_one(pattern, subject)})
    return 0


def _child_helper(name: str, emit) -> int:
    from cwe_agent.skills import _lexical as lx

    call, build = _helper_cases()[name]
    subjects = {f"n={n}": build(n) for n in DOUBLING_SIZES}
    subjects["past_cap"] = build(INPUT_BYTES)
    emit({"status": "start", "input": "sweep", "cap": lx.MAX_SCAN_CHARS})
    for key, ms in _time_sweep(call, subjects).items():
        emit({"status": "ok", "input": key, "ms": ms})
    return 0


def _child_main(kind: str, name: str, out_path: str) -> int:
    with open(out_path, "w", encoding="utf-8") as handle:
        emit = _emit_to(handle)
        if kind == "pattern":
            return _child_pattern(name, emit)
        return _child_helper(name, emit)


def _spawn(kind: str, name: str, out_path: str) -> None:
    """Run the child; a timeout leaves the unfinished measurement without an ok record."""
    try:
        subprocess.run(
            [sys.executable, "-m", "tests.unit.test_0101_lexical_redos",
             "--child", kind, name, out_path],
            cwd=AGENT_ROOT, capture_output=True, text=True,
            timeout=PROC_TIMEOUT_SEC * 2, check=False,
        )
    except subprocess.TimeoutExpired:
        pass


def _fold(results: dict[str, float | None], record: dict) -> None:
    """``start`` -> None (in flight), ``ok`` -> its milliseconds."""
    if record["status"] == "missing":
        pytest.fail(f"{record['name']!r} disappeared between collection and measurement")
    ms = record.get("ms")
    results[record["input"]] = None if ms is None else float(ms)


def _run_child(kind: str, name: str) -> dict[str, float | None]:
    fd, out_path = tempfile.mkstemp(prefix=f"redos0101_{name}_", suffix=".jsonl")
    os.close(fd)
    try:
        _spawn(kind, name, out_path)
        results: dict[str, float | None] = {}
        with open(out_path, encoding="utf-8") as handle:
            for raw in filter(None, map(str.strip, handle)):
                _fold(results, json.loads(raw))
    finally:
        os.unlink(out_path)
    assert results, f"measurement child for {kind} {name!r} produced no records"
    return results


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_pattern_discovery_is_not_vacuous() -> None:
    assert len(PATTERN_NAMES) >= MIN_PATTERNS, (
        f"{MODULE} exposes {len(PATTERN_NAMES)} module-level patterns "
        f"({list(PATTERN_NAMES)}); the pinned floor is {MIN_PATTERNS}. Fix the "
        "discovery, do not lower the floor."
    )


def _over_budget(ms: float | None) -> bool:
    """None = the child was killed before this measurement returned."""
    return ms is None or ms >= BUDGET_MS


@pytest.mark.parametrize("pattern_name", PATTERN_NAMES)
def test_pattern_survives_adversarial_input(pattern_name: str) -> None:
    timings = _run_child("pattern", pattern_name)
    bad = {n: ms for n in INPUT_NAMES if _over_budget(ms := timings.get(n))}
    assert not bad, (
        f"{pattern_name}: budget {BUDGET_MS:.1f} ms per {INPUT_BYTES // 1024} KB; "
        f"over budget or did not complete (None): {bad}"
    )


def _sweep(timings: dict[str, float | None]) -> list[float]:
    """Per-size milliseconds; a measurement that never returned reads as infinite."""
    return [timings.get(f"n={n}") or float("inf") for n in DOUBLING_SIZES]


def _failed(helper: str, checks: tuple[tuple[bool, str], ...]) -> list[str]:
    return [f"{helper}: {msg}" for ok, msg in checks if not ok]


def _doubling_ratios(sizes: list[float]) -> list[float]:
    return [b / max(a, 1e-6) for a, b in zip(sizes, sizes[1:])]


def _helper_verdict(helper: str, timings: dict[str, float | None]) -> list[str]:
    """Every violated property of one helper's sweep (empty when it holds)."""
    sizes = _sweep(timings)
    ratios = _doubling_ratios(sizes)
    per_kb = sizes[-1] / (DOUBLING_SIZES[-1] / 1024)
    past_ratio = (timings.get("past_cap") or float("inf")) / max(sizes[-1], 1e-6)
    checks = (
        (max(ratios) < MAX_DOUBLING_RATIO, f"doubling ratios {ratios} ({sizes} ms)"),
        (per_kb <= HELPER_BUDGET_MS_PER_KB, f"{per_kb:.3f} ms/KB at the cap"),
        (past_ratio < MAX_PAST_CAP_RATIO,
         f"{INPUT_BYTES // 1024} KB costs {past_ratio:.1f}x the cap: the helper no longer caps its input"),
    )
    return _failed(helper, checks)


@pytest.mark.parametrize("helper", HELPER_NAMES)
def test_helper_is_linear_to_the_cap_and_bounded_past_it(helper: str) -> None:
    problems = _helper_verdict(helper, _run_child("helper", helper))
    assert not problems, "\n".join(problems)


def test_doubling_sizes_end_at_the_cap() -> None:
    from cwe_agent.skills import _lexical as lx

    # The linearity sweep is only meaningful up to the cap; pin both together.
    assert DOUBLING_SIZES[-1] == lx.MAX_SCAN_CHARS == 2000


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3], sys.argv[4]))
    raise SystemExit("run under pytest; --child <kind> <name> <out_path> is internal")
