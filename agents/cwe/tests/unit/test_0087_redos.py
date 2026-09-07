"""Feature 0087 §5 — adversarial-input (ReDoS) gate for the CWE-778 skill.

The plan's gate, verbatim: *every compiled site and log pattern must complete in
< 10 ms on 512 KB single-line inputs of: all spaces; all tabs; ``(``×N; ``a``×N;
and ``catch(e){`` + spaces×N.*

Why this matters operationally: Vulture scans arbitrary git URLs with a 512 KB
per-file cap (``VULTURE_MAX_FILE_SIZE``). A single-line 512 KB file is therefore
remote-attacker-supplied input to every one of these patterns, and the cost is
paid by the agent, not the attacker.

HOW THE PATTERNS ARE DISCOVERED
    By introspecting the module for ``re.Pattern`` attributes — never a
    hardcoded list — so a pattern added by a later step of the work order is
    covered the day it lands without anybody remembering to update this file.
    ``test_pattern_discovery_is_not_vacuous`` pins a floor of 6 so that a
    refactor which moves the patterns out of module scope turns this file red
    instead of turning it into a no-op.

STATE WHEN THIS FILE WAS WRITTEN (2026-09-02), measured with this harness
    Milliseconds per 512 KB search; the pattern set is whatever introspection
    found at the time, so later steps will add rows.

      pattern              spaces    tabs  parens  letters  catch(e){+spaces
      _PY_EXCEPT             0.49    0.49    0.00     0.00     0.00
      _PY_EXCEPT_INLINE      0.51    0.51    0.00     0.00     0.00
      _CATCH_LINE            5.50    5.51    5.58     1.82     0.00
      _CATCH_EMPTY           5.49    5.47    5.52     1.82     5.55
      _LOG_CALL              5.62    5.65    5.54     1.80     5.56
      _AUTH_DECISION         5.66    5.60    5.65     1.85     5.65
      _ERROR_DELEGATE        5.65    5.65    5.65     1.85     5.65
      _GO_SITE               0.00    0.00    0.00     0.00     0.00
      _GO_LOG                5.65    5.62    5.54     1.85     5.51
      _GO_PROPAGATES         5.65    5.65    5.65     1.85     5.67
      _GO_SWALLOW_RETURN     0.00    0.00    0.00     0.00     0.00
      _GO_SWALLOW_LOOP       0.00    0.00    0.00     0.00     0.00
      _PROPAGATES           40.13   39.75   39.80    19.98    39.90   <-- FAILS

    **_CATCH_EMPTY / defect B2.** This gate was written expecting B2 to be red.
    The shipped (git HEAD) pattern ``\\bcatch\\s*\\([^)]*\\)\\s*\\{\\s*[;]?\\s*\\}``
    is quadratic — re-measured here at 3.29 / 12.97 / 53.22 ms on 2 k / 4 k / 8 k
    trailing spaces, reproducing the plan's 12.98 ms figure to two decimals and
    extrapolating to roughly two minutes at 512 KB. Step 1 of §8 (bounded
    quantifiers, ``\\s{0,8};?\\s{0,8}``) had already landed in the working tree
    by the time this harness first ran, so the case reads 5.55 ms and is green.
    *It is deliberately NOT xfailed:* an xfail passes silently once the defect is
    fixed and thereby stops being a gate. ``test_catch_empty_quadratic_regression_shape``
    below pins the complexity class directly, so a future edit that reintroduces
    an unbounded ``\\s*`` there is caught even on hardware fast enough to squeak
    under 10 ms.

    **_PROPAGATES.** A second, previously unrecorded violation, and a different
    failure class: it is **linear** (0.16 / 0.31 / 0.62 / 1.25 / 2.47 ms at 2 k
    / 4 k / 8 k / 16 k / 32 k), not quadratic. It has no literal prefix for the
    engine to skip on, so it pays ~76 ns at each of the 512 K start positions,
    landing at 40 ms — 4× budget. §5's "defence in depth" per-line guard (skip
    site matching on lines longer than 2000 chars) closes this without touching
    the pattern; at 2000 chars every pattern here is far inside budget. It is
    asserted rather than waived because the gate as the plan states it is a
    property of the patterns, and nothing here is relaxed to match current
    behaviour.

MEASUREMENT MECHANICS
    Each pattern is measured in a **fresh child process** with a hard wall-clock
    timeout. This is not fastidiousness: catastrophic backtracking inside
    CPython's ``sre`` engine is a single uninterruptible C call — ``signal.alarm``
    and ``KeyboardInterrupt`` are only delivered once ``search()`` returns, so an
    in-process timeout is impossible and a quadratic pattern would hang the suite
    for minutes. The child streams one JSON line per measurement to a result file
    and flushes it, so a measurement that never returns is attributable: the
    parent sees a ``start`` record with no matching ``ok`` record.

    Inputs are ordered with the known-slow ``catch(e){`` case LAST so that a
    child killed on it still yields the other four measurements.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

SKILL_MODULE = "cwe_agent.skills.insufficient_logging_check"

# §5 gate constants.
INPUT_BYTES = 512 * 1024
BUDGET_MS = 10.0

# Non-vacuity floor: the shipped skill compiles 8 module-level patterns
# (_PY_EXCEPT, _PY_EXCEPT_INLINE, _CATCH_LINE, _CATCH_EMPTY, _LOG_CALL,
# _AUTH_DECISION, _ERROR_DELEGATE, _PROPAGATES). 6 leaves room for a
# consolidation into per-family alternations (§5 optimisation #2) without
# leaving room for "the introspection found nothing and every test passed".
MIN_PATTERNS = 6

# Wall clock allowed per child process: ~1 s module import + five measurements.
# Any single measurement that blows through this is 1000× over a 10 ms budget,
# so the exact value is not load-bearing — it only bounds how long the suite
# waits before calling a pattern pathological.
PROC_TIMEOUT_SEC = 12.0


def build_adversarial_input(name: str, size: int = INPUT_BYTES) -> str:
    """Return one of §5's adversarial single-line inputs, exactly ``size`` chars."""
    if name == "spaces":
        return " " * size
    if name == "tabs":
        return "\t" * size
    if name == "open_parens":
        return "(" * size
    if name == "letters":
        return "a" * size
    if name == "catch_open_then_spaces":
        prefix = "catch(e){"
        return prefix + " " * (size - len(prefix))
    raise ValueError(f"unknown adversarial input: {name}")


# Known-slow case LAST: a child killed on it still reports the first four.
INPUT_NAMES: tuple[str, ...] = (
    "spaces",
    "tabs",
    "open_parens",
    "letters",
    "catch_open_then_spaces",
)


def discover_patterns() -> dict[str, re.Pattern[str]]:
    """Every module-level compiled pattern in the skill, found by introspection.

    Deliberately not a hardcoded list: patterns added by later steps of the 0087
    work order (the brace-family alternation, the Go arm, the Rust arm) are
    covered automatically.
    """
    import importlib

    module = importlib.import_module(SKILL_MODULE)
    return {
        name: value
        for name, value in vars(module).items()
        if isinstance(value, re.Pattern)
    }


PATTERN_NAMES: tuple[str, ...] = tuple(sorted(discover_patterns()))


def test_pattern_discovery_is_not_vacuous() -> None:
    """Guard the gate itself: introspection must find a real population.

    Without this, a refactor that moves the patterns into a class, a closure or
    a dict would make every parametrised case below vanish and the whole file
    would report green while checking nothing.
    """
    assert len(PATTERN_NAMES) >= MIN_PATTERNS, (
        f"{SKILL_MODULE} exposed only {len(PATTERN_NAMES)} module-level "
        f"re.Pattern objects ({list(PATTERN_NAMES)}); expected at least "
        f"{MIN_PATTERNS}. The ReDoS gate discovers its subjects by "
        "introspection, so a smaller population means this test file is "
        "checking (almost) nothing — fix the discovery, do not lower the floor."
    )


# --------------------------------------------------------------------------
# Child-process measurement
# --------------------------------------------------------------------------

# Measurements below this are repeated and the minimum kept. Above it, one shot:
# repeating a two-minute search buys nothing, and anything over 100 ms is already
# ten budgets deep, so the extra precision would not change a verdict.
_REPEAT_UNDER_SEC = 0.100
_REPEATS = 5


def _measure_one(pattern: re.Pattern[str], subject: str) -> float:
    """Min-of-N wall time of one ``search`` call, in milliseconds.

    Min, not mean: this is a floor-measurement of a deterministic computation, so
    every source of variance (scheduling, page faults on the freshly-allocated
    512 KB subject, CPU frequency ramp) is additive noise. Taken as a single
    shot, the FIRST measurement in a fresh process reads 2-3× high — measured
    13.1 ms against a 5.7 ms steady state for ``_CATCH_LINE`` — which straddles
    the 10 ms budget and would make this gate flap. A warmup pass on a small
    subject plus min-of-5 removes it.
    """
    pattern.search(subject[:4096])  # warm the code path, not the timer
    start = time.perf_counter()
    pattern.search(subject)
    best = time.perf_counter() - start
    if best < _REPEAT_UNDER_SEC:
        for _ in range(_REPEATS - 1):
            start = time.perf_counter()
            pattern.search(subject)
            best = min(best, time.perf_counter() - start)
    return best * 1000.0


def _child_main(pattern_name: str, out_path: str) -> int:
    """Measure one pattern against every adversarial input; stream results out.

    Each measurement is bracketed by a ``start`` record and an ``ok`` record,
    both flushed and fsynced, so that a kill mid-search leaves evidence of which
    measurement was in flight.
    """
    patterns = discover_patterns()
    pattern = patterns.get(pattern_name)
    with open(out_path, "w", encoding="utf-8") as handle:

        def emit(record: dict[str, object]) -> None:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

        if pattern is None:
            emit({"status": "missing", "input": None, "pattern": pattern_name})
            return 1
        for input_name in INPUT_NAMES:
            subject = build_adversarial_input(input_name)
            emit({"status": "start", "pattern": pattern_name, "input": input_name})
            elapsed_ms = _measure_one(pattern, subject)
            emit({
                "status": "ok",
                "pattern": pattern_name,
                "input": input_name,
                "ms": elapsed_ms,
            })
    return 0


def _run_child(pattern_name: str) -> dict[str, float | None]:
    """Run the measurement child and return ``{input_name: ms or None}``.

    ``None`` means the child was killed before that measurement returned, i.e.
    the pattern did not complete within PROC_TIMEOUT_SEC — a budget violation by
    a factor of at least a thousand.
    """
    fd, out_path = tempfile.mkstemp(prefix=f"redos_{pattern_name}_", suffix=".jsonl")
    os.close(fd)
    try:
        completed: subprocess.CompletedProcess[str] | None = None
        timed_out = False
        try:
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()),
                 "--child", pattern_name, out_path],
                capture_output=True,
                text=True,
                timeout=PROC_TIMEOUT_SEC,
                check=False,
            )
        except subprocess.TimeoutExpired:
            timed_out = True

        results: dict[str, float | None] = {name: None for name in INPUT_NAMES}
        seen_start = False
        with open(out_path, encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue
                record = json.loads(raw)
                if record.get("status") == "missing":
                    pytest.fail(
                        f"pattern {pattern_name!r} disappeared between collection "
                        "and measurement"
                    )
                if record.get("status") == "start":
                    seen_start = True
                if record.get("status") == "ok":
                    results[record["input"]] = float(record["ms"])

        if not seen_start:
            stderr = completed.stderr if completed is not None else "(killed)"
            pytest.fail(
                f"measurement child for {pattern_name!r} produced no records "
                f"(timed_out={timed_out}); stderr:\n{stderr}"
            )
        return results
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


@pytest.fixture(scope="session")
def redos_timings() -> dict[str, dict[str, float | None]]:
    """All measurements, one child process per pattern, taken once per session."""
    return {name: _run_child(name) for name in PATTERN_NAMES}


def _format_row(pattern_name: str, timings: dict[str, float | None]) -> str:
    parts = []
    for input_name in INPUT_NAMES:
        value = timings[input_name]
        parts.append(
            f"{input_name}={'TIMEOUT(>%.0fs)' % PROC_TIMEOUT_SEC if value is None else '%.3f ms' % value}"
        )
    return f"{pattern_name}: " + ", ".join(parts)


@pytest.mark.parametrize("pattern_name", PATTERN_NAMES)
def test_pattern_survives_adversarial_input(
    pattern_name: str,
    redos_timings: dict[str, dict[str, float | None]],
) -> None:
    """§5 gate: < 10 ms on every 512 KB adversarial single-line input.

    Red for ``_PROPAGATES`` when this was written (40 ms, 4× budget), and
    written expecting ``_CATCH_EMPTY`` to be red too (defect B2). See the module
    docstring for both. Nothing is xfailed — an xfail keeps passing after the
    defect is fixed and stops being a gate.
    """
    timings = redos_timings[pattern_name]

    # Non-vacuity: every input must actually have been attempted.
    assert set(timings) == set(INPUT_NAMES), (
        f"measured {sorted(timings)} for {pattern_name}, expected {list(INPUT_NAMES)}"
    )

    violations = [
        (input_name, timings[input_name])
        for input_name in INPUT_NAMES
        if timings[input_name] is None or timings[input_name] >= BUDGET_MS
    ]
    if violations:
        detail = "\n  ".join(
            f"{input_name}: "
            + ("did not complete within %.0f s" % PROC_TIMEOUT_SEC
               if ms is None else "%.3f ms (%.1f× budget)" % (ms, ms / BUDGET_MS))
            for input_name, ms in violations
        )
        pytest.fail(
            f"{pattern_name} exceeds the 0087 §5 adversarial-input budget of "
            f"{BUDGET_MS:.0f} ms on {INPUT_BYTES // 1024} KB single-line input:"
            f"\n  {detail}\n"
            f"full row -> {_format_row(pattern_name, timings)}\n"
            "Fix: bounded quantifiers only (\\s{0,8}, [^)]{0,200}); never place "
            "[^X]* adjacent to \\s*; and apply the §5 per-line 2000-char guard."
        )


def test_catch_empty_quadratic_regression_shape() -> None:
    """Pin the *shape* of defect B2, so a fix is a fix and not a constant factor.

    Doubling the trailing-space count must not quadruple the time. Runs at small
    N (≤ 8 k) so it is cheap and in-process. Independent of the 512 KB gate above:
    that one says "too slow", this one says "super-linear", and a pattern can be
    made to pass the first by luck of hardware while still being quadratic.
    """
    patterns = discover_patterns()
    catch_empty = patterns.get("_CATCH_EMPTY")
    if catch_empty is None:
        pytest.skip("_CATCH_EMPTY was consolidated away; the 512 KB gate still applies")

    def timed(n: int) -> float:
        subject = "catch(e){" + " " * n
        catch_empty.search(subject[:512])
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            catch_empty.search(subject)
            best = min(best, time.perf_counter() - start)
        return best * 1000.0

    small = timed(4_000)
    large = timed(32_000)

    # Non-vacuity: a ratio of two numbers indistinguishable from zero proves
    # nothing. Both endpoints must be above timer noise.
    assert large > 0.005, (
        f"large-N measurement was {large:.6f} ms, below timer noise; this "
        "comparison cannot detect anything"
    )

    # 8× the input costs a linear pattern ~8×, a quadratic one ~64×. 20 sits
    # near the geometric midpoint, so the verdict does not hinge on a tight
    # constant. Measured either side of it: the shipped pre-0087 pattern grows
    # 33.4× over this span, the bounded rewrite 8.0×.
    growth = large / max(small, 1e-6)
    assert growth < 20.0, (
        f"_CATCH_EMPTY grows {growth:.1f}× when the trailing-space run grows 8× "
        f"({small:.3f} ms at 4000 -> {large:.3f} ms at 32000). That is "
        "super-linear — defect B2, an unbounded `\\s*` adjacent to another "
        "quantifier — not a constant factor. Reference sweep of the shipped "
        "pre-0087 pattern, min of 3: 0.85 / 3.29 / 12.96 / 27.28 / 108.5 / "
        "433.4 / 1735.2 ms at 1k / 2k / 4k / 8k / 16k / 32k / 64k."
    )


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest; --child <pattern> <out_path> is internal")
