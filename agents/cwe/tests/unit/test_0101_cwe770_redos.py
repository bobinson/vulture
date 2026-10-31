"""Feature 0101 -- adversarial-input gate for the patterns of `skills/resource_check.py`.

Every module-level ``re.Pattern`` of the module is found by INTROSPECTION (never
a name list) with a pinned floor, so a 0101 pattern that moves out of module
scope, or a consolidation that drops one, turns this red instead of silently
shrinking the gate (LLD 9.3, PERF-5, PERF-12).

Each pattern is measured THROUGH THE LINE CAP: every CWE-770 predicate runs on
``line[:MAX_SCAN_CHARS]`` (LLD 4.2), so the subject is the 0087 / 0101
adversarial 512 KB input cut at the cap. Two properties, both inside one child
process with a hard timeout (a catastrophic ``sre`` search is one
uninterruptible C call, so only a process boundary bounds it):

1. the capped search stays within the 0087 per-KB budget of the 512 KB input;
2. each doubling of the subject up to the cap costs < 2.6x (linearity), on the
   input that was slowest at the cap.

The CWE-770 per-identifier templates (``*_TEMPLATE``, built for adversarial
names, RM-13) read JOINED routine text of up to 120 capped lines, so they are
measured on the raw 512 KB inputs against the same budget, not through the cap.

The cap itself is pinned: ``_code`` on a 512 KB line must cost about what it
costs at the cap, so removing the cap turns this file red.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.unit import test_0087_redos as gate0087
from tests.unit import test_0101_lexical_redos as gate0101
from tests.unit.test_0087_redos import BUDGET_MS, INPUT_BYTES, PROC_TIMEOUT_SEC

MODULE = "cwe_agent.skills.resource_check"
AGENT_ROOT = Path(__file__).resolve().parents[2]

# Pinned after the 0101 port: the module's pre-0101 patterns plus the CWE-770
# role patterns. Fix the discovery, never lower the floor.
MIN_PATTERNS = 69
MIN_TEMPLATES = 17
# Adversarial identifiers for the templates: the longest the identifier
# patterns admit, one that repeats inside the inputs, and one needing escapes.
TEMPLATE_NAMES = ("a" * 64, "a", "$e")

# CWE-770 repetition units on top of the 0087 and 0101 keyword inputs.
UNITS_770: dict[str, str] = {
    "kw_push": ".push(",
    "kw_plus_eq": "a += ",
    "kw_subscript_assign": "a] = ",
    "kw_chan_recv": "= <- ",
    "kw_generic": "Map<",
    "kw_brace": "{",
}
INPUT_NAMES: tuple[str, ...] = (*gate0101.INPUT_NAMES, *UNITS_770)
DOUBLING_SIZES = (250, 500, 1000, 2000)
MAX_DOUBLING_RATIO = 2.6
MAX_PAST_CAP_RATIO = 3.0
CHILD_TIMEOUT_SEC = PROC_TIMEOUT_SEC * 10


def build_input(name: str, size: int = INPUT_BYTES) -> str:
    unit = UNITS_770.get(name)
    if unit is None:
        return gate0101.build_input(name, size)
    return (unit * (size // len(unit) + 1))[:size]


def discover_patterns() -> dict[str, re.Pattern[str]]:
    import importlib

    module = importlib.import_module(MODULE)
    return {k: v for k, v in vars(module).items() if isinstance(v, re.Pattern)}


def discover_templates() -> dict[str, str]:
    import importlib

    module = importlib.import_module(MODULE)
    return {k: v for k, v in vars(module).items() if k.endswith("_TEMPLATE") and isinstance(v, str)}


PATTERN_NAMES: tuple[str, ...] = tuple(sorted(discover_patterns()))
TEMPLATE_IDS: tuple[str, ...] = tuple(sorted(discover_templates()))


# --------------------------------------------------------------------------
# Child process: every pattern, streamed, so a kill names the one in flight.
# --------------------------------------------------------------------------

def _capped_inputs() -> dict[str, str]:
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS

    return {name: build_input(name)[:MAX_SCAN_CHARS] for name in INPUT_NAMES}


def _measure_pattern(pattern: re.Pattern[str], subjects: dict[str, str]) -> dict[str, object]:
    at_cap = {n: gate0087._measure_one(pattern, s) for n, s in subjects.items()}
    worst = max(at_cap, key=at_cap.__getitem__)
    sweep = gate0101._time_sweep(pattern.search, {
        str(n): subjects[worst][:n] for n in DOUBLING_SIZES
    })
    return {"at_cap": at_cap, "worst": worst, "sweep": [sweep[str(n)] for n in DOUBLING_SIZES]}


def _raw_worst(pattern: re.Pattern[str]) -> float:
    return max(gate0087._measure_one(pattern, build_input(n)) for n in INPUT_NAMES)


def _child_patterns(emit) -> int:
    subjects = _capped_inputs()
    for name, pattern in sorted(discover_patterns().items()):
        emit({"status": "start", "name": name})
        emit({"status": "ok", "name": name, **_measure_pattern(pattern, subjects)})
    return 0


def _child_templates(emit) -> int:
    from cwe_agent.skills import resource_check as rc

    for tid in sorted(discover_templates()):
        emit({"status": "start", "name": tid})
        worst = max(_raw_worst(rc._named(getattr(rc, tid), name)) for name in TEMPLATE_NAMES)
        emit({"status": "ok", "name": tid, "raw_ms": worst})
    return 0


def _child_cap(emit) -> int:
    from cwe_agent.skills import resource_check as rc
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS

    code = rc.stripped_code.__wrapped__   # bypass the lru_cache: time the work
    line = "    out.append(v)  # " + "x(" * INPUT_BYTES
    subjects = {"at_cap": line[:MAX_SCAN_CHARS], "past_cap": line[:INPUT_BYTES]}
    emit({"status": "start", "name": "cap"})
    emit({"status": "ok", "name": "cap", **gate0101._time_sweep(code, subjects)})
    return 0


def _child_main(kind: str, out_path: str) -> int:
    with open(out_path, "w", encoding="utf-8") as handle:
        emit = gate0101._emit_to(handle)
        children = {"patterns": _child_patterns, "templates": _child_templates, "cap": _child_cap}
        return children[kind](emit)


def _run_child(kind: str) -> dict[str, dict | None]:
    fd, out_path = tempfile.mkstemp(prefix=f"redos0101_770_{kind}_", suffix=".jsonl")
    os.close(fd)
    try:
        _spawn(kind, out_path)
        results = _read_records(out_path)
    finally:
        os.unlink(out_path)
    assert results, f"measurement child {kind!r} produced no records"
    return results


def _spawn(kind: str, out_path: str) -> None:
    """Run the child; a timeout leaves the unfinished measurement without an ok record."""
    try:
        subprocess.run(
            [sys.executable, "-m", "tests.unit.test_0101_cwe770_redos", "--child", kind, out_path],
            cwd=AGENT_ROOT, capture_output=True, text=True, timeout=CHILD_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        pass


def _read_records(out_path: str) -> dict[str, dict | None]:
    """``start`` -> None (in flight when killed), ``ok`` -> the record."""
    with open(out_path, encoding="utf-8") as handle:
        records = [json.loads(raw) for raw in filter(None, map(str.strip, handle))]
    return {r["name"]: (r if r["status"] == "ok" else None) for r in records}


@pytest.fixture(scope="module")
def pattern_timings() -> dict[str, dict | None]:
    return _run_child("patterns")


@pytest.fixture(scope="module")
def template_timings() -> dict[str, dict | None]:
    return _run_child("templates")


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_pattern_discovery_is_not_vacuous() -> None:
    assert len(PATTERN_NAMES) >= MIN_PATTERNS, (
        f"{MODULE} exposes {len(PATTERN_NAMES)} module-level patterns; the pinned "
        f"floor is {MIN_PATTERNS}. Fix the discovery, do not lower the floor."
    )


def test_template_discovery_is_not_vacuous() -> None:
    assert len(TEMPLATE_IDS) >= MIN_TEMPLATES, (
        f"{MODULE} exposes {len(TEMPLATE_IDS)} per-identifier templates; the pinned "
        f"floor is {MIN_TEMPLATES}."
    )


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_template_survives_adversarial_names_on_joined_text(template_id, template_timings) -> None:
    record = template_timings.get(template_id)
    assert record, f"{template_id}: not measured (the child was killed on or before it)"
    assert record["raw_ms"] < BUDGET_MS, (
        f"{template_id}: {record['raw_ms']:.1f} ms on a {INPUT_BYTES // 1024} KB input "
        f"(budget {BUDGET_MS:.1f} ms) for one of {TEMPLATE_NAMES}"
    )


def _over_budget(timings: dict[str, float]) -> dict[str, float]:
    return {n: ms for n, ms in timings.items() if ms >= BUDGET_MS}


def _ratios(sweep: list[float]) -> list[float]:
    return [b / max(a, 1e-6) for a, b in zip(sweep, sweep[1:])]


@pytest.mark.parametrize("pattern_name", PATTERN_NAMES)
def test_pattern_is_linear_and_within_budget_through_the_cap(pattern_name, pattern_timings) -> None:
    record = pattern_timings.get(pattern_name)
    assert record, f"{pattern_name}: not measured (the child was killed on or before it)"
    over = _over_budget(record["at_cap"])
    ratios = _ratios(record["sweep"])
    assert not over, f"{pattern_name}: over {BUDGET_MS:.1f} ms through the cap: {over}"
    assert max(ratios) < MAX_DOUBLING_RATIO, (
        f"{pattern_name}: doubling ratios {[round(r, 2) for r in ratios]} on "
        f"{record['worst']!r} (per-size ms {record['sweep']})"
    )


def test_the_line_cap_is_pinned() -> None:
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS
    from shared.tools.pattern_matcher import _MAX_LINE_CHARS

    assert MAX_SCAN_CHARS is _MAX_LINE_CHARS
    record = _run_child("cap")["cap"]
    assert record, "cap measurement did not complete"
    ratio = record["past_cap"] / max(record["at_cap"], 1e-6)
    assert ratio < MAX_PAST_CAP_RATIO, (
        f"_code on a {INPUT_BYTES // 1024} KB line costs {ratio:.1f}x the at-cap cost: "
        "the MAX_SCAN_CHARS cap was removed"
    )


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--child":
    sys.exit(_child_main(sys.argv[2], sys.argv[3]))
