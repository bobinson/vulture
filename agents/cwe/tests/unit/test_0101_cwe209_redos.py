"""Feature 0101 -- adversarial-input gate for the CWE-209 value section of `info_exposure_check`.

Every module-level pattern the 0101 CWE-209 section defines -- found by
introspection over the section's source span (the `# CWE-209 VALUE SECTION`
banners), never a hardcoded list, with a pinned floor -- must complete within
the 0087 per-KB budget (0.060 ms/KB) on 512 KB single-line inputs: the five
0087 inputs plus the keyword-repetition inputs of LLD 9.3. Measured in a fresh
child process with a hard timeout (the 0087 harness): a catastrophic `sre`
search is one uninterruptible C call, so only a process boundary bounds it.

The module's OTHER sections (CWE-532/200/550/...) predate 0101 and are out of
its scope; the section span keeps them out without a name list that could rot.

Seven patterns are linear but read a bounded identifier chain from EVERY start
position after a `.`, so `a.a.a.a...` costs ~2-8x the raw budget at 512 KB. They
are only ever applied to capped text -- a sink's argument text (at most
`MAX_SCAN_CHARS`) or the 160-character receiver window -- so, as LLD 9.3
prescribes, they are measured on the capped subject (`CAP_BOUND`), and the cap
itself is pinned by timing the value resolver's entry on every 512 KB input:
removing the cap turns that test red.
"""
from __future__ import annotations

import ast
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.unit import test_0101_lexical_redos as lexgate
from tests.unit.test_0087_redos import BUDGET_MS, INPUT_BYTES, PROC_TIMEOUT_SEC, _measure_one

MODULE = "cwe_agent.skills.info_exposure_check"
AGENT_ROOT = Path(__file__).resolve().parents[2]
BEGIN = "# CWE-209 VALUE SECTION (feature 0101)"
END = "# END OF THE CWE-209 VALUE SECTION"
# Pinned at the CURRENT count (RED R209-R2-7: the floor of 33 sat below the 37
# patterns the section then had, so four could vanish unnoticed). Round 2 adds
# `_MARKER`, `_COMMENT_START`, `_VARIANT_BINDING`, `_DECLARES` and `_HANDLER_WORD`.
# A pattern that moves out of the section, or a consolidation that drops one,
# turns this red instead of shrinking the gate; a deliberate removal lowers it.
# 43 -> 41: the parameter-list `_PARAMS` and `_PARAM_SPLIT` moved to `_lexical`
# (`paren_lists`, `param_name`), whose own gate, test_0101_lexical_redos.py,
# discovers and measures them there.
MIN_PATTERNS = 41
ENTRY = "<entry>"
INPUT_NAMES = lexgate.INPUT_NAMES
# Applied only to capped text (see the module docstring); measured on subject[:MAX_SCAN_CHARS].
CAP_BOUND = frozenset({
    "_DETAIL_CHAIN", "_INNER_CALL", "_METHOD_STRINGIFIER",   # a sink's capped argument text
    "_PM_CMP", "_PM_PRED", "_PM_TERN",                        # `_premask` of that text / an rhs
    "_RECEIVER_ROOT",                                         # the 160-character receiver window
})


def _banner_line(lines: list[str], banner: str) -> int | None:
    """1-based line number of the first line starting with ``banner``."""
    return next((i for i, x in enumerate(lines, 1) if x.startswith(banner)), None)


def _assigned_names(node: ast.stmt) -> set[str]:
    """Plain names a module-level assignment binds (none for any other statement)."""
    if not isinstance(node, ast.Assign):
        return set()
    return {t.id for t in node.targets if isinstance(t, ast.Name)}


def _section_names() -> set[str]:
    """Module-level names assigned between the section banners."""
    path = Path(importlib.import_module(MODULE).__file__)
    source = path.read_text(encoding="utf-8")
    span = _banner_span(source.splitlines())
    if span is None:
        return set()
    return set().union(*map(_assigned_names, _statements_between(source, *span)))


def _banner_span(lines: list[str]) -> tuple[int, int] | None:
    """(begin, end) banner line numbers, or None when either banner is missing."""
    begin, end = _banner_line(lines, BEGIN), _banner_line(lines, END)
    return None if begin is None or end is None else (begin, end)


def _statements_between(source: str, begin: int, end: int) -> list[ast.stmt]:
    """Module-level statements starting strictly between the two banner lines."""
    return [node for node in ast.parse(source).body if begin < node.lineno < end]


def discover_patterns() -> dict[str, re.Pattern[str]]:
    module = importlib.import_module(MODULE)
    section = _section_names()
    return {k: v for k, v in vars(module).items() if k in section and isinstance(v, re.Pattern)}


PATTERN_NAMES: tuple[str, ...] = tuple(sorted(discover_patterns()))


def _subject(name: str, input_name: str) -> str:
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS

    subject = lexgate.build_input(input_name)
    return subject[:MAX_SCAN_CHARS] if name in CAP_BOUND else subject


def _entry_child(emit) -> None:
    """Time the value resolver's entry on a 512 KB sink line per adversarial input."""
    from cwe_agent.skills import info_exposure_check as iec

    for input_name in INPUT_NAMES:
        for shape in ("res.json({})", "logger.error(x); res.json({})"):
            line = shape.format(lexgate.build_input(input_name))
            lines = ["function h(req, res) {", line]
            emit({"status": "start", "input": f"{input_name}|{shape}"})
            start = time.perf_counter()
            iec._response_discloses_error(lines, 2, iec._mask_log_calls(line), ".ts")
            emit({"status": "ok", "input": f"{input_name}|{shape}", "ms": (time.perf_counter() - start) * 1000})


def _child_main(name: str, out_path: str) -> int:
    pattern = discover_patterns().get(name)
    with open(out_path, "w", encoding="utf-8") as handle:
        def emit(record: dict) -> None:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if name == ENTRY:
            _entry_child(emit)
            return 0
        if pattern is None:
            emit({"status": "missing", "name": name})
            return 1
        for input_name in INPUT_NAMES:
            subject = _subject(name, input_name)
            emit({"status": "start", "input": input_name})
            emit({"status": "ok", "input": input_name, "ms": _measure_one(pattern, subject)})
    return 0


def _run_child(name: str) -> dict[str, float | None]:
    fd, out_path = tempfile.mkstemp(prefix=f"redos209_{name}_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run(
                [sys.executable, "-m", "tests.unit.test_0101_cwe209_redos", "--child", name, out_path],
                cwd=AGENT_ROOT, capture_output=True, text=True, timeout=PROC_TIMEOUT_SEC * 2, check=False,
            )
        except subprocess.TimeoutExpired:
            pass
        results: dict[str, float | None] = {}
        with open(out_path, encoding="utf-8") as handle:
            for raw in filter(None, map(str.strip, handle)):
                record = json.loads(raw)
                if record["status"] == "missing":
                    pytest.fail(f"{name!r} disappeared between collection and measurement")
                results[record["input"]] = record.get("ms")
    finally:
        os.unlink(out_path)
    return results


def test_section_discovery_is_not_vacuous() -> None:
    assert len(PATTERN_NAMES) >= MIN_PATTERNS, (
        f"{MODULE}: {len(PATTERN_NAMES)} patterns found between the CWE-209 section banners "
        f"({list(PATTERN_NAMES)}); the pinned floor is {MIN_PATTERNS}. Fix the discovery, do "
        "not lower the floor."
    )


def _inputs_over_budget(timings: dict[str, float | None]) -> dict[str, float | None]:
    """Every adversarial input whose timing is missing (did not complete) or over budget."""
    return {n: ms for n in INPUT_NAMES if (ms := timings.get(n)) is None or ms >= BUDGET_MS}


def _timings_over_budget(timings: dict[str, float | None]) -> dict[str, float | None]:
    """Every recorded timing that is missing (did not complete) or over budget."""
    return {n: ms for n, ms in timings.items() if ms is None or ms >= BUDGET_MS}


@pytest.mark.parametrize("pattern_name", PATTERN_NAMES)
def test_pattern_survives_adversarial_input(pattern_name: str) -> None:
    timings = _run_child(pattern_name)
    bad = _inputs_over_budget(timings)
    assert not bad, (
        f"{pattern_name}: budget {BUDGET_MS:.1f} ms per {INPUT_BYTES // 1024} KB; "
        f"over budget or did not complete (None): {bad}"
    )


def test_cap_bound_names_are_section_patterns() -> None:
    assert CAP_BOUND <= set(PATTERN_NAMES), sorted(CAP_BOUND - set(PATTERN_NAMES))


def test_the_value_resolver_caps_a_512kb_line() -> None:
    """Every adversarial 512 KB input inside a sink costs what a capped line costs."""
    timings = _run_child(ENTRY)
    assert len(timings) == 2 * len(INPUT_NAMES), sorted(timings)
    bad = _timings_over_budget(timings)
    assert not bad, f"entry over {BUDGET_MS:.1f} ms per {INPUT_BYTES // 1024} KB line: {bad}"


def test_the_section_caps_with_the_shared_constant() -> None:
    from cwe_agent.skills import _lexical
    from cwe_agent.skills import info_exposure_check as iec

    assert iec.MAX_SCAN_CHARS is _lexical.MAX_SCAN_CHARS
    assert iec.MAX_SCAN_CHARS == 2000


def test_a_huge_line_costs_what_a_capped_line_costs() -> None:
    """The entry caps its input: a 512 KB sink line is judged on its first 2000 characters."""
    from cwe_agent.skills import info_exposure_check as iec

    line = "res.json(" + ", ".join(f"v{i}" for i in range(INPUT_BYTES // 6)) + ")"
    lines = ["function h(req, res) {", line]
    assert not iec._discloses_error(Path("app/h.ts"), line, 2, lines)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest; --child <name> <out_path> is internal")
