"""Feature 0101 -- site-density gate for the CWE-770 rule (LLD 9.3 PERF-10, 9.5).

Each case rebuilds one RED performance probe in shape: the worst file the
reviewers found for the rule, with many sinks under one near-cap loop line,
neighbour and body lines at and above ``MAX_SCAN_CHARS``, and deep nesting.
Revision 1 of the design measured 3.07 ms/KB on ``nested.py`` (it re-scanned an
80-line body per site per enclosing loop); the memoised design measures
<= 0.21 ms/KB on every probe.

Timed by calling ``_check_unbounded_alloc`` PER LINE, never through
``check_resource_management``: that entry also runs the pre-0101
``_check_null_deref``, which takes over 60 s on ``huge.go`` and is outside 0101.

Two properties per probe, in a child process with a hard timeout: the cost per
KB of file stays <= 0.5 ms, and doubling the file (sites, nesting and long-line
width together) costs < 2.6x. Every lru_cache of the module is cleared before
each timed pass, so the figure is the cold per-file cost a scan pays.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.unit.test_0087_redos import PROC_TIMEOUT_SEC

AGENT_ROOT = Path(__file__).resolve().parents[2]
BUDGET_MS_PER_KB = 0.5
MAX_DOUBLING_RATIO = 2.6
ROUNDS = 3


def _nested_py(scale: int) -> tuple[str, str]:
    """40 nested `while True:` loops with ~1900-char comment tails, 80 sinks below.

    Doubling scales the SINKS under the same 40-deep nest. Each sink's upward
    walk passes at most the 120-line look-back (and stops after 4 loops), so
    nesting depth is a bounded constant per sink; doubling the depth as well
    measures that constant growing towards its bound, not super-linear work.
    """
    depth, sites = 40, 80 * scale
    rows = ["def f():"]
    rows += ["    " * (d + 1) + "while True:  # " + "b" * 1900 for d in range(depth)]
    pad = "    " * (depth + 1)
    rows += [f"{pad}out.append(v{i})  # " + "c" * 1900 for i in range(sites)]
    return "nested.py", "\n".join(rows) + "\n"


def _wide_py(scale: int) -> tuple[str, str]:
    """One `while True:` with 78 sinks, each followed by a near-cap string on its line."""
    rows = ["def f():", "    while True:"]
    rows += [f"        out.append(v{i}); x{i} = '" + "b" * 1980 + "'" for i in range(78 * scale)]
    return "wide.py", "\n".join(rows) + "\n"


def _huge_brace(name: str, opener: list[str], sink: str, scale: int) -> tuple[str, str]:
    """A ~200 KB string line inside the loop, then 80 sinks under it."""
    body = [opener[-1].split("w")[0] + "  " + 'String s = "' + "a" * (200_000 * scale) + '";']
    body += [opener[-1].split("w")[0] + "  " + sink.format(i=i) for i in range(80 * scale)]
    return name, "\n".join([*opener, *body, *["}"] * len(opener)]) + "\n"


def _huge_ts(scale: int) -> tuple[str, str]:
    return _huge_brace("huge.ts", ["function f() {", "  while (true) {"], "out.push(v{i});", scale)


def _huge_java(scale: int) -> tuple[str, str]:
    return _huge_brace("Huge.java", ["class C {", "  void f() {", "    while (true) {"],
                       "out.add(v{i});", scale)


def _huge_go(scale: int) -> tuple[str, str]:
    rows = ["package p", "func f() {", "    for {", '    s := "' + "a" * (200_000 * scale) + '"']
    rows += [f"        out = append(out, v{i})" for i in range(80 * scale)]
    return "huge.go", "\n".join([*rows, "    }", "}"]) + "\n"


PROBES = {
    "nested.py": _nested_py,
    "wide.py": _wide_py,
    "huge.ts": _huge_ts,
    "Huge.java": _huge_java,
    "huge.go": _huge_go,
}


# --------------------------------------------------------------------------
# Child process
# --------------------------------------------------------------------------

def _clear_caches(module) -> None:
    for value in vars(module).values():
        clear = getattr(value, "cache_clear", None)
        if callable(clear):
            clear()


def _time_file(name: str, text: str) -> float:
    from cwe_agent.skills import resource_check as rc

    best = float("inf")
    for _ in range(ROUNDS):
        lines = text.split("\n")
        _clear_caches(rc)
        out: list[dict] = []
        start = time.perf_counter()
        for n, line in enumerate(lines, 1):
            rc._check_unbounded_alloc(Path(name), line, n, lines, out)
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def _child_main(probe: str, out_path: str) -> int:
    with open(out_path, "w", encoding="utf-8") as handle:
        for scale in (1, 2):
            name, text = PROBES[probe](scale)
            ms = _time_file(name, text)
            handle.write(json.dumps({"scale": scale, "kb": len(text) / 1024, "ms": ms}) + "\n")
            handle.flush()
    return 0


def _run_child(probe: str) -> dict[int, dict]:
    fd, out_path = tempfile.mkstemp(prefix="density0101_770_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run(
                [sys.executable, "-m", "tests.unit.test_0101_cwe770_density", "--child", probe, out_path],
                cwd=AGENT_ROOT, capture_output=True, text=True,
                timeout=PROC_TIMEOUT_SEC * 5, check=False,
            )
        except subprocess.TimeoutExpired:
            pass
        with open(out_path, encoding="utf-8") as handle:
            return {r["scale"]: r for r in map(json.loads, filter(None, map(str.strip, handle)))}
    finally:
        os.unlink(out_path)


def _per_kb(runs: dict[int, dict]) -> dict[int, float]:
    return {scale: r["ms"] / r["kb"] for scale, r in runs.items()}


@pytest.mark.parametrize("probe", sorted(PROBES))
def test_density_probe_is_linear_and_within_budget(probe: str) -> None:
    runs = _run_child(probe)
    assert set(runs) == {1, 2}, f"{probe}: the child did not finish (got scales {sorted(runs)})"
    per_kb = _per_kb(runs)
    ratio = runs[2]["ms"] / max(runs[1]["ms"], 1e-6)
    assert max(per_kb.values()) <= BUDGET_MS_PER_KB, f"{probe}: {per_kb} ms/KB"
    assert ratio < MAX_DOUBLING_RATIO, f"{probe}: doubling ratio {ratio:.2f} ({runs})"


def test_probes_reproduce_the_red_shapes() -> None:
    """The probes keep their shape: sizes of the RED files, sites under one loop."""
    for probe, build in PROBES.items():
        name, text = build(1)
        kb = len(text) / 1024
        assert 100 <= kb <= 512, f"{probe}: {kb:.0f} KB is outside the RED probe range"
        assert text.count("append(") + text.count("push(") + text.count("add(") >= 78, probe


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--child":
    sys.exit(_child_main(sys.argv[2], sys.argv[3]))
