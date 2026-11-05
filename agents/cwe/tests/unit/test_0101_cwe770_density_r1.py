"""Feature 0101 -- CWE-770 density gate, round-1 implementation review shapes.

The first density gate (``test_0101_cwe770_density``) reuses ONE accumulator
name in every probe, so analyses keyed per (loop, accumulator) were shared by
every site and their cost never showed. The implementation review measured
three shapes that the gate missed:

``distinct.py``  77 DISTINCT accumulators under one driven loop, each site line
                 padded with a near-cap identifier (41.4 ms/KB measured: the
                 running-total scan of the loop body ran once per accumulator).
``selfgrow.py``  no loop at all; lines of one long dotted chain grown with
                 ``+=`` (5.4 ms/KB: the self-growth pattern backtracked over the
                 chain at every start position, on every prefiltered line).
``cmp.py``       near-cap comparison rows with distinct accumulators (2.6 ms/KB).
``eq.py``        lines of many short ``a=b,`` assignments under a driven loop:
                 every ``=`` is a candidate operator for the self-growth read.

Same method and budget as the first gate: ``_check_unbounded_alloc`` per line,
every cache cleared before each timed pass, <= 0.5 ms per KB, doubling < 2.6x.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.unit import test_0101_cwe770_density as gate

ROW_BUDGET = 240_000


def _fill(rows: list[str], header: list[str], body, scale: int) -> list[str]:
    loop = 0
    while sum(len(r) + 1 for r in rows) < ROW_BUDGET * scale:
        rows += [line.format(k=loop) for line in header]
        rows += body(loop)
        loop += 1
    return rows


_DRIVEN = ["def f{k}(sock):", "    while True:", "        d = sock.recv(4096)"]


def _distinct_py(scale: int) -> tuple[str, str]:
    def body(_loop: int) -> list[str]:
        return [f"        acc{i}.append(d); {'a' * 1900} = 1" for i in range(77)]
    return "distinct.py", "\n".join(_fill([], _DRIVEN, body, scale)) + "\n"


def _selfgrow_py(scale: int) -> tuple[str, str]:
    chain = ".".join(["a" * 60] * 31)
    rows = ["def f():"]
    while sum(len(r) + 1 for r in rows) < ROW_BUDGET * scale:
        rows.append(f"    {chain} += q")
    return "selfgrow.py", "\n".join(rows) + "\n"


def _cmp_py(scale: int) -> tuple[str, str]:
    def body(_loop: int) -> list[str]:
        return [f"        acc{i}.append(d); z = " + " < ".join([f"len(acc{i})"] + ["q"] * 300)
                for i in range(77)]
    return "cmp.py", "\n".join(_fill([], _DRIVEN, body, scale)) + "\n"


def _eq_py(scale: int) -> tuple[str, str]:
    def body(_loop: int) -> list[str]:
        return [f"        acc{i}.append(d); " + ", ".join(["a=b"] * 400) for i in range(77)]
    return "eq.py", "\n".join(_fill([], _DRIVEN, body, scale)) + "\n"


PROBES = {
    "distinct.py": _distinct_py,
    "selfgrow.py": _selfgrow_py,
    "cmp.py": _cmp_py,
    "eq.py": _eq_py,
}


def _child_main(probe: str, out_path: str) -> int:
    gate.PROBES.update(PROBES)
    return gate._child_main(probe, out_path)


def _run_child(probe: str) -> dict[int, dict]:
    import json
    import os
    import subprocess
    import tempfile

    fd, out_path = tempfile.mkstemp(prefix="density0101_770r1_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run(
                [sys.executable, "-m", "tests.unit.test_0101_cwe770_density_r1", "--child", probe, out_path],
                cwd=gate.AGENT_ROOT, capture_output=True, text=True,
                timeout=gate.PROC_TIMEOUT_SEC * 5, check=False,
            )
        except subprocess.TimeoutExpired:
            pass
        with open(out_path, encoding="utf-8") as handle:
            return {r["scale"]: r for r in map(json.loads, filter(None, map(str.strip, handle)))}
    finally:
        os.unlink(out_path)


@pytest.mark.parametrize("probe", sorted(PROBES))
def test_review_probe_is_linear_and_within_budget(probe: str) -> None:
    runs = _run_child(probe)
    assert set(runs) == {1, 2}, f"{probe}: the child did not finish (got scales {sorted(runs)})"
    per_kb = gate._per_kb(runs)
    ratio = runs[2]["ms"] / max(runs[1]["ms"], 1e-6)
    assert max(per_kb.values()) <= gate.BUDGET_MS_PER_KB, f"{probe}: {per_kb} ms/KB"
    assert ratio < gate.MAX_DOUBLING_RATIO, f"{probe}: doubling ratio {ratio:.2f} ({runs})"


def test_review_probes_keep_their_shape() -> None:
    """Distinct accumulators per loop, and a prefiltered no-loop line, at the RED sizes."""
    for probe, build in PROBES.items():
        _, text = build(1)
        assert 100 <= len(text) / 1024 <= 512, probe
    _, distinct = _distinct_py(1)
    assert len({f"acc{i}." for i in range(77) if f"acc{i}.append" in distinct}) == 77
    _, grow = _selfgrow_py(1)
    assert "while" not in grow and "for " not in grow and " += " in grow


def test_review_probe_verdicts_are_stable() -> None:
    """The probes still exercise the decision: driven sites report, the loopless file does not."""
    from cwe_agent.skills import resource_check as rc

    for build, expect_rows in ((_selfgrow_py, False), (_distinct_py, True)):
        name, text = build(1)
        lines = text.split("\n")[:400]
        out: list[dict] = []
        for n, line in enumerate(lines, 1):
            rc._check_unbounded_alloc(Path(name), line, n, lines, out)
        assert bool(out) is expect_rows, name


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--child":
    sys.exit(_child_main(sys.argv[2], sys.argv[3]))
