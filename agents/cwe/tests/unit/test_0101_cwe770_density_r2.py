"""Feature 0101 -- CWE-770 density gate, round-2 implementation review shapes.

The round-1 gates use long identifiers and few distinct names. The round-2
review measured shapes they miss (same method: ``_check_unbounded_alloc`` per
line, every cache cleared before each timed pass):

``seg1.py`` / ``seg2.py`` / ``segsub.py``
    near-cap chains of 1- and 2-character segments (``a.a.a.``) ending in a
    self-growth operator, under a driven loop. Every other character is an
    identifier boundary, so a receiver read tried at each boundary measured
    3.7 ms/KB (R770-R2-1).
``names_many.py``
    dense short lines, 20 sites per driven loop, more than 4096 DISTINCT
    accumulator names (more than the per-name pattern cache): 19 ms/KB measured
    while each name cost ~8 regex compiles (R770-R2-2).
``names_50.py``
    the same shape with 50 names repeated: 2.2 ms/KB measured, from per-site
    scans of the whole loop body for trims and resets.
``names_script.py``
    no routine header at all (every site reads a 120-line window), one distinct
    name per site: 25 ms/KB measured.

Budget as the first gate: <= 0.5 ms per KB, doubling < 2.6x.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.unit import test_0101_cwe770_density as gate

ROW_BUDGET = 240_000
_DRIVEN = ["def f(sock):", "    while True:", "        d = sock.recv(1)"]


def _cap() -> int:
    from cwe_agent.skills._lexical import MAX_SCAN_CHARS

    return MAX_SCAN_CHARS


def _segments(name: str, segment: str, tail: str):
    def build(scale: int) -> tuple[str, str]:
        line = "        " + (segment * _cap())[:_cap() - 20] + tail
        rows, i = list(_DRIVEN), 0
        while sum(len(r) + 1 for r in rows) < ROW_BUDGET * scale:
            rows.append(line)
            i += 1
            if i % 70 == 0:
                rows += _DRIVEN
        return name, "\n".join(rows) + "\n"
    return build


def _names(name: str, distinct: int, header: bool):
    def build(scale: int) -> tuple[str, str]:
        rows, i = [], 0
        lead = _DRIVEN if header else ["while True:", "    d = sock.recv(1)"]
        pad = "        " if header else "    "
        while sum(len(r) + 1 for r in rows) < ROW_BUDGET * scale:
            rows += lead
            for _ in range(20 if header else 70):
                rows.append(f"{pad}a{i % distinct}.append(d)")
                i += 1
        return name, "\n".join(rows) + "\n"
    return build


PROBES = {
    "seg1.py": _segments("seg1.py", "a.", "x += q"),
    "seg2.py": _segments("seg2.py", "ab.", "x << q"),
    "segsub.py": _segments("segsub.py", "a.", "x[] = q"),
    "names_many.py": _names("names_many.py", 100_000, header=True),
    "names_50.py": _names("names_50.py", 50, header=True),
    "names_script.py": _names("names_script.py", 1_000_000, header=False),
}


def _child_main(probe: str, out_path: str) -> int:
    gate.PROBES.update(PROBES)
    return gate._child_main(probe, out_path)


def _run_child(probe: str) -> dict[int, dict]:
    import json
    import os
    import subprocess
    import tempfile

    fd, out_path = tempfile.mkstemp(prefix="density0101_770r2_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run(
                [sys.executable, "-m", "tests.unit.test_0101_cwe770_density_r2", "--child", probe, out_path],
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
def test_review_r2_probe_is_linear_and_within_budget(probe: str) -> None:
    runs = _run_child(probe)
    assert set(runs) == {1, 2}, f"{probe}: the child did not finish (got scales {sorted(runs)})"
    per_kb = gate._per_kb(runs)
    ratio = runs[2]["ms"] / max(runs[1]["ms"], 1e-6)
    assert max(per_kb.values()) <= gate.BUDGET_MS_PER_KB, f"{probe}: {per_kb} ms/KB"
    assert ratio < gate.MAX_DOUBLING_RATIO, f"{probe}: doubling ratio {ratio:.2f} ({runs})"


def _assert_probe_sizes() -> None:
    for probe, build in PROBES.items():
        _, text = build(1)
        assert 100 <= len(text) / 1024 <= 512, probe


def _distinct_accumulators(text: str) -> int:
    return len({line.split(".")[0] for line in text.split("\n") if ".append(" in line})


def _assert_probe_features() -> None:
    _, many = PROBES["names_many.py"](1)
    assert _distinct_accumulators(many) > 4096
    _, script = PROBES["names_script.py"](1)
    assert "def " not in script
    _, seg = PROBES["seg1.py"](1)
    assert max(map(len, seg.split("\n"))) >= _cap() - 20


def test_review_r2_probes_keep_their_shape() -> None:
    _assert_probe_sizes()
    _assert_probe_features()


def test_review_r2_probe_verdicts_are_stable() -> None:
    """The probes exercise the decision: their sites are driven, uncapped and reported."""
    from cwe_agent.skills import resource_check as rc

    for probe in ("names_many.py", "names_50.py", "names_script.py", "seg2.py", "segsub.py"):
        name, text = PROBES[probe](1)
        lines = text.split("\n")[:200]
        out: list[dict] = []
        for n, line in enumerate(lines, 1):
            rc._check_unbounded_alloc(Path(name), line, n, lines, out)
        assert out, probe


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--child":
    sys.exit(_child_main(sys.argv[2], sys.argv[3]))
