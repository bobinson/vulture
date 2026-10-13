"""Feature 0101 (PERF-1, PERF-10) -- the CWE-209 resolver stays linear at worst-case site density.

The revision-1 design resolved every value token of a sink by scanning the
whole 30-line window with per-identifier regexes: O(tokens x window x width)
per sink. RED built the worst file under the per-line cap -- 40 sink lines of
about 1980 characters, each writing 259 distinct identifiers, every sink inside
the window of the ones before it -- and the check took 25.8 s on 79 KB. The
port bounds it by construction (LLD 9.2): each window line's binding facts are
computed once, an identifier's resolution is memoised per sink, and at most 32
distinct tokens per sink are resolved.

Measured through `_check_error_disclosure`, called per line exactly as
`_analyze_file` does, in a FRESH CHILD PROCESS with a hard timeout (a
regression here is a hang, not a slow test):

* cost <= 0.5 ms per KB of file at 40 sinks;
* doubling the number of sinks costs < 2.6x (linear, not quadratic).

Every run uses identifiers no earlier run used, so each timing is cold: the
per-file caches cannot carry work over from a smaller run into a larger one.

The ``marked`` variant (RED round 2) opens the routine with a catch binding,
so every sink has an error marker in reach and the resolver's full path is
measured, not a shortcut a file without error vocabulary may take.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

AGENT_ROOT = Path(__file__).resolve().parents[2]
SINKS = (20, 40)
IDS_PER_SINK = 259
LINE_CAP = 1980          # just under MAX_SCAN_CHARS (2000): the per-line guard never fires
BUDGET_MS_PER_KB = 0.5
MAX_DOUBLING_RATIO = 2.6
ROUNDS = 3
PROC_TIMEOUT_SEC = 120.0


def build_lines(sinks: int, tag: str, marked: bool = False) -> list[str]:
    """`many_ids.ts`: one routine, ``sinks`` near-cap response writes of distinct identifiers."""
    lines = ["function h(req, res) {"]
    if marked:
        lines.append(f"  try {{ run(req); }} catch (fault{tag}) {{ audit(fault{tag}); }}")
    for i in range(sinks):
        args = ", ".join(f"{tag}{i}_{k}" for k in range(IDS_PER_SINK))
        lines.append(f"  res.json({args})"[:LINE_CAP])
    lines.append("}")
    return lines


def _time_once(lines: list[str]) -> float:
    from cwe_agent.skills import info_exposure_check as iec

    path = Path("app/many_ids.ts")
    findings: list[dict] = []
    start = time.perf_counter()
    for n, line in enumerate(lines, 1):
        iec._check_error_disclosure(path, line, n, lines, findings)
    return time.perf_counter() - start


def _child_main(out_path: str, marked: bool = False) -> int:
    best: dict[int, float] = {}
    sizes: dict[int, int] = {}
    for r in range(ROUNDS):
        for n in SINKS:
            lines = build_lines(n, f"r{r}s{n}v", marked)
            sizes[n] = sum(len(x) + 1 for x in lines)
            best[n] = min(best.get(n, float("inf")), _time_once(lines))
    Path(out_path).write_text(json.dumps({"seconds": best, "bytes": sizes}))
    return 0


def _measure(tmp_path: Path, marked: bool = False) -> dict:
    out = tmp_path / "density.json"
    flag = ["--marked"] if marked else []
    try:
        subprocess.run(
            [sys.executable, "-m", "tests.unit.test_0101_cwe209_density", "--child", str(out), *flag],
            cwd=AGENT_ROOT, capture_output=True, text=True, timeout=PROC_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the density run did not finish within {PROC_TIMEOUT_SEC:.0f} s")
    assert out.exists(), "the measurement child wrote nothing"
    return _read_measurement(out)


def _read_measurement(out: Path) -> dict:
    """The child's record, its sink counts read back as integers."""
    data = json.loads(out.read_text())
    return {"seconds": {int(k): v for k, v in data["seconds"].items()},
            "bytes": {int(k): v for k, v in data["bytes"].items()}}


def test_shape_is_the_red_probe() -> None:
    lines = build_lines(40, "v")
    assert len(lines) == 42
    assert all(len(x) <= LINE_CAP for x in lines)
    assert sum(len(x) + 1 for x in lines) / 1024 > 75   # RED's file was 79 KB


@pytest.mark.parametrize("marked", [False, True], ids=["plain", "marked"])
def test_cost_per_kb_and_doubling_ratio(tmp_path: Path, marked: bool) -> None:
    data = _measure(tmp_path, marked)
    secs, size = data["seconds"], data["bytes"]
    per_kb = secs[SINKS[-1]] * 1000 / (size[SINKS[-1]] / 1024)
    ratio = secs[SINKS[1]] / max(secs[SINKS[0]], 1e-6)
    assert per_kb <= BUDGET_MS_PER_KB, f"{per_kb:.3f} ms/KB at {SINKS[-1]} sinks ({secs})"
    assert ratio < MAX_DOUBLING_RATIO, f"doubling ratio {ratio:.2f} ({secs})"


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3:] == ["--marked"]))
    raise SystemExit("run under pytest; --child <out_path> [--marked] is internal")
