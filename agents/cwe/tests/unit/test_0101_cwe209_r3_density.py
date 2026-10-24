"""Feature 0101 revision 3 -- every CWE-209 arm stays linear at worst-case site density (LLD 5.3.7 item 8).

One probe per arm, built so that EVERY routine in the file is a site of that
arm: W-helper (helpers that fill an object their callers send, two hops),
bare-call/helper (C1 and H on every handler), constructor/parameter (F through
a positional constructor), stream (S under a switch), key role (Y), X (a
projection helper whose definition renders its parameter) and return binding
(F with a persisted fill beside the returned one).

Measured through `_check_error_disclosure`, called per line exactly as
`_analyze_file` does, in a FRESH CHILD PROCESS with a hard timeout:

* the finding count is the arm's expected count at EVERY size and EVERY
  repetition -- a probe that stops reporting is a failed probe, not a fast one
  (the revision-2 module reports none of these sites, so there the probes are
  vacuous and fail here through the count);
* doubling the file costs < 2.6x (linear, not quadratic), each size's cost read as its ratio
  to the calibration workload times the growth in bytes, so load during one size cannot fake it;
* cost <= a HARD per-arm ceiling, expressed as a RATIO to a calibration workload
  (stdlib regex and dict work over the same lines, no rule code) timed in the
  same child, interleaved with the probe, round by round. Machine load slows
  both alike, so the ratio holds under a full-suite run where an absolute ms/KB
  ceiling did not (review round 2 saw `ctor` breach its absolute ceiling under
  load and pass three isolated reruns). The ceiling is the arm's measured
  ratio plus 25 %; exceeding it fails, so a regression is never hidden. The
  design budget is 0.5 ms per KB; every arm was measured over it when it was
  ported (every site of these probes is reported, and the revision-2 rule alone
  spends 0.06-0.46 ms/KB on the same text). Shipping over budget or deferring
  arms is a decision escalated to the user (E4). Until it is taken, an arm over
  the budget emits a warning that carries its measured absolute cost.

Every repetition uses identifiers no earlier one used, so each timing is cold:
neither the per-file caches nor the line-text caches carry work over.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import warnings
from pathlib import Path

import pytest

AGENT_ROOT = Path(__file__).resolve().parents[2]
UNITS = (256, 512, 1024)        # routines per probe file; each step doubles the file
ROUNDS = 3
BUDGET_MS_PER_KB = 0.5
# probe CPU time / calibration CPU time at 1024 routines (the minimum over the interleaved rounds of
# one child), measured in review round 2 as the highest of 5 fresh children run serially at load
# average 13-17 from other sessions. Their spread per arm was 2-10 % (wall-clock timing gave up to
# 60 %, so both sides are read as process CPU time, which preemption does not bend). The ceiling is
# measured + 25 %.
MEASURED_RATIO = {
    "bare": 5.01, "ctor": 6.21, "keyrole": 5.12, "retbind": 4.82, "stream": 4.81, "whelper": 3.41, "xhelper": 3.67,
}
CEILING_FACTOR = 1.25
CALIBRATION_PASSES = 4
_CAL_WORD = re.compile(r"[A-Za-z_$][\w$]{0,63}")
_CAL_CALL = re.compile(r"([A-Za-z_$][\w$.]{0,80})\s{0,2}\(")
MAX_DOUBLING_RATIO = 2.6
PROC_TIMEOUT_SEC = 300.0


def whelper(n: int, t: str) -> str:
    helpers = [f"function h{t}{k}(resp) {{\n  try {{ run{t}{k}(); }} catch (err) {{\n"
               f"    resp.error = `failed: ${{err.message}}`;\n  }}\n}}\n" for k in range(n)]
    routes = [f"export async function route{t}{k}(req, res) {{\n  const out = {{ ok: true }};\n  h{t}{k}(out);\n"
              f"  h{t}{(k + 1) % n}(out);\n  res.status(200).json(out);\n}}\n" for k in range(n)]
    return "".join(helpers + routes)


def bare(n: int, t: str) -> str:
    head = f"function sendJson{t}(res, status, body) {{ res.statusCode = status; res.end(JSON.stringify(body)); }}\n"
    return head + "".join(
        f"export async function r{t}{k}(req, res) {{\n  try {{ await go{t}{k}(); }} catch (err) {{ "
        f"sendJson{t}(res, 500, {{ error: String(err) }}); jsonError(res, 500, String(err)); }}\n}}\n" for k in range(n))


def ctor(n: int, t: str) -> str:
    head = f"class Outcome{t} {{ constructor(ok, error) {{ this.ok = ok; this.error = error; }} }}\n"
    return head + "".join(
        f"function load{t}{k}(id) {{ try {{ return new Outcome{t}(true); }} catch (e) "
        f"{{ return new Outcome{t}(false, e.message); }} }}\n"
        f"export function show{t}{k}(req, res) {{ const o = load{t}{k}(req.id); res.json({{ error: o.error }}); }}\n"
        for k in range(n))


def stream(n: int, t: str) -> str:
    return "".join(
        f"export async function c{t}{k}(req, res) {{\n  for await (const ev of s{t}{k}) {{\n    switch (ev.type) {{\n"
        f"      case 'text': res.write(ev.text); break;\n      case 'error': res.write(String(ev.error)); break;\n"
        f"    }}\n  }}\n}}\n" for k in range(n))


def keyrole(n: int, t: str) -> str:
    return "".join(
        f"export async function k{t}{k}(req, res) {{\n  const st = await getStatus{t}{k}(req.id);\n"
        f"  return res.json({{ state: st.state, ...(st.error ? {{ error: 'FAILED', message: st.error }} : {{}}) }});\n}}\n"
        for k in range(n))


def xhelper(n: int, t: str) -> str:
    head = (f"function formatFailure{t}(value) {{ if (value instanceof Error) "
            f"{{ return `${{value.name}}: ${{value.message}}`; }} return String(value); }}\n")
    return head + "".join(
        f"export async function x{t}{k}(req, res) {{\n  try {{ await go{t}{k}(); }} catch (err) "
        f"{{ return res.status(500).json({{ error: formatFailure{t}(err) }}); }}\n}}\n" for k in range(n))


def retbind(n: int, t: str) -> str:
    return "".join(
        f"async function run{t}{k}(id) {{\n  try {{\n    await work{t}{k}(id);\n    return {{ ok: true }};\n"
        f"  }} catch (e) {{\n    await db.jobs.update({{ data: {{ error: e.message }} }});\n"
        f"    return {{ ok: false, error: e.message }};\n  }}\n}}\n"
        f"export async function h{t}{k}(req, res) {{\n  const r = await run{t}{k}(req.id);\n"
        f"  if (!r.ok) return res.status(500).json({{ error: r.error }});\n}}\n" for k in range(n))


# probe -> (builder, reported rows per routine unit): every unit is one site of the arm
PROBES = {
    "whelper": (whelper, 1), "bare": (bare, 1), "ctor": (ctor, 1), "stream": (stream, 1),
    "keyrole": (keyrole, 1), "xhelper": (xhelper, 1), "retbind": (retbind, 1),
}


def _calibrate(lines: list[str]) -> float:
    """Seconds for a fixed stdlib workload over ``lines`` (regex scans and dict updates, the
    operations the rule is made of, none of its code): the yardstick machine load bends too."""
    counts: dict[str, int] = {}
    start = time.process_time()
    for _ in range(CALIBRATION_PASSES):
        for line in lines:
            for word in _CAL_WORD.findall(line):
                counts[word] = counts.get(word, 0) + 1
            _CAL_CALL.findall(line.lower())
    return time.process_time() - start


def _time_once(lines: list[str]) -> tuple[float, int]:
    from cwe_agent.skills import info_exposure_check as iec

    path = Path("app/probe.ts")
    findings: list[dict] = []
    start = time.process_time()
    for n, line in enumerate(lines, 1):
        iec._check_error_disclosure(path, line, n, lines, findings)
    return time.process_time() - start, sum(f["category"] == "CWE-209" for f in findings)


def _child_main(kind: str, out_path: str) -> int:
    build = PROBES[kind][0]
    record: dict[str, dict] = {}
    for units in UNITS:
        sizes, times, counts, ratios = [], [], [], []
        for r in range(ROUNDS):
            text = build(units, f"r{r}u{units}")
            lines = text.splitlines()
            before = _calibrate(lines)
            secs, found = _time_once(lines)
            after = _calibrate(lines)
            sizes.append(len(text))
            times.append(secs)
            counts.append(found)
            ratios.append(secs / max((before + after) / 2, 1e-9))
        record[str(units)] = {"bytes": max(sizes), "seconds": min(times), "counts": counts, "ratio": min(ratios)}
    Path(out_path).write_text(json.dumps(record))
    return 0


def _measure(tmp_path: Path, kind: str) -> dict[int, dict]:
    out = tmp_path / f"density_{kind}.json"
    try:
        subprocess.run(
            [sys.executable, "-m", "tests.unit.test_0101_cwe209_r3_density", "--child", kind, str(out)],
            cwd=AGENT_ROOT, capture_output=True, text=True, timeout=PROC_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the {kind} density run did not finish within {PROC_TIMEOUT_SEC:.0f} s")
    assert out.exists(), "the measurement child wrote nothing"
    return {int(k): v for k, v in json.loads(out.read_text()).items()}


def test_probes_are_the_specified_shapes() -> None:
    for kind, (build, _) in PROBES.items():
        small, large = len(build(UNITS[0], "t")), len(build(UNITS[-1], "t"))
        assert 3.6 < large / small < 4.4, (kind, small, large)
    assert len(bare(UNITS[-1], "t")) / 1024 > 60


def _per_kb(data: dict[int, dict]) -> float:
    largest = data[UNITS[-1]]
    return largest["seconds"] * 1000 / (largest["bytes"] / 1024)


@pytest.mark.parametrize("kind", sorted(PROBES))
def test_arm_density(tmp_path: Path, kind: str) -> None:
    data = _measure(tmp_path, kind)
    _assert_every_site_reported(kind, data)
    _assert_linear(kind, data)
    _assert_within_ceiling(tmp_path, kind, data)
    per_kb = _per_kb(data)
    if per_kb > BUDGET_MS_PER_KB:
        warnings.warn(f"{kind}: {per_kb:.3f} ms/KB > {BUDGET_MS_PER_KB} ms/KB design budget (E4 pending)",
                      stacklevel=1)


def _assert_every_site_reported(kind: str, data: dict[int, dict]) -> None:
    per_unit = PROBES[kind][1]
    for units, rec in data.items():
        assert rec["counts"] == [units * per_unit] * ROUNDS, (kind, units, rec["counts"])


def _assert_linear(kind: str, data: dict[int, dict]) -> None:
    largest, middle = data[UNITS[-1]], data[UNITS[-2]]
    ratio = largest["ratio"] / max(middle["ratio"], 1e-9) * largest["bytes"] / middle["bytes"]
    assert ratio < MAX_DOUBLING_RATIO, f"{kind}: doubling ratio {ratio:.2f} ({data})"


def _assert_within_ceiling(tmp_path: Path, kind: str, data: dict[int, dict]) -> None:
    ceiling = MEASURED_RATIO[kind] * CEILING_FACTOR
    cost = data[UNITS[-1]]["ratio"]
    if cost > ceiling:
        # one fresh child before failing: a breach must repeat to count (the minimum of both is compared)
        cost = min(cost, _measure(tmp_path, kind)[UNITS[-1]]["ratio"])
    assert cost <= ceiling, (f"{kind}: {cost:.3f}x calibration exceeds its hard ceiling {ceiling:.3f}x "
                             f"({_per_kb(data):.3f} ms/KB)")


def test_every_arm_has_a_ceiling() -> None:
    assert set(MEASURED_RATIO) == set(PROBES)
    assert all(v > 0 for v in MEASURED_RATIO.values()), MEASURED_RATIO


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest; --child <kind> <out_path> is internal")
