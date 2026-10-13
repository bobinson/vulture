"""Feature 0101 (RED R209-I2) -- CWE-209 stays linear when ONE line holds many sinks.

`test_0101_cwe209_density.py` builds one response write per line, so it never
exercised the per-line sink loop. RED built lines of up to ~1990 characters
holding dozens of response writes (`r.send(oN.pJ ` repeated, unclosed, or
`r.send(oN.pJ); ` repeated, closed). Every sink re-read the whole rest of the
line (and up to 12 continuation lines) as its argument text, so the cost was
quadratic in the sinks per line: 51 ms/KB unclosed, 4.1 ms/KB closed, against
a 0.5 ms/KB budget. At the 512 KB file cap that is ~35 s per file for one check.

Real code is nowhere near this: measured over four multi-language trees, 7,469
lines hold one response write, 35 hold two, and one minified line holds four.

Measured through `_check_error_disclosure`, called per line exactly as
`_analyze_file` does, in a FRESH CHILD PROCESS with a hard timeout, for every
shape:

* cost <= 0.5 ms per KB of file at 40 lines;
* doubling the number of lines costs < 2.6x (linear, not quadratic).

The ``narrow_open`` shapes are the same open calls on 40- and 300-character
lines, as many bytes as the near-cap shapes, so a line's last open call reading
on into the following lines is measured too.

The ``prefixed`` shapes put ~1300 characters of expression BEFORE the sinks, so
each sink's same-line prefix (binding row 0 and the receiver read) is long too.
Every run uses identifiers no earlier run used, so each timing is cold.

RED round 2 (R209-R2-1) measured the per-SINK cost on short, CLOSED lines,
which none of the shapes above isolate: `tiny` (`r.send(qN)` per line) 1.80
ms/KB against HEAD's 0.23, `tsreal` (an assignment of a service result, then a
`.json({...})` of six fields) 1.10-1.22 ms/KB against 0.12, `sameid` (the same
three names re-assigned on every line) 2.2 ms/KB against 0.18. They are the
``PER_LINE`` shapes below, built to as many bytes as the near-cap shapes. The
``_marked`` variants put an error marker (a catch binding) in reach of every
sink, so the resolver's full path is measured too, not only a shortcut that a
file without any error vocabulary can take; ``catchy`` reports every sink.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

AGENT_ROOT = Path(__file__).resolve().parents[2]
LINES = (20, 40)
WIDTH = 1990             # just under MAX_SCAN_CHARS (2000): the per-line guard never fires
BUDGET_MS_PER_KB = 0.5
MAX_DOUBLING_RATIO = 2.6
ROUNDS = 3
PROC_TIMEOUT_SEC = 240.0


def _filler(tag: str) -> str:
    return (f"x{tag} = " + "+".join(f"v{tag}_{k}" for k in range(300)))[:1300]


def _unclosed(tag: str) -> str:
    return "".join(f"r.send(o{tag}.p{j} " for j in range(400))


def _closed(tag: str) -> str:
    return "".join(f"r.send(o{tag}.p{j}); " for j in range(400))


def _prefixed(tag: str) -> str:
    return _filler(tag) + "".join(f"; r.send(e{tag}.p{j})" for j in range(40))


def _prefixed_open(tag: str) -> str:
    return _filler(tag) + "".join(f" r.send(e{tag}.p{j}" for j in range(40))


SHAPES = {"unclosed": _unclosed, "closed": _closed, "prefixed": _prefixed,
          "prefixed_open": _prefixed_open, "narrow_open_40": _unclosed, "narrow_open_300": _unclosed}


def _tiny(tag: str, i: int) -> str:
    return f"r.send(q{tag}_{i})"


def _tsreal(tag: str, i: int) -> str:
    if i % 2 == 0:
        return f"  const r{tag}_{i} = await svc.load{i}(req.body.id, user);"
    return f"  res.status(200).json({{ ok: true, data: r{tag}_{i - 1}, user, count, page, total }});"


def _sameid(tag: str, i: int) -> str:
    x, y, z = f"x{tag}", f"y{tag}", f"z{tag}"
    return f"{x} = {y}({z}); {y} = {z}({x}); {z} = {x}({y});" if i % 3 else f"res.json({{{x}, {y}, {z}}})"


def _marked(shape):
    """``shape`` with a catch binding every 40 lines: every sink has an error marker in reach."""
    def build(tag: str, i: int) -> str:
        return f"  }} catch (fault{tag}_{i}) {{" if i % 40 == 0 else shape(tag, i)
    return build


def _catchy(tag: str, i: int) -> str:
    """RED's `catchy`: a catch binding, then a sink writing its detail -- every sink reports."""
    q = f"q{tag}_"
    if i % 2:
        return f"}} catch ({q}{i}) {{"
    return f"res.json({{m: {q}{i - 1}.message, s: String({q}{i - 3}), r: {q}{i - 5}}})"


def _calls(tag: str, i: int) -> str:
    """RED's `calls`: ten nested calls around a bare `e` (a marker) on every line."""
    return "res.json(" + "".join(f"f{tag}_{i}_{k}(" for k in range(10)) + "e" + ")" * 10 + ")"


# One short sink per line (or every other line): the per-sink cost, closed calls.
PER_LINE = {"tiny": _tiny, "tsreal": _tsreal, "sameid": _sameid,
            "tiny_marked": _marked(_tiny), "tsreal_marked": _marked(_tsreal),
            "sameid_marked": _marked(_sameid), "catchy": _catchy, "calls": _calls}
SHAPES.update(dict.fromkeys(PER_LINE))
# Narrow shapes: the same open calls on short lines, as many lines as the
# near-cap shapes' bytes. Every line ends inside an open call, so its last sink
# reads on into the next lines; that read must stop at the next line's own sink,
# or a 40-character line carries ~2000 characters of analysis (RED R209-I2
# follow-up: 3.45 ms/KB at width 40, HEAD 0.20).
NARROW = {"narrow_open_40": 40, "narrow_open_300": 300}


def _build_per_line(shape: str, lines: int, tag: str) -> list[str]:
    """As many bytes as ``lines`` near-cap lines, one generated line at a time."""
    out: list[str] = []
    size = 0
    while size < lines * WIDTH:
        out.append(PER_LINE[shape](tag, len(out)))
        size += len(out[-1]) + 1
    return out


def build_lines(shape: str, lines: int, tag: str) -> list[str]:
    if shape in PER_LINE:
        return _build_per_line(shape, lines, tag)
    width = NARROW.get(shape, WIDTH)
    count = lines * WIDTH // width
    return [SHAPES[shape](f"{tag}{i}")[:width] for i in range(count)]


def _time_once(lines: list[str]) -> float:
    from cwe_agent.skills import info_exposure_check as iec

    path = Path("app/many_sinks.ts")
    findings: list[dict] = []
    start = time.perf_counter()
    for n, line in enumerate(lines, 1):
        iec._check_error_disclosure(path, line, n, lines, findings)
    return time.perf_counter() - start


def _child_main(shape: str, out_path: str) -> int:
    best: dict[int, float] = {}
    sizes: dict[int, int] = {}
    for r in range(ROUNDS):
        for n in LINES:
            lines = build_lines(shape, n, f"r{r}n{n}v")
            sizes[n] = sum(len(x) + 1 for x in lines)
            best[n] = min(best.get(n, float("inf")), _time_once(lines))
    Path(out_path).write_text(json.dumps({"seconds": best, "bytes": sizes}))
    return 0


def _measure(shape: str, tmp_path: Path) -> tuple[dict[int, float], dict[int, int]]:
    out = tmp_path / f"{shape}.json"
    try:
        subprocess.run(
            [sys.executable, "-m", "tests.unit.test_0101_cwe209_sinks_per_line", "--child", shape, str(out)],
            cwd=AGENT_ROOT, capture_output=True, text=True, timeout=PROC_TIMEOUT_SEC, check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"the {shape} run did not finish within {PROC_TIMEOUT_SEC:.0f} s")
    assert out.exists(), "the measurement child wrote nothing"
    return _read_measurement(out)


def _read_measurement(out: Path) -> tuple[dict[int, float], dict[int, int]]:
    """The child's (seconds, bytes) record, its line counts read back as integers."""
    data = json.loads(out.read_text())
    return ({int(k): v for k, v in data["seconds"].items()},
            {int(k): v for k, v in data["bytes"].items()})


def _assert_near_cap(lines: list[str]) -> None:
    assert all(len(x) <= WIDTH for x in lines)
    assert sum(len(x) + 1 for x in lines) / 1024 > 70


def _assert_sink_every_third_line(lines: list[str]) -> None:
    from cwe_agent.skills import info_exposure_check as iec

    assert sum(bool(iec._RESPONSE_WRITE.search(x)) for x in lines) * 3 >= len(lines) * 0.9


def _assert_sinks_per_line(lines: list[str], per_line: int) -> None:
    from cwe_agent.skills import info_exposure_check as iec

    assert min(len(iec._RESPONSE_WRITE.findall(x)) for x in lines) >= per_line


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_shape_is_near_cap_and_dense(shape: str) -> None:
    lines = build_lines(shape, 40, "v")
    _assert_near_cap(lines)
    if shape in PER_LINE:   # a sink on at least every third line
        _assert_sink_every_third_line(lines)
        return
    per_line = 1 if shape in NARROW else 30   # many sinks per line; every narrow line has one
    _assert_sinks_per_line(lines, per_line)


_MEASURED: dict[str, tuple[float, float]] = {}


def _cost(shape: str, tmp_path: Path) -> tuple[float, float]:
    """(ms per KB at the larger size, doubling ratio), measured once per shape."""
    if shape not in _MEASURED:
        secs, size = _measure(shape, tmp_path)
        per_kb = secs[LINES[-1]] * 1000 / (size[LINES[-1]] / 1024)
        _MEASURED[shape] = (per_kb, secs[LINES[1]] / max(secs[LINES[0]], 1e-6))
    return _MEASURED[shape]


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_doubling_ratio(shape: str, tmp_path: Path) -> None:
    _, ratio = _cost(shape, tmp_path)
    assert ratio < MAX_DOUBLING_RATIO, f"{shape}: doubling ratio {ratio:.2f}"


# Every shape, the per-sink full-path shapes included. `catchy` (every sink
# REPORTS, so finding construction is included), `tsreal_marked` and `calls`
# (ten nested calls) put a marker in reach of every sink AND a name bound on a
# marked row, so the resolver runs its full path on every one; they were pinned
# as a strict xfail (0.64-0.78 ms/KB against HEAD's 0.10-0.15) until the
# resolver stopped paying for names nothing in the window can bind.
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_cost_per_kb(shape: str, tmp_path: Path) -> None:
    per_kb, _ = _cost(shape, tmp_path)
    assert per_kb <= BUDGET_MS_PER_KB, f"{shape}: {per_kb:.3f} ms/KB at {LINES[-1]} lines"


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest; --child <shape> <out_path> is internal")
