"""Feature 0101 -- CWE-778 site-density gate (LLD 9.3, PERF-2/3/6/10).

The worst files of the RED performance review, rebuilt synthetically at three
sizes and timed through the rule's own entry point, ``check_insufficient_logging``,
in a child process: <= 0.5 ms/KB at the largest size and a doubling ratio < 2.6.

  huge_decl_py   70+ handlers under ONE ~400 KB declaration line (PERF-3: the
                 routine analysis is shared, never redone per handler)
  calls_py/java  a 200 KB `x(`-repeated BODY line (revision 1: 18 s, `_call_args`
                 walked it char by char; the argument span is now <= 400)
  ret_py/ts      a 450 KB ` return x` body line (PERF-6: `return` by search +
                 slice, not `return\\b.{0,2000}$` at every position)
  adv_ts         handlers with ten near-cap `typeof e, ...` lines each
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from shared.testing.timing import budget

AGENT_ROOT = Path(__file__).resolve().parents[2]
SIZES_KB = (120, 240, 480)  # 480 KB: under the 512 KB per-file read cap
MAX_MS_PER_KB = budget(0.5)
MAX_DOUBLING_RATIO = 2.6
CHILD_TIMEOUT_SEC = 120.0
ROUNDS = 5


def _fill(prefix: str, unit: str, suffix: str, size: int) -> str:
    n = max(0, size - len(prefix) - len(suffix))
    return prefix + (unit * (n // len(unit) + 1))[:n] + suffix


def _huge_decl_py(size: int) -> str:
    handlers = "".join(f"    try:\n        do_thing{i}()\n    except ValueError as e:\n        errors.append(e)\n"
                       for i in range(70))
    decl = _fill("def f(", "a=b(c), ", "):\n", size - len(handlers) - 1)
    return decl + handlers


def _calls(prefix: str, suffix: str) -> Callable[[int], str]:
    return lambda size: _fill(prefix, "x(", suffix, size)


def _adv_ts(size: int) -> str:
    near_cap = "      " + ("typeof e, " * 199)[:1990] + "\n"
    handler = "  try {\n    g();\n  } catch (e) {\n    report([\n" + near_cap * 10 + "    ]);\n  }\n"
    count = max(1, (size - 40) // len(handler))
    return "function f() {\n" + handler * count + "}\n"


SHAPES: dict[str, tuple[str, Callable[[int], str]]] = {
    "huge_decl_py": ("huge_decl.py", _huge_decl_py),
    "calls_py": ("calls.py", _calls("def f():\n    try:\n        g()\n    except ValueError as e:\n        ", "\n")),
    "calls_java": ("Calls.java", _calls("class C { void f() {\n  try {\n    g();\n  } catch (Exception e) {\n    ",
                                        "\n  }\n} }\n")),
    "ret_py": ("ret.py", lambda size: _fill("def f():\n    try:\n        g()\n    except ValueError as e:\n"
                                            "        x = 1;", " return x", "\n", size)),
    "ret_ts": ("ret.ts", lambda size: _fill("function f() {\n  try {\n    g();\n  } catch (e) {\n    ",
                                            " return x", "\n  }\n}\n", size)),
    "adv_ts": ("adv.ts", _adv_ts),
}


def _time_scan(root: Path) -> float:
    from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging

    check_insufficient_logging(str(root))  # warm: imports, caches of an unrelated file
    best = float("inf")
    for _ in range(ROUNDS):
        start = time.perf_counter()
        check_insufficient_logging(str(root))
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def _child(shape: str, out_path: str) -> int:
    name, build = SHAPES[shape]
    with open(out_path, "w", encoding="utf-8") as handle:
        for kb in SIZES_KB:
            work = Path(tempfile.mkdtemp(prefix="dens778_"))
            try:
                (work / "app").mkdir()
                (work / "app" / name).write_text(build(kb * 1024))
                handle.write(json.dumps({"kb": kb, "ms": _time_scan(work)}) + "\n")
                handle.flush()
            finally:
                shutil.rmtree(work, ignore_errors=True)
    return 0


def _spawn(shape: str, out: str) -> None:
    try:
        subprocess.run([sys.executable, "-m", "tests.unit.test_0101_cwe778_density", "--child", shape, out],
                       cwd=AGENT_ROOT, capture_output=True, text=True,
                       timeout=CHILD_TIMEOUT_SEC, check=False)
    except subprocess.TimeoutExpired:
        pass  # the sizes that finished are reported; a missing one fails the test


def _run(shape: str) -> dict[int, float]:
    fd, out = tempfile.mkstemp(prefix=f"dens778_{shape}_", suffix=".jsonl")
    os.close(fd)
    try:
        _spawn(shape, out)
        with open(out, encoding="utf-8") as handle:
            rows = [json.loads(r) for r in handle if r.strip()]
    finally:
        os.unlink(out)
    return {r["kb"]: r["ms"] for r in rows}


def _noisy_free_ratios(times: list[float]) -> list[float]:
    """Doubling ratios; a ratio is only meaningful above timer noise (5 ms)."""
    return [b / max(a, 1e-3) for a, b in zip(times, times[1:]) if b >= 5.0]


def _density_problems(ms: dict[int, float]) -> list[str]:
    if sorted(ms) != list(SIZES_KB):
        return [f"child did not finish every size within {CHILD_TIMEOUT_SEC}s: {ms}"]
    times = [ms[kb] for kb in SIZES_KB]
    per_kb = times[-1] / SIZES_KB[-1]
    ratio = max(_noisy_free_ratios(times), default=0.0)
    checks = ((per_kb <= MAX_MS_PER_KB, f"{per_kb:.3f} ms/KB at {SIZES_KB[-1]} KB ({times} ms)"),
              (ratio < MAX_DOUBLING_RATIO, f"doubling ratio {ratio:.2f} ({times} ms)"))
    return [msg for ok, msg in filter(lambda c: not c[0], checks)]


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_site_density_is_linear_and_cheap(shape: str) -> None:
    problems = _density_problems(_run(shape))
    assert not problems, f"{shape}: {problems}"


def test_the_shapes_have_their_sizes() -> None:
    for name, build in SHAPES.values():
        text = build(64 * 1024)
        assert 56 * 1024 <= len(text) <= 68 * 1024, (name, len(text))  # adv.ts: whole ~20 KB handlers


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest")
