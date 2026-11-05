"""Feature 0101 -- CWE-778 auth-dense density gate (RED round 2, R2-5; LLD 9.3/9.5).

Concept B's bracket scan looks at up to 40 code lines above every auth-candidate
line. Without a per-line summary it re-reads every one of those lines, so a file
of auth-candidate lines costs 40 x 2000 characters per line. Two shapes, timed
through ``check_insufficient_logging`` in a child process at three sizes, must stay
<= 0.5 ms/KB at the largest size with a doubling ratio < 2.6:

  closers   `x` + 1985 `)` + ` forbidden`, every line an auth candidate
  catalog   `k<i>: [scope(a), key(b), fmt(c, d), Codes.FORBIDDEN],` in one object
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.unit.test_0101_cwe778_density import (
    CHILD_TIMEOUT_SEC,
    SIZES_KB,
    _density_problems,
    _time_scan,
)

AGENT_ROOT = Path(__file__).resolve().parents[2]


def _lines_to(size: int, head: str, line: Callable[[int], str], tail: str) -> str:
    out, n, i = [head], len(head) + 1, 0
    while n < size - len(tail):
        text = line(i)
        out.append(text)
        n, i = n + len(text) + 1, i + 1
    out.append(tail)
    return "\n".join(out) + "\n"


SHAPES: dict[str, tuple[str, Callable[[int], str]]] = {
    "closers": ("closers.ts", lambda size: _lines_to(size, "// closers", lambda i: "x" + ")" * 1985 + " forbidden", "")),
    "catalog": ("catalog.ts", lambda size: _lines_to(
        size, "export const MESSAGES = {", lambda i: f"  k{i}: [scope(a), key(b), fmt(c, d), Codes.FORBIDDEN],", "};")),
}


def _child(shape: str, out_path: str) -> int:
    name, build = SHAPES[shape]
    with open(out_path, "w", encoding="utf-8") as handle:
        for kb in SIZES_KB:
            work = Path(tempfile.mkdtemp(prefix="dens778r3_"))
            try:
                (work / "app").mkdir()
                (work / "app" / name).write_text(build(kb * 1024))
                handle.write(json.dumps({"kb": kb, "ms": _time_scan(work)}) + "\n")
                handle.flush()
            finally:
                shutil.rmtree(work, ignore_errors=True)
    return 0


def _run(shape: str) -> dict[int, float]:
    fd, out = tempfile.mkstemp(prefix=f"dens778r3_{shape}_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run([sys.executable, "-m", "tests.unit.test_0101_cwe778_density_r3", "--child", shape, out],
                           cwd=AGENT_ROOT, capture_output=True, text=True, timeout=CHILD_TIMEOUT_SEC, check=False)
        except subprocess.TimeoutExpired:
            pass  # the sizes that finished are reported; a missing one fails the test
        with open(out, encoding="utf-8") as handle:
            rows = [json.loads(r) for r in handle if r.strip()]
    finally:
        os.unlink(out)
    return {r["kb"]: r["ms"] for r in rows}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_auth_dense_file_is_linear_and_cheap(shape: str) -> None:
    problems = _density_problems(_run(shape))
    assert not problems, f"{shape}: {problems}"


def test_the_shapes_have_their_sizes_and_are_candidates() -> None:
    from cwe_agent.skills import insufficient_logging_check as m

    for name, build in SHAPES.values():
        text = build(64 * 1024)
        assert 60 * 1024 <= len(text) <= 68 * 1024, (name, len(text))
        assert m._auth_candidate(text.splitlines()[1]), name


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest")
