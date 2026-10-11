"""Feature 0101 -- CWE-778 helper linearity (LLD 9.3, PERF-9, RM-16).

Each 0101 helper the CWE-778 rule runs per handler caps its own input at
``MAX_SCAN_CHARS``, so its cost is linear up to the cap and flat past it, even
with the site-line guard disabled (``VULTURE_CWE778_MAX_LINE_CHARS=0``, C9).
Measured in a child process (the 0101 lexical harness: round-robin min-of-N
sweeps), asserting a doubling ratio < 2.6 up to the cap, <= 0.5 ms/KB at it, and
a 512 KB input costing about what an input at the cap costs.

The ``mentions_evidence_miss`` subject must never contain the bound name as a
whole word. Its first spelling, ``("ee " * n)[:n]``, ended in a lone `` e`` at
250 and 1000 characters, so those sizes were HITS: the call stopped at the first
name that matched, and whether that was ``e`` (one scan) or ``$e`` (two) followed
the frozenset's per-process hash order. That made the ratios bimodal and
deterministic per seed (2.51 / 3.27 in a failing child, in-process linear),
not timer noise (R778-4). ``"xe "`` truncates to ``x`` or ``xe``, never ``e``,
and a guard below asserts every size really is a miss.

Revision 1 of the design spent 18 s on one 200 KB `x(`-repeated body line
(`_call_args` walked it character by character); these sweeps turn red on that.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.unit import test_0101_lexical_redos as lexgate
from tests.unit.test_0087_redos import INPUT_BYTES, PROC_TIMEOUT_SEC

AGENT_ROOT = Path(__file__).resolve().parents[2]


def _helper_cases() -> dict[str, tuple[Callable[[str], object], Callable[[int], str]]]:
    from cwe_agent.skills import insufficient_logging_check as m
    from cwe_agent.skills._lexical import call_argument_text

    names = m._evidence_names(frozenset({"e"}))
    return {
        # ten body lines of one unclosed statement: joined, each line capped first
        "statements_joined": (lambda s: m._statements("", [s] * 10), lambda n: ("report([" + "f(e), " * n)[:n]),
        "statements_one_line": (lambda s: m._statements(s, []), lambda n: ("x(" * n)[:n]),
        "is_call_chain": (m._is_call_chain, lambda n: ("f(x) " * n)[:n]),
        "is_call_chain_parens": (m._is_call_chain, lambda n: ("(" * n)[:n]),
        "call_argument_text": (lambda s: call_argument_text(s, 1), lambda n: ("x(" * n)[:n]),
        "mentions_evidence_typeof": (lambda s: m._mentions_evidence(s, names), lambda n: ("typeof e, " * n)[:n]),
        "mentions_evidence_miss": (lambda s: m._mentions_evidence(s, names), lambda n: ("xe " * n)[:n]),
        "return_rhs": (m._return_rhs, lambda n: (" return x" * n)[:n]),
    }


HELPER_NAMES: tuple[str, ...] = tuple(sorted(_helper_cases()))


def _child(name: str, out_path: str) -> int:
    os.environ["VULTURE_CWE778_MAX_LINE_CHARS"] = "0"
    call, build = _helper_cases()[name]
    subjects = {f"n={n}": build(n) for n in lexgate.DOUBLING_SIZES}
    subjects["past_cap"] = build(INPUT_BYTES)
    with open(out_path, "w", encoding="utf-8") as handle:
        emit = lexgate._emit_to(handle)
        emit({"status": "start", "input": "sweep"})
        for key, ms in lexgate._time_sweep(call, subjects).items():
            emit({"status": "ok", "input": key, "ms": ms})
    return 0


def _run(name: str) -> dict[str, float | None]:
    fd, out = tempfile.mkstemp(prefix=f"lin778_{name}_", suffix=".jsonl")
    os.close(fd)
    try:
        try:
            subprocess.run([sys.executable, "-m", "tests.unit.test_0101_cwe778_linear", "--child", name, out],
                           cwd=AGENT_ROOT, capture_output=True, text=True,
                           timeout=PROC_TIMEOUT_SEC * 2, check=False)
        except subprocess.TimeoutExpired:
            pass
        results: dict[str, float | None] = {}
        with open(out, encoding="utf-8") as handle:
            for raw in filter(None, map(str.strip, handle)):
                lexgate._fold(results, json.loads(raw))
    finally:
        os.unlink(out)
    assert results, f"linearity child for {name!r} produced no records"
    return results


def test_the_miss_subject_never_names_the_binding() -> None:
    """Every size of the miss sweep is a miss, whatever the hash order (R778-4)."""
    from cwe_agent.skills import insufficient_logging_check as m

    names = m._evidence_names(frozenset({"e"}))
    _call, build = _helper_cases()["mentions_evidence_miss"]
    for n in (*lexgate.DOUBLING_SIZES, INPUT_BYTES, 1, 2, 3, 4):
        for order in (tuple(sorted(names)), tuple(sorted(names, reverse=True))):
            assert not m._mentions_evidence(build(n), order), (n, order)


@pytest.mark.parametrize("helper", HELPER_NAMES)
def test_helper_is_linear_to_the_cap_and_bounded_past_it(helper: str) -> None:
    problems = lexgate._helper_verdict(helper, _run(helper))
    assert not problems, "\n".join(problems)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(_child(sys.argv[2], sys.argv[3]))
    raise SystemExit("run under pytest")
