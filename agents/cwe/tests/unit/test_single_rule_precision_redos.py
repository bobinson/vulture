"""Adversarial-input gate for the patterns the single-line rule fixes added.

They run over attacker-supplied source, a line of which can be 512 KB, so each
must stay linear. The resource_check patterns (and its `{v}` templates as
compiled) are covered by ``test_0101_cwe770_redos``, which discovers every
module-level pattern of that module; this file covers the other modules, and the
templates once a name is formatted in. Each measurement runs in a child process
with a hard timeout, because a catastrophic search cannot be interrupted
in-process.

``_GUARD_SHAPE`` is measured through the scan cap, which its only caller
applies: its JavaScript comparison arm scans up to 120 characters after every
`if (`, so a 512 KB line of `if (` cost 63 ms before these fixes added the
Python arms (over the budget already), and the cap is what bounds it.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from cwe_agent.skills._lexical import MAX_SCAN_CHARS
from tests.unit.test_0087_redos import BUDGET_MS, INPUT_BYTES, PROC_TIMEOUT_SEC

AGENT_ROOT = Path(__file__).resolve().parents[2]
# Line length per pattern: the full adversarial line, or the scan cap for a
# pattern whose callers read at most MAX_SCAN_CHARS of a line.
SIZES = {"guard_shape": MAX_SCAN_CHARS}

# name -> (import statement binding P, units repeated to INPUT_BYTES)
CASES = {
    "channel_sync": (
        "from cwe_agent.skills.concurrency_check import _CHANNEL_SYNC as P", ("<", "close", ".close"),
    ),
    "wait_group_call": (
        "from cwe_agent.skills.concurrency_check import _WAIT_GROUP_CALL as P", ("a", "a .", " ", ".Wait"),
    ),
    "wait_group_decl": (
        "from cwe_agent.skills.concurrency_check import _WAIT_GROUP_DECL as P",
        ("a", "a ", "a := ", "a := &", "sync.", " "),
    ),
    "constexpr_variable": (
        "from cwe_agent.skills.divide_by_zero_check import _CONSTEXPR_VARIABLE as P",
        ("constexpr ", "constexpr a", " "),
    ),
    "rust_const_item": (
        "from cwe_agent.skills.divide_by_zero_check import _CONST_DECLARATION as D; P = D['.rs']",
        (" ", "pub(", "const a"),
    ),
    "go_const_item": (
        "from cwe_agent.skills.divide_by_zero_check import _CONST_DECLARATION as D; P = D['.go']",
        (" ", "const "),
    ),
    "go_const_group": (
        "from cwe_agent.skills.divide_by_zero_check import _GO_CONST_GROUP as P", (" ", "const ("),
    ),
    "go_group_edge": (
        "from cwe_agent.skills.divide_by_zero_check import _GO_GROUP_EDGE as P", (" ", "var", "a"),
    ),
    "guard_shape": (
        "from cwe_agent.skills.input_validation_check import _GUARD_SHAPE as P",
        ("is ", "is not ", "if not", "if (", "isinstance"),
    ),
    "bound_names": (
        "from cwe_agent.skills.input_validation_check import _BOUND_NAMES as P", ("a:", " ", "a"),
    ),
    "return_operand": (
        "from cwe_agent.skills.input_validation_check import _RETURN_OPERAND as P", (" ", "return "),
    ),
    "routine_name": (
        "from cwe_agent.skills.input_validation_check import _ROUTINE_NAME as P",
        ("def ", "a = ", "function(", "async ", "a", " "),
    ),
    "ok_short_circuit": (
        "from cwe_agent.skills.resource_check import GO_OK_SHORT_CIRCUIT as T; "
        "import re; P = re.compile(T.pattern.format(v='ok'))",
        ("!", "! ok", "ok ", " "),
    ),
    "ok_negated_if": (
        "from cwe_agent.skills.resource_check import GO_OK_NEGATED_IF as T; "
        "import re; P = re.compile(T.pattern.format(v='ok'))",
        (" ", "if !", "if ! ok "),
    ),
    "handle_exists_if": (
        "from cwe_agent.skills.resource_check import _HANDLE_EXISTS_IF as T; "
        "import re; P = re.compile(T.pattern.format(v='fh'))",
        (" ", "if (", "if fh ", "if fh is not "),
    ),
    "ok_positive_if": (
        "from cwe_agent.skills.resource_check import GO_OK_POSITIVE_IF as T; "
        "import re; P = re.compile(T.pattern.format(v='ok'))",
        (" ", "if ", "if ok "),
    ),
}

_CHILD = textwrap.dedent("""
    import json, sys, time
    {import_line}
    out = {{}}
    for unit in {units!r}:
        subject = (unit * ({size} // len(unit) + 1))[:{size}] + "\\x00"
        best = None
        for _ in range(3):
            start = time.perf_counter()
            P.search(subject)
            took = (time.perf_counter() - start) * 1000.0
            best = took if best is None else min(best, took)
        out[unit] = best
    print(json.dumps(out))
""")


def _timings(name: str, size: int) -> dict[str, float]:
    """Best-of-3 milliseconds per adversarial unit, measured in a child process."""
    import_line, units = CASES[name]
    probe = _CHILD.format(import_line=import_line, units=units, size=size)
    try:
        done = subprocess.run(
            [sys.executable, "-c", probe], cwd=AGENT_ROOT, capture_output=True, text=True,
            timeout=PROC_TIMEOUT_SEC * len(units),
        )
    except subprocess.TimeoutExpired:
        raise AssertionError(f"{name}: a {size}-character adversarial line did not resolve") from None
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads(done.stdout)


@pytest.mark.parametrize("name", sorted(CASES))
def test_pattern_is_linear_on_adversarial_lines(name: str) -> None:
    size = SIZES.get(name, INPUT_BYTES)
    over = {unit: ms for unit, ms in _timings(name, size).items() if ms >= BUDGET_MS}
    assert not over, f"{name}: over {BUDGET_MS:.1f} ms on a {size}-character line: {over}"
