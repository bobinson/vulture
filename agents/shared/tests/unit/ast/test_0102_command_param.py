"""Feature 0102, plan task 3.3 (LLD §5, §8.5, §10.1; D9, D25; A42 (1)): the command parameter
heuristic.

D9 leaves a sink whose origins are UNKNOWN-only unreported. For the ``command`` family only,
D25 reports such a flow when its unknowns hold ``unknown(param)``, the sink shells the
argument by the command row's existing tables or the argument is BUILT (a BINOP or TEMPLATE,
or one NAME hop to a Def whose value is one), and no same-file caller bound the parameter. A
covering guard still declines it. The facts are trailing ``Flow`` fields the flow pass sets on
a ``command`` flow (``shell_sink``, ``built_arg``, ``param_bound``); the hook is
``FamilyRule.heuristic`` (``consume.command_param``), asked inside ``decide``; the row names it
as ``validation.flow.heuristic`` only when ``decide`` reported the flow on it. A rule with no
hook — the harness's stub rule, the fact dump's — decides exactly as D9 does.

Pinned elsewhere: the production ``injection``/``skill_c`` CWE-78 rows the heuristic keeps
(cwe ``test_0102_command_ast.py::test_existing_injection_fixtures_are_unchanged``), the
``ast_v1`` group (cwe ``test_0102_ast_corpus.py`` ``[78]``), the row's place under
``validation`` (cwe ``test_0102_consumer_contract.py``).
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from tests.unit.ast._analysis import (
    ALLOWLIST,
    REPORT,
    RecordingContext,
    candidates_of,
    consume_mod,
    decided,
    finding_of,
    flow_mod,
    flows_on,
    program,
    stub_rule,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# Every program's command sink is on line 4 (the def on line 3).
SINK_LINE = 4
# The consumer's file every decision and row here names.
CMD_PATH = Path("/audit/src/cmd.py")
NONE = "none"
UNKNOWN_ONLY = "unknown_only_sinks"
TOKEN = "command_param"

# (shell_sink, built_arg) of the one command flow, and the verdict under the command rule.
_SHELL_AND_BUILT = 'import os\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n'
_SHELL_KWARG = "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
_TEMPLATE = 'import os\n\ndef lookup(domain):\n    os.popen(f"whois {domain}")\n'
_ONE_HOP = (
    'import os\n\ndef usage(path):\n    line = "du -sh " + path\n    os.popen(line)\n'
)
_TWO_HOPS = (
    'import os\n\ndef usage(path):\n    built = "du -sh " + path\n    line = built\n'
    "    os.popen(line)\n"
)
_PLAIN = "import os\n\ndef run(cmd):\n    os.popen(cmd)\n"
_JS_TEMPLATE = "function list(dir) {\n  const x = 1;\n  child_process.exec(`ls ${dir}`);\n}\n"
CASES = {
    "shell_and_built": (("py", _SHELL_AND_BUILT), SINK_LINE, True, True, REPORT),
    "shell_kwarg": (("py", _SHELL_KWARG), SINK_LINE, True, False, REPORT),
    "template": (("py", _TEMPLATE), SINK_LINE, False, True, REPORT),
    "one_hop": (("py", _ONE_HOP), 5, False, True, REPORT),
    "two_hops": (("py", _TWO_HOPS), 6, False, False, NONE),
    "plain": (("py", _PLAIN), SINK_LINE, False, False, NONE),
    "js_template": (("js", _JS_TEMPLATE), 3, False, True, REPORT),
}
# A same-file caller binds the parameter: its constant context decides (D25 (c)).
_BOUND = _SHELL_AND_BUILT + '\nping("localhost")\n'
# A covering guard declines the heuristic's flow like any other (``guarded:allowlist``).
_GUARDED = (
    'import os\n\nALLOWED = {"a"}\n\ndef ping(host):\n    if host not in ALLOWED:\n'
    '        return\n    os.system("ping -c 1 " + host)\n'
)
# An external origin beside ``unknown(param)``: ``decide`` reports on the external one.
_WITH_EXTERNAL = (
    "import os\nfrom flask import request\n\ndef ping(host):\n"
    '    os.system("ping " + host + request.args["x"])\n'
)
# The facts are a ``command`` flow's only: a built path argument of a parameter.
_PATH = 'def read(name):\n    return open("/srv/" + name)\n'


def _model(spec: tuple[str, str]) -> Any:
    return program(*spec)


def _command_flow(spec: tuple[str, str], line: int) -> Any:
    """The one ``command`` flow of ``spec`` whose sink is on ``line``."""
    (flow,) = flows_on(_model(spec), "command", line)
    return flow


def _rule() -> Any:
    """The command rule as cwe builds it (``_RULE_78``): the stub's strings, no gate, the hook."""
    fields = dataclasses.asdict(stub_rule("command"))
    fields.update(gate=None, heuristic=consume_mod().command_param)
    return consume_mod().FamilyRule(**fields)


def _decided(flow: Any) -> tuple[str, RecordingContext]:
    """``decide`` under the command rule's hook, into a recording context."""
    return decided(flow, "command", path=CMD_PATH, heuristic=consume_mod().command_param)


def _record(flow: Any, rule: Any, spec: tuple[str, str]) -> dict[str, Any]:
    """``validation.flow`` of ``flow``'s row under ``rule``."""
    _, source = spec
    row = finding_of(flow, rule, CMD_PATH, source.split("\n"))
    return row["validation"]["flow"]


@pytest.mark.parametrize("case", list(CASES))
def test_command_flow_carries_the_shell_and_built_facts(case: str) -> None:
    spec, line, shell, built, _ = CASES[case]
    flow = _command_flow(spec, line)
    assert flow.origins == {flow_mod().unknown("param")}
    assert (flow.shell_sink, flow.built_arg, flow.param_bound) == (shell, built, False)


@pytest.mark.parametrize("case", list(CASES))
def test_the_command_rule_decides_a_parameter_flow_by_the_heuristic(case: str) -> None:
    spec, line, *_, verdict = CASES[case]
    found, ctx = _decided(_command_flow(spec, line))
    assert found == verdict
    assert ctx.tallies[UNKNOWN_ONLY] == (verdict == NONE)


@pytest.mark.parametrize("case", list(CASES))
def test_a_rule_with_no_hook_leaves_every_parameter_flow_to_d9(case: str) -> None:
    """The stub rule (the fact dump's): UNKNOWN-only is tallied, never reported (D9)."""
    spec, line, *_ = CASES[case]
    verdict, ctx = decided(_command_flow(spec, line), "command")
    assert (verdict, ctx.tallies[UNKNOWN_ONLY]) == (NONE, 1)


def test_a_same_file_caller_binds_the_parameter() -> None:
    """D25 (c): the parameter flow is superseded by the caller's constant context, which
    decides (``none``): neither flow reports."""
    flows = flows_on(_model(("py", _BOUND)), "command", SINK_LINE)
    param = flow_mod().unknown("param")
    assert sorted((param in f.origins, f.param_bound) for f in flows) == [(False, False), (True, True)]
    assert [_decided(f)[0] for f in flows] == [NONE, NONE]


def test_a_covering_guard_declines_the_heuristic_flow() -> None:
    flow = _command_flow(("py", _GUARDED), 8)
    verdict, ctx = _decided(flow)
    assert (verdict, ctx.labels, ctx.tallies[UNKNOWN_ONLY]) == ("decline", [ALLOWLIST], 0)


def test_the_row_names_the_heuristic_it_was_reported_on() -> None:
    spec = ("py", _SHELL_AND_BUILT)
    flow = _command_flow(spec, SINK_LINE)
    assert _record(flow, _rule(), spec)["heuristic"] == consume_mod().COMMAND_PARAM == TOKEN
    assert "heuristic" not in _record(flow, stub_rule("command"), spec)


def test_a_flow_with_an_external_origin_names_no_heuristic() -> None:
    """``decide`` reports it on its external origin, so the row names no heuristic, though the
    hook alone would answer for it."""
    spec = ("py", _WITH_EXTERNAL)
    flow = _command_flow(spec, 5)
    held = flow_mod().unknown("param") in flow.origins
    hook, asked = consume_mod().command_param(flow), flow_mod().named_heuristic(flow, _rule())
    assert (held, hook, asked, _decided(flow)[0]) == (True, TOKEN, None, REPORT)
    assert "heuristic" not in _record(flow, _rule(), spec)


def test_the_facts_belong_to_command_flows_only() -> None:
    (flow,) = candidates_of(_model(("py", _PATH)), "path")
    assert flow.origins == {flow_mod().unknown("param")}
    assert (flow.shell_sink, flow.built_arg, flow.param_bound) == (False, False, False)
