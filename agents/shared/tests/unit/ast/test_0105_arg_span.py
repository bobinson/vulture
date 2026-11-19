"""The argument's byte span a flow carries (feature 0105, LLD §4.4, §4.6).

``Flow.span`` is the sink CALL's byte span, so its lines hold the whole call: a callback body
and later keyword arguments. ``Flow.arg_span`` is the byte span of the flow's argument node
(``Flow.arg``), and the CWE-89 cover test reads a statement sink from its sink line plus that
argument's lines (``consume.argument_lines``), counted by ``"\\n"`` in the buffer the worker
parsed, as ``consume._span_lines`` counts the sink span's. Pinned here:

* every production flow carries it, one program per profile family the rule reaches
  (JavaScript, TypeScript, Python, Go): the argument node's span, within the buffer and the
  sink's span;
* ``argument_lines``: the sink line, then the argument's lines, over a ``str`` buffer (ASCII
  text) and a ``bytes`` one (multibyte text above and inside the call); a flow built without
  the field (None, a test double, never a production flow) reads its whole sink span's lines,
  the lines the cover test read before the field;
* the wire (``answer._CODECS``): ``encode`` then ``validate_answer`` round-trips it, and D3'
  refuses it out of the buffer, reversed, null or missing, as it refuses ``span``. The answer
  schema stays 3 (unreleased). A forged answer D3' admits (an argument span over the whole
  buffer; the last sink line with a whole-buffer span) has ``argument_lines`` read no line past
  the file's end;
* the footprint (``_sizing.flow_parts``, A17/A35) counts the tuple and its own ints;
* every flow reported at a sink: ``consume.family_flows`` gives ``family_spans``'
  spans and, from the same ``decide`` pass, every reported flow (a hint-only one included);
  ``sink_flows`` gives each sink line every flow at its sink (its own flow alone when none is
  recorded); ``argument_lines`` given them reads the sink line and every flow's argument lines.
* the program argument's span: a ``command`` flow carries ``Flow.program_span``,
  the byte span of its sink's program argument (``Calls.program_arg``, the node the classifier
  reads statement text from), whichever argument the flow itself is; for a hoisted NAME, the
  NAME at the sink, not its Def. Shown on a flow at another argument of the sink, for a literal
  statement, a template, a concatenation, a hoisted NAME and a statement written over two
  lines. None on any other family's flow and on a hand-built one. ``argument_lines`` reads its
  lines too, so the kept flow alone gives the program argument's lines (two pins of the
  kept-flow-alone fallback move on purpose and say so). On the wire it is the first nullable
  field: ``null`` round-trips as None, a present value is bounded as ``arg_span`` is, and a
  forged one D3' admits reads no line past the file's end. The footprint counts it;
* one group per sink: ``sink_flows`` groups the reported flows by the kept flow's
  sink (``Flow.sink``), so two sinks on one line are two groups.

RED until the round lands: each test fails for want of the field or the helper.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from shared.ast import FileModel
from shared.ast._frames import ModelError
from shared.ast._nodes import parsed_buffer
from shared.ast._records import hint_only
from shared.ast._sizing import flow_parts
from tests.unit.ast._0104 import required
from tests.unit.ast._analysis import (
    candidates_of,
    consume_mod,
    flow_with,
    fresh_context,
    model_of,
    profile_of,
    source_of,
)

pytestmark = pytest.mark.usefixtures("real_pool")

# A comment long enough that every offset below is an int object of its own (``SHARED_INTS``).
PAD = "x" * 300
# The statement-bearing argument of each program.
JS_ARG = '"DELETE FROM t WHERE id = " + req.body.id'
PY_ARG = '"DELETE FROM t WHERE id = " + request.args["id"]'


class Program(NamedTuple):
    """A program whose one command flow's argument is ``arg``: ``lines`` its sink line, then
    the argument's (``argument_lines``); ``call_lines`` how many lines the sink call spans."""

    lang: str
    source: str
    arg: str
    lines: tuple[int, ...]
    call_lines: int


PROGRAMS: dict[str, Program] = {
    "js": Program(
        "js",
        f"// {PAD}\n"
        "function wipe(req, store) {\n"
        "  store.exec(\n"
        f"    {JS_ARG},\n"
        "    function (err) { log(err); }\n"
        "  );\n"
        "}\n",
        JS_ARG, (3, 4), 4,
    ),
    "ts": Program(
        "ts",
        f"// {PAD}\n"
        "function wipe(req: any, store: any): void {\n"
        "  store.exec(\n"
        f"    {JS_ARG},\n"
        "    (err: unknown) => log(err),\n"
        "  );\n"
        "}\n",
        JS_ARG, (3, 4), 4,
    ),
    "py": Program(
        "py",
        f"# {PAD}\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store):\n"
        "    store.exec(\n"
        f"        {PY_ARG},\n"
        '        note="later",\n'
        "    )\n",
        PY_ARG, (6, 7), 4,
    ),
    "go": Program(
        "go",
        f"// {PAD}\n"
        "package m\n"
        "\n"
        'import "net/http"\n'
        "\n"
        "func wipe(h X, r *http.Request) {\n"
        "\th.Exec(\n"
        '\t\t"DELETE FROM t WHERE id = "+r.FormValue("id"),\n'
        '\t\tr.FormValue("opts"),\n'
        "\t)\n"
        "}\n",
        '"DELETE FROM t WHERE id = "+r.FormValue("id")', (7, 8), 4,
    ),
    # Multibyte text above the call and inside it, before the argument: the buffer is the
    # text's UTF-8 bytes, where a line counted by characters would land elsewhere.
    "py_utf8": Program(
        "py",
        "# café 日本語 " + "é" * 200 + "\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(store):\n"
        "    store.exec(  # ünï 日本\n"
        f"        {PY_ARG},  # é\n"
        '        note="later",\n'
        "    )\n",
        PY_ARG, (6, 7), 4,
    ),
    # An argument written over two lines below the sink line: each of them.
    "js_two_line_arg": Program(
        "js",
        f"// {PAD}\n"
        "function wipe(req, store) {\n"
        "  store.exec(\n"
        '    "DELETE FROM t " +\n'
        '      "WHERE id = " + req.body.id,\n'
        "    function (err) { log(err); }\n"
        "  );\n"
        "}\n",
        '"DELETE FROM t " +\n      "WHERE id = " + req.body.id', (3, 4, 5), 5,
    ),
    # The argument on the sink line: the line once.
    "js_one_line": Program(
        "js",
        f"// {PAD}\n"
        "function wipe(req, store) {\n"
        f"  store.exec({JS_ARG}, function (err) {{\n"
        "    log(err);\n"
        "  });\n"
        "}\n",
        JS_ARG, (3,), 3,
    ),
}
FAMILIES = ["js", "ts", "py", "go"]
MISSING = object()


def _model(name: str) -> FileModel:
    program = PROGRAMS[name]
    return model_of(program.source, program.lang)


def _flow(model: FileModel) -> Any:
    """The program's one command flow."""
    flows = candidates_of(model, "command")
    assert len(flows) == 1, flows
    return flows[0]


def _arg_span(flow: Any) -> Any:
    found = getattr(flow, "arg_span", MISSING)
    assert found is not MISSING, "Flow has no arg_span"
    return found


@pytest.mark.parametrize("name", FAMILIES)
def test_a_flow_carries_its_arguments_byte_span(name: str) -> None:
    model = _model(name)
    flow = _flow(model)
    start, end = _arg_span(flow)
    assert (start, end) == model.span(flow.arg)
    assert flow.span[0] <= start <= end <= flow.span[1] <= len(PROGRAMS[name].source.encode())
    assert source_of(model, flow.arg) == PROGRAMS[name].arg


def test_a_flow_built_without_it_records_none() -> None:
    """The default (a test double, never a production flow): not recorded."""
    assert _arg_span(flow_with("command")) is None


def _argument_lines() -> Callable[..., dict[int, Any]]:
    return required("consume", "argument_lines")


def _lines_of(model: FileModel, flow: Any) -> list[int]:
    """``argument_lines`` of the one sink ``flow``, as the cover test asks it."""
    found = _argument_lines()({flow.sink_line: flow}, model.nl_lines)
    assert list(found) == [flow.sink_line]
    return list(found[flow.sink_line])


@pytest.mark.parametrize("name", list(PROGRAMS))
def test_the_sink_line_then_the_arguments_lines(name: str) -> None:
    model = _model(name)
    assert _lines_of(model, _flow(model)) == list(PROGRAMS[name].lines)


@pytest.mark.parametrize(("name", "kind"), [("py", str), ("py_utf8", bytes)])
def test_the_buffer_counted_in(name: str, kind: type) -> None:
    """The buffer ``argument_lines`` counts in is the one the worker parsed: the text when it
    is ASCII, else its UTF-8 bytes (``parsed_buffer``)."""
    assert type(parsed_buffer(_model(name).nl_lines.text)) is kind


@pytest.mark.parametrize("name", ["js", "py_utf8"])
def test_a_flow_without_it_reads_its_whole_sink_span(name: str) -> None:
    """None: the whole call's lines, which the cover test read before the field."""
    model = _model(name)
    flow = _flow(model)
    _arg_span(flow)
    whole = dataclasses.replace(flow, arg_span=None)
    first = flow.sink_line
    assert _lines_of(model, whole) == list(range(first, first + PROGRAMS[name].call_lines))


def test_argument_lines_of_no_sink_is_empty() -> None:
    model = _model("js")
    assert _argument_lines()({}, model.nl_lines) == {}


# ── the wire (answer._CODECS, D3') ───────────────────────────────────────────


def _answer_mod() -> Any:
    from shared.ast import answer

    return answer


def _doc(name: str) -> dict[str, Any]:
    """The program's answer document as the worker sends it: ``encode``d, through JSON."""
    return json.loads(json.dumps(_answer_mod().encode(_model(name))))


def _validated(name: str, doc: dict[str, Any]) -> Any:
    """``doc`` through D3' against the program's request."""
    program = PROGRAMS[name]
    profile, data = profile_of(program.lang), program.source.encode("utf-8")
    return _answer_mod().validate_answer(doc, profile, profile.grammar_attr, data, program.source)


def _flow_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """The document's one command flow, which carries ``arg_span``."""
    (flow,) = doc["families"]["command"]
    assert "arg_span" in flow, "the answer's flow carries no arg_span"
    return flow


@pytest.mark.parametrize("name", [*FAMILIES, "py_utf8"])
def test_the_answer_round_trips_it(name: str) -> None:
    doc = _doc(name)
    assert _flow_doc(doc)["arg_span"] == list(_arg_span(_flow(_model(name))))
    answer = _validated(name, doc)
    (flow,) = answer.analysis().candidates("command")
    assert _arg_span(flow) == _arg_span(_flow(_model(name)))


def test_the_answer_schema_stays_three() -> None:
    import shared.ast

    assert shared.ast.ANSWER_SCHEMA == 3


def _past_the_bytes(flow: dict[str, Any], size: int) -> None:
    flow["arg_span"] = [0, size + 1]


def _reversed(flow: dict[str, Any], _size: int) -> None:
    start, end = flow["arg_span"]
    flow["arg_span"] = [end, start]


def _null(flow: dict[str, Any], _size: int) -> None:
    flow["arg_span"] = None


def _missing(flow: dict[str, Any], _size: int) -> None:
    del flow["arg_span"]


def _negative(flow: dict[str, Any], _size: int) -> None:
    flow["arg_span"] = [-1, flow["arg_span"][1]]


def _three(flow: dict[str, Any], _size: int) -> None:
    flow["arg_span"] = [*flow["arg_span"], 0]


FORGED: dict[str, Callable[[dict[str, Any], int], None]] = {
    "past the bytes": _past_the_bytes,
    "reversed": _reversed,
    "null": _null,
    "missing": _missing,
    "negative": _negative,
    "three ints": _three,
}


@pytest.mark.parametrize("forgery", list(FORGED))
def test_d3_refuses_a_forged_arg_span(forgery: str) -> None:
    """The worker's own document is admitted; the same with ``arg_span`` forged is
    ``ModelError``, as a forged ``span`` is."""
    doc = _doc("js")
    _validated("js", copy.deepcopy(doc))
    FORGED[forgery](_flow_doc(doc), len(PROGRAMS["js"].source.encode("utf-8")))
    with pytest.raises(ModelError):
        _validated("js", doc)


def _whole_buffer_arg(flow: dict[str, Any], data: bytes) -> None:
    """The argument span over the whole buffer: within the bytes, starting before the sink's."""
    flow["arg_span"] = [0, len(data)]


def _last_sink_line(flow: dict[str, Any], data: bytes) -> None:
    """The sink line the buffer's last and the sink span the whole buffer, each within its
    bound: the lines below the sink line reach past the file's end."""
    flow["sink_line"] = data.count(b"\n") + 1
    flow["span"] = [0, len(data)]


ADMITTED: dict[str, Callable[[dict[str, Any], bytes], None]] = {
    "argument over the whole buffer": _whole_buffer_arg,
    "last sink line, whole-buffer span": _last_sink_line,
}


@pytest.mark.parametrize("forgery", list(ADMITTED))
def test_a_forged_answer_d3_admits_reads_no_line_past_the_file(forgery: str) -> None:
    """D3' bounds ``arg_span`` and ``span`` by the bytes and ``sink_line`` by the lines, not one
    by another, so it admits these; ``argument_lines`` reads only lines of the file, which the
    statement-text check indexes (feature 0105, LLD §4.6)."""
    doc = _doc("js")
    ADMITTED[forgery](_flow_doc(doc), PROGRAMS["js"].source.encode("utf-8"))
    answer = _validated("js", doc)
    (flow,) = answer.analysis().candidates("command")
    read = _argument_lines()({flow.sink_line: flow}, answer.nl_lines)
    lines = list(read[flow.sink_line])
    assert lines[0] == flow.sink_line
    assert max(lines) <= len(answer.nl_lines)


# ── the footprint (_sizing.flow_parts) ───────────────────────────────────────


@pytest.mark.parametrize("name", FAMILIES)
def test_the_footprint_counts_it(name: str) -> None:
    """``flow_parts`` yields the tuple and both its offsets (each above the shared ints)."""
    flow = _flow(_model(name))
    span = _arg_span(flow)
    parts = list(flow_parts(flow, lambda _name: True))
    assert any(part is span for part in parts)
    assert all(any(part is offset for part in parts) for offset in span)


# ── every flow reported at a sink (feature 0105, LLD §4.6) ────────────────────

# A statement sink with two sink arguments (under a ``system`` key): a hint-only flow
# (``file_path``, its argument on line 6) and a request-fed one (line 7), both at sink line 5.
TWO_FLOWS = (
    "from flask import request\n"
    "\n"
    "\n"
    "def wipe(h, file_path):\n"
    "    h.system(\n"
    "        \"DELETE FROM t WHERE p = '\" + file_path + \"'\",\n"
    '        request.args["opts"],\n'
    "    )\n"
)


def _statement_rule() -> Any:
    """cwe's CWE-89 command rule as ``consume`` builds one: the statement flows (E4)."""
    consume = consume_mod()
    return consume.FamilyRule(
        family="command", check_id="cwe.injection.sql", category="CWE-89",
        title="SQL injection", severity="critical", recommendation="Parameterize",
        cwe_id="89", heuristic=consume.statement_param, accepts=consume.statement_flow,
    )


class Reported(NamedTuple):
    """``family_flows`` of ``TWO_FLOWS``: its model, spans and reported flows."""

    model: FileModel
    spans: dict[int, Any]
    reported: Any


def _reported(tmp_path: Path) -> Reported:
    model = model_of(TWO_FLOWS, "py")
    ctx = fresh_context(tmp_path)
    found = required("consume", "family_flows")(model, _statement_rule(), ctx, tmp_path / "f.py")
    spans, reported = found
    return Reported(model, spans, reported)


def _by_arg(flows: Any) -> list[Any]:
    return sorted(flows, key=lambda flow: flow.arg_span)


def test_family_flows_gives_the_spans_and_every_reported_flow(tmp_path: Path) -> None:
    """One ``decide`` pass: ``family_spans``' spans, and beside them every flow reported, the
    hint-only one included; the line's own flow is the request-fed one (0104 A1)."""
    found = _reported(tmp_path)
    alone = consume_mod().family_spans(
        found.model, _statement_rule(), fresh_context(tmp_path), tmp_path / "f.py")
    assert found.spans == alone
    pairs = sorted((flow.sink_line, hint_only(flow.origins)) for flow in found.reported)
    assert pairs == [(5, False), (5, True)]
    assert found.spans[5] in found.reported and not hint_only(found.spans[5].origins)


def test_sink_flows_gives_each_sink_line_every_flow_at_it(tmp_path: Path) -> None:
    """Each sink line -> every reported flow at the sink of its own flow (here both flows are at
    the one call); with none recorded, the line's own flow alone."""
    found = _reported(tmp_path)
    sink_flows = required("consume", "sink_flows")
    at = sink_flows(found.spans, found.reported)
    assert {line: _by_arg(flows) for line, flows in at.items()} == {5: _by_arg(found.reported)}
    assert {line: list(flows) for line, flows in sink_flows(found.spans).items()} == {
        5: [found.spans[5]]}


def test_argument_lines_reads_every_flow_at_the_sink(tmp_path: Path) -> None:
    """The sink line, then the argument lines of every flow at it, sorted and each once; with no
    flows given, its own flow's alone (the request-fed argument, line 7) and, since the
    program-argument cover, its sink's program argument's (the statement, line 6:
    ``Flow.program_span``). Before that cover the flow alone read ``[5, 7]``; the move is that
    rule's (feature 0105, LLD §4.6), measured on its prototype."""
    found = _reported(tmp_path)
    flows = required("consume", "sink_flows")(found.spans, found.reported)
    read = _argument_lines()(found.spans, found.model.nl_lines, flows)
    assert {line: list(lines) for line, lines in read.items()} == {5: [5, 6, 7]}
    alone = _argument_lines()(found.spans, found.model.nl_lines)
    assert {line: list(lines) for line, lines in alone.items()} == {5: [5, 6, 7]}


# ── the program argument's span (feature 0105, LLD §4.4, §4.6) ───────────────


class ProgramCase(NamedTuple):
    """A program whose sink's program argument (the node the classifier reads statement text
    from, ``Calls._statement_text``) is ``program``; ``arg`` is the argument of the flow read,
    another argument of the same sink (a ``system`` key makes each a sink argument)."""

    lang: str
    source: str
    arg: str
    program: str


PROGRAM_CASES: dict[str, ProgramCase] = {
    # A literal statement: no flow of its own reaches the CWE-89 rule; its span is still the
    # program argument's.
    "literal": ProgramCase(
        "js",
        f"// {PAD}\n"
        "function wipe(req, h) {\n"
        '  h.system("DELETE FROM t WHERE id = 1", req.query.opts);\n'
        "}\n",
        "req.query.opts", '"DELETE FROM t WHERE id = 1"',
    ),
    "template": ProgramCase(
        "js",
        f"// {PAD}\n"
        "function wipe(req, h) {\n"
        "  h.system(`DELETE FROM t WHERE id = ${req.body.id}`, req.query.opts);\n"
        "}\n",
        "req.query.opts", "`DELETE FROM t WHERE id = ${req.body.id}`",
    ),
    "concatenation": ProgramCase(
        "js",
        f"// {PAD}\n"
        "function wipe(req, h) {\n"
        f"  h.system({JS_ARG}, req.query.opts);\n"
        "}\n",
        "req.query.opts", JS_ARG,
    ),
    # A hoisted NAME: the NAME at the sink, never its reaching Def, so the sink still reads as
    # hoisted.
    "hoisted": ProgramCase(
        "py",
        f"# {PAD}\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def wipe(h):\n"
        f"    stmt = {PY_ARG}\n"
        '    h.system(stmt, request.args["opts"])\n',
        'request.args["opts"]', "stmt",
    ),
    "multi_line": ProgramCase(
        "js",
        f"// {PAD}\n"
        "function wipe(req, h) {\n"
        "  h.system(\n"
        '    "DELETE FROM t " +\n'
        '      "WHERE id = " + req.body.id,\n'
        "    req.query.opts\n"
        "  );\n"
        "}\n",
        "req.query.opts", '"DELETE FROM t " +\n      "WHERE id = " + req.body.id',
    ),
}


def _case_model(name: str) -> FileModel:
    case = PROGRAM_CASES[name]
    return model_of(case.source, case.lang)


def _flow_at(model: FileModel, arg: str) -> Any:
    """The one command flow whose argument's source is ``arg``."""
    found = [flow for flow in candidates_of(model, "command") if source_of(model, flow.arg) == arg]
    assert len(found) == 1, found
    return found[0]


def _program_span(flow: Any) -> Any:
    found = getattr(flow, "program_span", MISSING)
    assert found is not MISSING, "Flow has no program_span"
    return found


@pytest.mark.parametrize("name", list(PROGRAM_CASES))
def test_a_command_flow_carries_its_sinks_program_argument_span(name: str) -> None:
    """The byte span of the sink's program argument, which is not the flow's own argument: the
    program's first occurrence at or after the sink's start (for ``hoisted``, the NAME at the
    sink, not the Def above it), inside the sink's span."""
    case = PROGRAM_CASES[name]
    model = _case_model(name)
    flow = _flow_at(model, case.arg)
    start, end = _program_span(flow)
    data, program = case.source.encode("utf-8"), case.program.encode("utf-8")
    at = data.index(program, flow.span[0])
    assert (start, end) == (at, at + len(program))
    assert flow.span[0] <= start <= end <= flow.span[1]
    assert (start, end) != flow.arg_span


def test_a_flow_of_another_family_records_none() -> None:
    """Only a ``command`` flow carries it: a ``request`` (SSRF) flow's is None."""
    model = model_of("function f(req) { fetch(req.query.u); }\n", "js")
    (flow,) = candidates_of(model, "request")
    assert _program_span(flow) is None


def test_a_hand_built_flow_records_none() -> None:
    """The default (a test double, never a production flow): not recorded."""
    assert _program_span(flow_with("command")) is None


def test_the_program_argument_is_the_program_position_or_none() -> None:
    """``Calls.program_arg``, the accessor the flow pass reads: the argument at the command
    row's program position, ``-1`` for a call with none there. A command flow is only ever
    built at a call with one (``Calls._command_args`` gives none without it), so a production
    command flow always records the span; the ``-1`` reading is the guard's."""
    from shared.ast._origins import Engine
    from shared.ast.kinds import Kind

    model = model_of("function f(h, a, b) { h.system(a, b); h.system(); }\n", "js")
    calls = Engine(model).calls
    sites = sorted(n for n in model.nodes(Kind.CALL) if calls.key(n) == "system")
    assert [source_of(model, n) if n >= 0 else n for n in map(calls.program_arg, sites)] == [
        "a", -1]


def test_argument_lines_read_the_program_arguments_lines() -> None:
    """The flow at ``req.query.opts`` (line 6) alone: its sink line (3), its sink's program
    argument's lines (4, 5: the statement written over two lines) and its own argument's."""
    model = _case_model("multi_line")
    flow = _flow_at(model, "req.query.opts")
    found = _argument_lines()({flow.sink_line: flow}, model.nl_lines)
    assert {line: list(lines) for line, lines in found.items()} == {3: [3, 4, 5, 6]}


# ── the program span on the wire (answer._CODECS, D3') ───────────────────────


def _case_doc(name: str) -> dict[str, Any]:
    """The case's answer document as the worker sends it: ``encode``d, through JSON."""
    return json.loads(json.dumps(_answer_mod().encode(_case_model(name))))


def _through_d3(name: str, doc: dict[str, Any]) -> Any:
    """``doc`` through D3' against the case's request."""
    case = PROGRAM_CASES[name]
    profile, data = profile_of(case.lang), case.source.encode("utf-8")
    return _answer_mod().validate_answer(doc, profile, profile.grammar_attr, data, case.source)


def _program_flows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The document's command flows, each carrying a ``program_span`` that is not null."""
    flows = doc["families"]["command"]
    assert flows and all(flow.get("program_span") is not None for flow in flows), (
        "the answer's flows carry no program_span")
    return flows


@pytest.mark.parametrize("name", list(PROGRAM_CASES))
def test_the_answer_round_trips_the_program_span(name: str) -> None:
    doc = _case_doc(name)
    flows = candidates_of(_case_model(name), "command")
    assert [flow["program_span"] for flow in _program_flows(doc)] == [
        list(_program_span(flow)) for flow in flows]
    admitted = _through_d3(name, doc).analysis().candidates("command")
    assert [_program_span(flow) for flow in admitted] == [_program_span(f) for f in flows]


def test_a_null_program_span_crosses_as_null() -> None:
    """The first nullable field on the wire: a flow without one (None) is written ``null``, and
    D3' admits ``null`` as None (it refuses ``null`` for ``span`` and ``arg_span``)."""
    flow = _flow_at(_case_model("literal"), "req.query.opts")
    _program_span(flow)
    written = _answer_mod()._flow_doc(dataclasses.replace(flow, program_span=None))
    assert written["program_span"] is None
    doc = _case_doc("literal")
    for each in _program_flows(doc):
        each["program_span"] = None
    admitted = _through_d3("literal", doc).analysis().candidates("command")
    assert admitted and all(_program_span(each) is None for each in admitted)


def _program_past_the_bytes(flow: dict[str, Any], size: int) -> None:
    flow["program_span"] = [0, size + 1]


def _program_reversed(flow: dict[str, Any], _size: int) -> None:
    start, end = flow["program_span"]
    flow["program_span"] = [end, start]


def _program_negative(flow: dict[str, Any], _size: int) -> None:
    flow["program_span"] = [-1, flow["program_span"][1]]


def _program_three(flow: dict[str, Any], _size: int) -> None:
    flow["program_span"] = [*flow["program_span"], 0]


def _program_missing(flow: dict[str, Any], _size: int) -> None:
    del flow["program_span"]


def _program_scalar(flow: dict[str, Any], _size: int) -> None:
    flow["program_span"] = flow["program_span"][0]


PROGRAM_FORGED: dict[str, Callable[[dict[str, Any], int], None]] = {
    "past the bytes": _program_past_the_bytes,
    "reversed": _program_reversed,
    "negative": _program_negative,
    "three ints": _program_three,
    "missing": _program_missing,
    "a scalar": _program_scalar,
}


@pytest.mark.parametrize("forgery", list(PROGRAM_FORGED))
def test_d3_refuses_a_forged_program_span(forgery: str) -> None:
    """The worker's own document is admitted; the same with ``program_span`` forged on every
    command flow is ``ModelError``: a present span is bounded as ``arg_span`` is."""
    doc = _case_doc("literal")
    flows = _program_flows(doc)
    _through_d3("literal", copy.deepcopy(doc))
    size = len(PROGRAM_CASES["literal"].source.encode("utf-8"))
    for flow in flows:
        PROGRAM_FORGED[forgery](flow, size)
    with pytest.raises(ModelError):
        _through_d3("literal", doc)


def test_a_forged_program_span_d3_admits_reads_no_line_past_the_file() -> None:
    """A program span over the whole buffer is within the bytes, so D3' admits it (it ties no
    span to the sink line); ``argument_lines`` reads only lines of the file, as for a forged
    ``arg_span`` (fix round r3's bound)."""
    doc = _case_doc("literal")
    data = PROGRAM_CASES["literal"].source.encode("utf-8")
    for flow in _program_flows(doc):
        flow["program_span"] = [0, len(data)]
    answer = _through_d3("literal", doc)
    flow = answer.analysis().candidates("command")[-1]
    assert _program_span(flow) == (0, len(data))
    read = _argument_lines()({flow.sink_line: flow}, answer.nl_lines)
    lines = list(read[flow.sink_line])
    assert lines[0] == flow.sink_line
    assert max(lines) <= len(answer.nl_lines)


def test_the_footprint_counts_the_program_span() -> None:
    """``flow_parts`` yields the program span's tuple and both its offsets (each above the
    shared ints), a tuple of its own beside the argument's."""
    flow = _flow_at(_case_model("literal"), "req.query.opts")
    span = _program_span(flow)
    assert span != flow.arg_span
    parts = list(flow_parts(flow, lambda _name: True))
    assert any(part is span for part in parts)
    assert all(any(part is offset for part in parts) for offset in span)


# ── one group per sink (feature 0105, LLD §4.6) ───────────────────────────────

# Two statement sinks on one line (6): ``row.owner`` and a request value, each its own call.
TWO_SINKS = (
    "from flask import request\n"
    "\n"
    "\n"
    "def f(conn, db):\n"
    "    row = db.query(f\"SELECT * FROM t WHERE id = {request.args['id']}\")\n"
    '    conn.exec(row.owner); conn.exec(request.form["sql"])\n'
)


def test_sink_flows_groups_the_flows_by_the_kept_flows_sink(tmp_path: Path) -> None:
    """Two sinks on one line are two groups: the line's entry holds the flows of the sink its
    flow belongs to (``Flow.sink``, the call), never the other sink's, whichever is kept."""
    model = model_of(TWO_SINKS, "py")
    ctx = fresh_context(tmp_path)
    spans, reported = required("consume", "family_flows")(
        model, _statement_rule(), ctx, tmp_path / "f.py")
    assert {flow.sink_line for flow in reported} == {6}
    assert len({flow.sink for flow in reported}) == 2
    assert spans[6] in reported
    sink_flows = required("consume", "sink_flows")
    for kept in reported:
        at = sink_flows({6: kept}, reported)
        assert list(at) == [6]
        assert {flow.sink for flow in at[6]} == {kept.sink}
