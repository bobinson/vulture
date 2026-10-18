r"""Feature 0102, plan task 3.1: ``shared.ast.consume`` — ``FamilyRule``, ``flow_to_finding``,
``emit_for_line`` and ``family_spans`` (LLD §5, §9.2, §9.3, §10.1; D11, D19, D21; A30 (1),
A40 (3)).

A reported flow becomes ONE row with the regex body's keys (the dict
``input_validation_check._check_path_traversal`` builds, its ``code_snippet`` included) plus
``validation`` (§10.1) and, by D11, the sink line as ``evidence_quote``. The row's identity is
its ``FamilyRule``'s strings (D19), it anchors at the sink line only (``line_start ==
line_end``, however many lines the call spans), its snippet and quote are cut from
``text.split("\n")`` (D21), and its description names no identifier the flow read.
``family_spans`` maps every line of a reported sink's call to its flow and records each decline
on the audit's context, against the consumer's file (A30 (1)); ``emit_for_line`` claims every
span line and appends the row once, at the sink line (§9.2, ``cwe_22_16.js``).

A40 (3): each flow carries its sink's GLUED callee key — the flow pass's ``Calls.key``, as
``Flow.sink_key`` — and ``family_spans`` hands a rule's gate (``FamilyRule.gate``) the file's
``server_ctx``; a flow the gate refuses is neither a span nor a decline. The SSRF gate's
policy over that key is cwe's ``_RULE_918.gate`` (``test_0102_ssrf_ast.py``).

Pinned elsewhere, not repeated here: both tiers' corpus rows carry one identity and quote
their sink line (cwe ``test_0102_identity.py``); AST facts travel only under ``validation``
(cwe ``test_0102_consumer_contract.py``); ``validation.flow`` carries credentials only as
placeholders and D16 hop names (``test_0102_egress.py``, its four ``validation.flow`` cases);
``decide``'s verdicts, labels and its call of the gate (``test_0102_flow_rules.py``,
``test_0102_guards.py``).

RED until ``shared.ast.consume`` exists: every test fails on its ``ModuleNotFoundError``. The
gate-key test then stays RED until ``Flow`` carries ``sink_key`` (A40 (3)).
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Collection, Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from shared.ast import MODEL_SCHEMA, FileModel
from shared.tools.snippet import extract_snippet
from tests.unit.ast._analysis import (
    FAMILIES,
    HOP_EXPR,
    HOP_PLACEHOLDERS,
    TOKEN,
    consume_mod,
    finding_of,
    fixture_path,
    flow_at_call,
    fresh_context,
    js_handler,
    newline_row,
    program,
    stub_rule,
)
from tests.unit.ast._audit import REQUEST_ORIGINS, decline_line, rendered
from tests.unit.ast._support import fixture_model, model_of_path, write

pytestmark = pytest.mark.usefixtures("real_pool")

type Gate = Callable[[Any, bool], bool]

# Plan 3.1: the keys of the regex body's dict, ``code_snippet`` included.
_REGEX_BODY_KEYS = frozenset({
    "severity", "check_id", "category", "title", "description", "file_path", "line_start",
    "line_end", "recommendation", "code_snippet",
})
# ...plus ``validation`` (§10.1) and D11's ``evidence_quote`` (the sink line), which
# ``test_0102_identity.py`` reads off the skill's rows.
_AST_ROW_KEYS = _REGEX_BODY_KEYS | {"validation", "evidence_quote"}
# D11, D19: the strings a row takes from its ``FamilyRule``.
_IDENTITY = ("check_id", "category", "title", "severity", "recommendation")

# ``cwe_22_16.js``: the four-line ``fs.readFile(`` call, lines 3-6
# (``test_0102_egress.py::test_a_multiline_call_is_windowed_at_its_first_line``), as
# ``_fixture_sink``'s (family, fixture, sink head).
_FOUR_LINE_CALL = tuple(range(3, 7))
_FOUR_LINE = ("path", "cwe_22_16.js", "fs.readFile")

# One reported flow per family, read through identifiers no prose uses, so a description
# that names one cannot do so by coincidence: family -> (source, the sink's call head).
_PROGRAMS: Mapping[str, tuple[str, str]] = {
    "path": (
        "function handler(req) {\n  const qzLedgerName = req.query.f;\n"
        "  fs.readFile(qzLedgerName);\n}\n",
        "fs.readFile",
    ),
    "request": (
        "function handler(req) {\n  const qzTarget = req.query.u;\n  fetch(qzTarget);\n}\n",
        "fetch",
    ),
    "command": (
        "function handler(req) {\n  const qzCmd = req.body.c;\n"
        "  child_process.exec(qzCmd);\n}\n",
        "child_process.exec",
    ),
}

# §10.1's example shape, reported: the request value passes a sanitiser that does not cover
# ``request`` (``path_normalize``) and a guard whose role does not cover it (``validate``).
_, _GUARDED_VIA = js_handler(
    "const u = path.basename(req.query.u);", 'if (typeof u !== "string") return;', "fetch(u);"
)

# A40 (3): one request sink per line behind one request value. ``httpGet(u)`` (line 9) is the
# ruling's example of a callee the gate must not split into ``get``: its glued key ``httpget``
# is in no request sink lexicon, so it is no candidate at all. ``urlOpen(u)`` (line 8) is the
# same case on a real sink — glued key ``urlopen``, last word ``open`` — and stays a sink
# outside server code.
_, _BROWSER_SINKS = js_handler(
    "const u = req.query.u;", "fetch(u);", "this.http.get(u);", "map.get(u);",
    "window.open(u);", "client.do(u);", "urlOpen(u);", "httpGet(u);", "axios(u);",
)
# The keys ``_glued_key_gate`` refuses outside server code: the four of ``_RULE_918.gate``,
# whose policy cwe pins.
_GATED_KEYS = frozenset({"fetch", "get", "open", "do"})

# A30 (2): every hop-name segment, or whole hop name, that names no identifier.
_HOP_PLACEHOLDERS = HOP_PLACEHOLDERS | {HOP_EXPR}


# ── the subject: one reported flow, where it was read ────────────────────────


class _Sink(NamedTuple):
    """A flow, the model and file it was read from, the text that model was built from, and
    that text's ``split("\\n")`` — the ``nl_lines`` a consumer hands ``flow_to_finding`` (D21)."""

    model: FileModel
    path: Path
    flow: Any
    text: str
    nl_lines: Sequence[str]


def _sink(path: Path, model: FileModel, text: str, family: str, head: str) -> _Sink:
    """The ``family`` flow at the sink ``head`` of ``model``, built from ``text`` (at
    ``path``): its ``nl_lines`` are split from that one decode."""
    return _Sink(model, path, flow_at_call(model, family, head), text, text.split("\n"))


def _fixture_sink(family: str, name: str, head: str) -> _Sink:
    """The ``family`` flow at the sink ``head`` of the ``ast_v1`` fixture ``name``."""
    return _sink(fixture_path(name), *fixture_model(name), family, head)


def _written_sink(tmp_path: Path, source: str, family: str, head: str) -> _Sink:
    """The ``family`` flow at the sink ``head`` of ``source``, written as ``handler.js``."""
    path = write(tmp_path / "handler.js", source)
    return _sink(path, *model_of_path(path), family, head)


def _program_sink(tmp_path: Path, family: str) -> _Sink:
    """The reported flow of ``_PROGRAMS[family]``, its model the session's shared one
    (``program``); the file is written too, so the row names a file that holds the text."""
    source, head = _PROGRAMS[family]
    path = write(tmp_path / "handler.js", source)
    return _sink(path, program("js", source), source, family, head)


# ── the consumer head, spelled once ──────────────────────────────────────────


def _rule(family: str, **gate: Gate) -> Any:
    """``consume.FamilyRule`` (§5) with ``stub_rule``'s strings; ``gate=`` only when given, so a
    rule built without one shows the field's default."""
    fields = dataclasses.asdict(stub_rule(family))
    fields.pop("gate")
    return consume_mod().FamilyRule(**fields, **gate)


def _finding(sink: _Sink, rule: Any) -> dict[str, Any]:
    """``flow_to_finding`` (§5) of ``sink``'s flow, in its file, over its ``nl_lines``."""
    return finding_of(sink.flow, rule, sink.path, sink.nl_lines)


def _claimed(
    spans: Mapping[int, Any], rule: Any, sink: _Sink, findings: list[Any]
) -> list[int]:
    """Every line of ``sink``'s file, walked in order through ``emit_for_line(spans,
    line_num, rule, *, file_path, nl_lines, findings)`` (§5, §9.2): those it claims."""
    emit, lines = consume_mod().emit_for_line, range(1, len(sink.nl_lines) + 1)
    return [line for line in lines if emit(
        spans, line, rule, file_path=sink.path, nl_lines=sink.nl_lines, findings=findings)]


def _spans(sink: _Sink, rule: Any, *, server_ctx: bool = True) -> tuple[dict[int, Any], Any]:
    """``family_spans(model, rule, ctx, path, *, server_ctx)`` (§5, A30 (1)) into a new, real
    ``AuditContext`` of the file's directory, and that context."""
    ctx = fresh_context(sink.path.parent)
    spans = consume_mod().family_spans(sink.model, rule, ctx, sink.path, server_ctx=server_ctx)
    return dict(spans), ctx


def _glued_key_gate(flow: Any, server_ctx: bool) -> bool:
    """A gate double of ``_RULE_918.gate``'s shape that reads ``Flow.sink_key``: outside server
    code it refuses a flow whose glued key is in ``_GATED_KEYS``. The policy itself (the four
    keys; ``httpget`` and ``urlopen`` kept) is pinned on ``_RULE_918`` by cwe
    ``test_0102_ssrf_ast.py::test_gate_reads_the_glued_key``."""
    return server_ctx or flow.sink_key not in _GATED_KEYS


# ── readers ──────────────────────────────────────────────────────────────────


def _wire(value: Any) -> Any:
    """``value`` as it reaches the wire: through JSON, so a tuple reads as a list and a value
    JSON cannot carry fails here."""
    return json.loads(json.dumps(value))


def _hop_identifiers(flow: Any) -> set[str]:
    """Every identifier the flow's hops name, case-folded: each ``.``-joined segment of each
    hop name (A30 (2)), the placeholders aside."""
    segments = {segment for hop in flow.hops for segment in hop.name.split(".")}
    return {segment.lower() for segment in segments - _HOP_PLACEHOLDERS}


def _named(text: str, identifiers: set[str]) -> list[str]:
    """The ``identifiers`` that ``text`` holds as a whole token, case-folded."""
    return sorted(identifiers & {token.lower() for token in TOKEN.findall(text)})


def _projected(row: Mapping[str, Any], keys: Collection[str]) -> dict[str, Any]:
    """``row`` cut down to ``keys``: what it holds of another row, its own extra keys aside."""
    return {key: row.get(key) for key in keys}


def _numbered_row(snippet: str, line: int) -> str | None:
    """The snippet row numbered ``line`` (``extract_snippet``'s ``"N: text"``), split on
    ``\\n`` only, as the snippet was built."""
    return next((row for row in snippet.split("\n") if row.startswith(f"{line}: ")), None)


def _gated(sink: _Sink, rule: Any, server_ctx: bool) -> tuple[dict[int, str], int]:
    """``family_spans`` of ``sink``'s file under ``rule`` and ``server_ctx``: span line -> the
    glued callee key of its flow's sink (A40 (3): ``Flow.sink_key``), and the declines."""
    spans, ctx = _spans(sink, rule, server_ctx=server_ctx)
    return {line: flow.sink_key for line, flow in spans.items()}, ctx.ledger.count


# ── flow_to_finding (§5, §10.1; D11, D19, D21) ───────────────────────────────


@pytest.mark.parametrize("family", FAMILIES)
def test_finding_has_the_regex_body_keys_validation_and_the_quote(
    tmp_path: Path, family: str
) -> None:
    """The row has exactly the regex body's keys, ``validation`` and ``evidence_quote``: no
    AST fact becomes a top-level key."""
    finding = _finding(_program_sink(tmp_path, family), _rule(family))
    assert sorted(finding) == sorted(_AST_ROW_KEYS)


def test_finding_takes_its_identity_from_the_rule_and_anchors_at_the_sink_line() -> None:
    """D11, D19: the five identity strings are the rule's and the file is ``str(file_path)``,
    as the regex body writes them; ``cwe_22_16.js``'s call runs from line 3 to 6, and the row
    is ``line_start == line_end == flow.sink_line == 3``."""
    sink = _fixture_sink(*_FOUR_LINE)
    rule = _rule("path")
    finding = _finding(sink, rule)
    observed = _projected(finding, (*_IDENTITY, "file_path", "line_start", "line_end"))
    assert (sink.flow.sink_line, observed) == (3, {
        **{key: getattr(rule, key) for key in _IDENTITY},
        "file_path": str(sink.path),
        "line_start": 3,
        "line_end": 3,
    })


def test_snippet_and_quote_are_cut_from_nl_lines_at_the_sink_line() -> None:
    """D21: ``code_snippet`` is ``extract_snippet(nl_lines, sink_line)`` — the window of the
    sink line, not of the call's four-line span — and D11's ``evidence_quote`` is the sink
    line itself."""
    sink = _fixture_sink(*_FOUR_LINE)
    finding = _finding(sink, _rule("path"))
    line = sink.flow.sink_line
    observed = {
        "code_snippet": finding.get("code_snippet"),
        "evidence_quote": str(finding.get("evidence_quote")).strip(),
    }
    assert observed == {
        "code_snippet": extract_snippet(sink.nl_lines, line),
        "evidence_quote": sink.nl_lines[line - 1].strip(),
    }


def test_validation_is_the_ast_stamp_and_the_flow_record(tmp_path: Path) -> None:
    """§10.1: ``validation.ast`` is the engine, the model's grammar stamp and ``MODEL_SCHEMA``;
    ``validation.flow`` is the family, the origins rendered as a decline renders them, the
    sanitiser roles the value passed (``via``), the guards' roles, every hop as ``{line, kind,
    name}`` and ``truncated`` — on the wire, as JSON."""
    sink = _written_sink(tmp_path, _GUARDED_VIA, "request", "fetch")
    finding = _finding(sink, _rule("request"))
    assert _wire(finding.get("validation")) == {
        "ast": {"engine": "ast", "grammar": sink.model.grammar, "model_schema": MODEL_SCHEMA},
        "flow": {
            "family": "request",
            "origins": list(REQUEST_ORIGINS),
            "via": ["path_normalize"],
            "guards": ["validate"],
            "hops": [hop._asdict() for hop in sink.flow.hops],
            "truncated": False,
        },
    }


@pytest.mark.parametrize("family", FAMILIES)
def test_description_names_no_hop_identifier(tmp_path: Path, family: str) -> None:
    """No identifier a hop names — the request parameter, the variable, the sink's callee —
    is a word of ``description``, in any case."""
    sink = _program_sink(tmp_path, family)
    description = str(_finding(sink, _rule(family)).get("description") or "")
    identifiers = _hop_identifiers(sink.flow)
    observed = {
        "described": bool(description.strip()),
        "hop identifiers": bool(identifiers),
        "named": _named(description, identifiers),
    }
    assert observed == {"described": True, "hop identifiers": True, "named": []}


def test_u2028_in_literal_keeps_line_and_snippet_aligned() -> None:
    """D21, review focus 1: ``cwe_22_20.js`` holds two raw U+2028 in a string before the sink,
    so ``splitlines()`` and ``split("\\n")`` disagree on its lines. The row's ``line_start`` is
    the ``\\n``-counted sink line, its snippet is cut from the same lines, and the snippet row
    with that number — the window's centre — holds the sink."""
    sink = _fixture_sink("path", "cwe_22_20.js", "fs.readFile")
    finding = _finding(sink, _rule("path"))
    text, nl_lines = sink.text, sink.nl_lines
    line = newline_row(text, "fs.readFile(")
    observed = {
        "the case is real": len(text.splitlines()) != len(nl_lines),
        "lines": (finding.get("line_start"), finding.get("line_end")),
        "code_snippet": finding.get("code_snippet"),
        "sink row": _numbered_row(str(finding.get("code_snippet")), line),
    }
    assert observed == {
        "the case is real": True,
        "lines": (line, line),
        "code_snippet": extract_snippet(nl_lines, line),
        "sink row": f"{line}: {nl_lines[line - 1]}",
    }


# ── family_spans (§5, §9.2; A30 (1)) ─────────────────────────────────────────


def test_family_spans_maps_every_line_of_a_four_line_call_to_its_flow() -> None:
    """``cwe_22_16.js``: each of the call's four lines maps to the one reported flow, and
    nothing is declined."""
    sink = _fixture_sink(*_FOUR_LINE)
    spans, ctx = _spans(sink, _rule("path"))
    assert (spans, ctx.ledger.count) == (dict.fromkeys(_FOUR_LINE_CALL, sink.flow), 0)


def test_family_spans_records_a_decline_on_the_consumers_file() -> None:
    """``cwe_22_1_clean.js``: ``path.basename`` covers the flow, so no line is a span and the
    decline is recorded on the context passed, against the path passed (A30 (1)), and rendered
    from it (§10.3)."""
    sink = _fixture_sink("path", "cwe_22_1_clean.js", "fs.readFile")
    spans, ctx = _spans(sink, _rule("path"))
    assert (spans, rendered(ctx.ledger, sink.path.parent)) == (
        {}, [decline_line("cwe_22_1_clean.js", line=2)])


# ── emit_for_line (§5, §9.2) ─────────────────────────────────────────────────


def test_emit_for_line_claims_every_span_line_and_appends_once() -> None:
    """Walked over every line of ``cwe_22_16.js``, ``emit_for_line`` returns True on exactly
    the four span lines and appends one row: ``flow_to_finding``'s, at the sink line (a
    consumer may add keys to it, never change one)."""
    sink = _fixture_sink(*_FOUR_LINE)
    rule = _rule("path")
    spans = dict.fromkeys(_FOUR_LINE_CALL, sink.flow)
    findings: list[Any] = []
    claimed = _claimed(spans, rule, sink, findings)
    expected = _finding(sink, rule)
    projected = [_projected(row, expected) for row in findings]
    assert (claimed, projected) == (list(_FOUR_LINE_CALL), [expected])


# ── the gate (§5, §8.5, §9.3; A40 (3)) ───────────────────────────────────────


def test_family_spans_hands_the_gate_server_ctx_and_each_flows_glued_key(
    tmp_path: Path,
) -> None:
    """Each flow carries its sink's glued callee key (``Flow.sink_key``) and ``family_spans``
    hands the gate the file's ``server_ctx``: in server code every request sink is a span;
    outside it the gate double refuses ``fetch``, ``this.http.get``, ``map.get``,
    ``window.open`` and ``client.do`` (``decide`` returns ``none``: no span, no decline),
    while ``urlOpen`` (``urlopen``) and ``axios`` stay. ``httpGet`` (line 9) is no request
    sink at all (the frozen lexicons)."""
    sink = _written_sink(tmp_path, _BROWSER_SINKS, "request", "fetch")
    rule = _rule("request", gate=_glued_key_gate)
    observed = {server_ctx: _gated(sink, rule, server_ctx) for server_ctx in (True, False)}
    assert observed == {
        True: ({3: "fetch", 4: "get", 5: "get", 6: "open", 7: "do", 8: "urlopen", 10: "axios"}, 0),
        False: ({8: "urlopen", 10: "axios"}, 0),
    }


@pytest.mark.parametrize(("family", "name", "head"), [
    _FOUR_LINE,
    ("command", "cwe_78_1.js", "cp.exec"),
])
def test_a_rule_without_a_gate_ignores_server_ctx(family: str, name: str, head: str) -> None:
    """A rule built without a gate has the §5 default, ``gate is None``, and ``family_spans``
    maps the same lines outside server code as inside it. Which cwe rules carry a gate
    (§9.3) is cwe's to pin."""
    sink = _fixture_sink(family, name, head)
    rule = _rule(family)
    inside, outside = (_spans(sink, rule, server_ctx=flag)[0] for flag in (True, False))
    assert (rule.gate, bool(inside), outside == inside) == (None, True, True)
