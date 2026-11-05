"""The consumer head (feature 0102, LLD §5, §9.2, §9.3, §10.1; D9, D11, D19, D21; A28, A30,
A40 (3), A41).

A skill that migrates a check to the AST tier keeps ONE ``FamilyRule`` per check — the
identity strings its regex body and its AST head both emit (D19) — and reaches the layer
through three functions:

* ``family_spans(model, rule, ctx, path, *, server_ctx)`` decides every candidate of the
  rule's family (``flow.decide``, §8.5) and maps EVERY line of each reported sink's span to
  its flow. Declines are recorded there, on the audit's context against the consumer's file
  (A30 (1)), and the analysis' per-file fact counts reach the audit's coverage once per file
  (A28 (3)). A rule's gate (``FamilyRule.gate``, the SSRF ``server_ctx`` gate) is handed
  ``server_ctx or not profile.browser_capable``: a profile that is never browser code is never
  gated (§8.5, A41 (3)).
* ``emit_for_line(spans, line_num, rule, ...)`` is the head a skill's line dispatcher calls
  first: True on every span line (the AST owns it; the regex siblings do not run on it), and
  the row appended once, at the sink line (§9.2, ``cwe_22_16.js``). ``enrich`` (the cwe
  catalog's ``enrich_finding``) is applied to the row before it is appended (A41 (5)).
* ``flow_to_finding(flow, rule, *, file_path, nl_lines)`` is that row: the regex body's keys,
  ``evidence_quote`` (D11: the sink line) and ``validation`` (§10.1). It anchors at the sink
  line only (``line_start == line_end``, D11) and is numbered and windowed from
  ``text.split("\\n")`` (D21); its description names no identifier the flow read, and its
  facts travel only under ``validation`` — the origins rendered as a decline renders them
  (A30 (1)), the hop names as the flow pass rendered them (D16, A30 (2)), and the token of
  the named heuristic ``decide`` reported it on, when one did (D25, A42 (1)).

``rule_row(rule, description, *, file_path, line, lines, **extra)`` is the identity row both
tiers build from a rule (D19): ``flow_to_finding`` extends it, and a skill's regex body builds
its own rows with it, so the two tiers' rows cannot drift apart.

A rule may carry ONE named heuristic (``FamilyRule.heuristic``): ``command_param`` (D25,
A42 (1), A43 (1)) is the command rule's — a flow whose origins are UNKNOWN-only, holding
``unknown(param)`` or ``unknown(argv)`` (A47 D22-c), at a sink that shells the argument, of a
built argument or of the whole command of a profile builtin process API, with no same-file
caller binding the parameter, reports. It is a heuristic, not data flow, and says
so on its row (``validation.flow.heuristic``).

``import shared.ast`` stays a leaf (D1): a skill reads ``FamilyRule`` and ``OWNED_CHECK_IDS``
at import time, so the flow engine, the profiles and the model are imported where a function
first needs them — by then a model exists and has loaded them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from shared.ast import MODEL_SCHEMA, VALIDATION_KEYS
from shared.ast._nodes import parsed_buffer
from shared.ast._records import ARGV, PARAM
from shared.ast.declines import render_origins
from shared.tools.snippet import extract_snippet

if TYPE_CHECKING:
    from shared.ast._records import Flow, Origins
    from shared.ast.answer import FileFacts
    from shared.ast.context import AuditContext

__all__ = [
    "COMMAND_PARAM",
    "OWNED_CHECK_IDS",
    "FamilyRule",
    "RuleIdentity",
    "command_param",
    "emit_for_line",
    "family_spans",
    "flow_to_finding",
    "rule_row",
]

type Finding = dict[str, Any]
# What ``emit_for_line`` applies to a row before it appends it: (row, rule.cwe_id) -> row.
type Enrich = Callable[[Finding, str], Finding]

# The check ids the AST tier owns on every file it parses cleanly (LLD §9): the ``path``,
# ``request`` and ``command`` families' rules, one each (§9.2, §9.3).
OWNED_CHECK_IDS = frozenset({
    "cwe.input_validation.path_traversal",
    "cwe.injection.ssrf",
    "cwe.injection.command",
})

# The row's two ``validation`` keys (§10.1), named once in ``shared.ast`` for the validate
# stage, which keeps them when it rebuilds the blob (A42 (3)).
_AST_KEY, _FLOW_KEY = VALIDATION_KEYS
# ``validation.flow``'s key for the named heuristic a row was reported on (§10.1, D25).
_HEURISTIC_KEY = "heuristic"
# D25's token (A42 (1)): stable, it names the command parameter heuristic on every row it
# reports and in SKILLS.md.
COMMAND_PARAM = "command_param"
# What D25 keys on: ``unknown(param)``, and ``unknown(argv)`` read as it (A47 D22-c). One set,
# so a flow is tested by the hashes both sets store.
_COMMAND_KEYS: Origins = frozenset({PARAM, ARGV})


@dataclass(frozen=True, slots=True)
class FamilyRule:
    """One migrated check (§5, D11, D19): its ``family``, the check id it owns and the identity
    strings both tiers emit, ``cwe_id`` the catalog number ``enrich`` reads, ``gate`` —
    ``(flow, server_ctx) -> keep?``, set only for the SSRF rule, reading ``Flow.sink_key``
    (§9.3, A40 (3)); ``decide`` returns ``none`` for a flow it refuses — and ``heuristic`` —
    ``flow -> token or None``, set only for the command rule (``command_param``, D25, A42
    (1)): ``decide`` asks it for a flow with no external origin, and a token reports the flow
    unless a covering guard declines it."""

    family: str
    check_id: str
    category: str
    title: str
    severity: str
    recommendation: str
    cwe_id: str
    gate: Callable[[Flow, bool], bool] | None = None
    heuristic: Callable[[Flow], str | None] | None = None


def command_param(flow: Flow) -> str | None:
    """D25 (§8.5, A42 (1), A43 (1)), the command rule's hook: ``COMMAND_PARAM`` when the flow
    holds ``unknown(param)`` or ``unknown(argv)`` (A47 D22-c) at a sink that shells the
    argument, of a built argument or of a profile builtin's whole command, and no same-file
    caller bound the parameter (``Flow.shell_sink``, ``built_arg``, ``builtin_program``,
    ``param_bound``: set on a flow holding ``unknown(param)`` only, so it supersedes one holding
    both); else None. ``decide`` asks it only for a flow with no external origin."""
    return COMMAND_PARAM if _param_at_a_command(flow) and not flow.param_bound else None


def _param_at_a_command(flow: Flow) -> bool:
    """The flow holds ``unknown(param)`` or ``unknown(argv)``, and its sink shells the
    argument, it is built or it is a profile builtin's whole command."""
    held = not flow.origins.isdisjoint(_COMMAND_KEYS)
    return held and (flow.shell_sink or flow.built_arg or flow.builtin_program)


def _as_is(finding: Finding, _cwe_id: str) -> Finding:
    """The default ``enrich``: the row unchanged."""
    return finding


# ── the row (§10.1; D11, D19, D21) ───────────────────────────────────────────


class RuleIdentity(Protocol):
    """What a row reads off its rule (D19): the identity strings both tiers emit. A
    ``FamilyRule`` is one, and so is a skill's own rule table entry for its regex-only rows."""

    @property
    def check_id(self) -> str: ...

    @property
    def category(self) -> str: ...

    @property
    def title(self) -> str: ...

    @property
    def severity(self) -> str: ...

    @property
    def recommendation(self) -> str: ...


def rule_row(
    rule: RuleIdentity,
    description: str,
    *,
    file_path: str | Path,
    line: int,
    lines: Sequence[str],
    **extra: Any,
) -> Finding:
    """The identity row of ``rule`` (D19), the row both tiers emit: its identity strings and
    ``description`` at ``line`` of ``file_path`` (``line_start == line_end``), a regex body's
    ``extra`` keys, then the snippet of ``lines`` around ``line`` — in the regex bodies' key
    order, which ``flow_to_finding`` extends."""
    return {
        "severity": rule.severity,
        "check_id": rule.check_id,
        "category": rule.category,
        "title": rule.title,
        "description": description,
        "file_path": str(file_path),
        "line_start": line,
        "line_end": line,
        "recommendation": rule.recommendation,
        **extra,
        "code_snippet": extract_snippet(lines, line),
    }


def flow_to_finding(
    flow: Flow, rule: FamilyRule, *, file_path: str | Path, nl_lines: Sequence[str]
) -> Finding:
    """The row a reported ``flow`` becomes in ``file_path``, whose ``text.split("\\n")`` is
    ``nl_lines`` (D21): the rule's identity row (``rule_row``) at the sink line; the sink line
    as ``evidence_quote`` (D11); ``validation`` = the AST stamp and the flow (§10.1)."""
    line = flow.sink_line
    description = f"{rule.title}: untrusted input reaches the sink at line {line}"
    return {
        **rule_row(rule, description, file_path=file_path, line=line, lines=nl_lines),
        "evidence_quote": _line_text(nl_lines, line),
        "validation": {_AST_KEY: _engine(file_path), _FLOW_KEY: _flow_record(flow, rule)},
    }


def _line_text(nl_lines: Sequence[str], line: int) -> str:
    """Line ``line`` of ``nl_lines``, stripped; ``""`` past their end (lines a caller split
    from a text other than the model's, and shorter)."""
    return nl_lines[line - 1].strip() if 0 < line <= len(nl_lines) else ""


def _engine(file_path: str | Path) -> dict[str, Any]:
    """``validation.ast``: the engine, the grammar stamp the file's models carry
    (``model.grammar_stamp``, A41 (4)) and ``MODEL_SCHEMA``."""
    from shared.ast.model import grammar_stamp

    return {"engine": "ast", "grammar": grammar_stamp(file_path), "model_schema": MODEL_SCHEMA}


def _flow_record(flow: Flow, rule: FamilyRule) -> dict[str, Any]:
    """``validation.flow``: the family; the origins rendered and sorted (A30 (1)); the sanitiser
    roles the value passed (``via``) and the roles of its guards, each sorted once; every hop
    as ``{line, kind, name}`` (A28 (4)); ``truncated``; and ``heuristic``, the token of the
    named heuristic ``decide`` reported the flow on (D25), only when one did."""
    return {
        "family": flow.family,
        "origins": list(render_origins(flow.origins)),
        "via": _roles(o.via for o in flow.origins),
        "guards": _roles(g.roles for g in flow.guards),
        "hops": [hop._asdict() for hop in flow.hops],
        "truncated": flow.truncated,
        **_heuristic(flow, rule),
    }


def _heuristic(flow: Flow, rule: FamilyRule) -> dict[str, str]:
    """``validation.flow.heuristic`` (§10.1): the token of the named heuristic ``decide``
    reported ``flow`` on (``flow.named_heuristic``, the one question both ask); nothing when
    none did."""
    from shared.ast.flow import named_heuristic

    token = named_heuristic(flow, rule)
    return {} if token is None else {_HEURISTIC_KEY: token}


def _roles(sets: Iterable[frozenset[str]]) -> list[str]:
    """The roles of ``sets``, each once, sorted (D14)."""
    return sorted(set(chain.from_iterable(sets)))


# ── the head (§9.2) ──────────────────────────────────────────────────────────


def emit_for_line(
    spans: Mapping[int, Flow],
    line_num: int,
    rule: FamilyRule,
    *,
    file_path: str | Path,
    nl_lines: Sequence[str],
    findings: list[Finding],
    enrich: Enrich = _as_is,
) -> bool:
    """True when ``line_num`` lies in a reported sink's span — the AST owns the line — and
    then, on the sink line itself, ``enrich(flow_to_finding(...), rule.cwe_id)`` appended to
    ``findings``: one row per sink, however many lines its call spans."""
    flow = spans.get(line_num)
    if flow is None:
        return False
    if line_num == flow.sink_line:
        row = flow_to_finding(flow, rule, file_path=file_path, nl_lines=nl_lines)
        findings.append(enrich(row, rule.cwe_id))
    return True


# ── the spans (§9.2, §9.3; A28 (3), A30 (1), A41 (3)) ───────────────────────


def family_spans(
    model: FileFacts,
    rule: FamilyRule,
    ctx: AuditContext,
    path: str | Path,
    *,
    server_ctx: bool = True,
) -> dict[int, Flow]:
    """Every line of each reported ``rule.family`` sink's span in ``model`` — a model, or a
    worker-built answer (§4.1 item 3) — -> its flow.
    ``decide`` records each decline on ``ctx`` against ``path``, the consumer's file; the
    gate is handed the file's ``server_ctx``, or True in a profile that is never browser code
    (§8.5). The analysis' fact counts reach ``ctx``'s coverage once per file."""
    from shared.ast.profile import PROFILES

    analysis = model.analysis()
    ctx.coverage.record_analysis(path, analysis.tallies)
    server_like = server_ctx or not PROFILES[model.language].browser_capable
    reported = _reported(analysis.candidates(rule.family), rule, ctx, path, server_like)
    return _by_line(model, reported)


def _reported(
    flows: Iterable[Flow], rule: FamilyRule, ctx: AuditContext, path: str | Path, server_ctx: bool
) -> list[Flow]:
    """The ``flows`` ``decide`` reports, in their order; it records the declines (§8.5)."""
    from shared.ast.flow import decide

    return [f for f in flows if decide(f, rule, ctx, path=path, server_ctx=server_ctx) == "report"]


def _by_line(model: FileFacts, flows: Sequence[Flow]) -> dict[int, Flow]:
    """Each line of each flow's sink span -> the flow. A span is a byte span of the buffer the
    worker parsed (§4), so its lines are counted there, by ``\\n`` only (D21): the buffer is
    read once (``_parsed_buffer``), and only when a flow was reported. The flows come sorted by
    sink line, so a later one takes a line two spans share: every reported sink line maps to a
    flow at that line, which ``emit_for_line`` emits."""
    if not flows:
        return {}
    buffer = _parsed_buffer(model.nl_lines.text)
    return {line: flow for flow in flows for line in _span_lines(flow, buffer)}


def _parsed_buffer(text: str) -> tuple[str, str] | tuple[bytes, bytes]:
    """The buffer the worker parsed (``_nodes.parsed_buffer``), as ``_span_lines`` counts in
    it, with its newline."""
    data = parsed_buffer(text)
    return (data, "\n") if isinstance(data, str) else (data, b"\n")


def _span_lines[B: (str, bytes)](flow: Flow, buffer: tuple[B, B]) -> range:
    """The lines of ``flow``'s sink span over the parsed buffer (``_parsed_buffer``)."""
    data, newline = buffer
    start, end = flow.span
    return range(flow.sink_line, flow.sink_line + data.count(newline, start, end) + 1)
