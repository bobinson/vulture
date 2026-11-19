"""The consumer head (feature 0102, LLD §5, §9.2, §9.3, §10.1; D9, D11, D19, D21; A28, A30,
A40 (3), A41).

A skill that migrates a check to the AST tier keeps ONE ``FamilyRule`` per check — the
identity strings its regex body and its AST head both emit (D19) — and reaches the layer
through three functions:

* ``family_spans(model, rule, ctx, path, *, server_ctx)`` decides (``flow.decide``, §8.5)
  each candidate of the rule's family that the rule accepts (``FamilyRule.accepts``, feature
  0105; every one, for a rule without it) and maps EVERY line of each reported sink's span to
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

``argument_lines(spans, nl_lines, flows)`` (feature 0105, LLD §4.6) maps each sink line of a
rule's spans to that line, its flows' argument lines (``Flow.arg_span``) and its program
argument's lines (``Flow.program_span``), counted in the parsed buffer as a span's lines are,
none past the file's last: what a cover test reads where a span's lines hold the whole call.
``family_flows`` gives ``family_spans``' spans together with the flows they are built from, and
``sink_flows`` maps each sink line to every flow reported at the sink of the line's own flow
(its one flow when none is recorded): a sink with several sink arguments has a flow per
argument, of which the spans keep one, and another sink on the same line is a group of its own.

Feature 0104 A2 (OD-2, S1–S4) reports a file's hint-only rows of one rule as ONE row. The head
picks the file's group (``hint_groups``) and stamps each member's row as it appends it
(``stamp_member``), so the per-finding events, the line collapse, the LLM tier's dedup and the
code window see each member's own row; ``fold_hint_groups`` then makes the group row, once
every row the agent emits is known, unless it refuses the group (it says when: R1, R2, D-S (2)
and (5)). The group row keeps its members' rows (``hint_rows``), which the validate stage
restores when its own reads disagree (R5).

A rule may carry ONE named heuristic (``FamilyRule.heuristic``): ``command_param`` (D25,
A42 (1), A43 (1)) is the CWE-78 command rule's — a flow whose origins are UNKNOWN-only,
holding ``unknown(param)`` or ``unknown(argv)`` (A47 D22-c), at a sink that shells the
argument, of a built argument or of the whole command of a profile builtin process API, with
no same-file caller binding the parameter, reports. It is a heuristic, not data flow, and says
so on its row (``validation.flow.heuristic``). The command family has two rules (feature 0105,
LLD §4.5): each takes the flows E4 gives it (``CLASS_REPORTS``: ``process_flow`` for CWE-78,
``statement_flow`` for CWE-89), and the CWE-89 rule asks ``command_param``'s question under
its own token (``statement_param``).

``import shared.ast`` stays a leaf (D1): a skill reads ``FamilyRule`` and ``OWNED_CHECK_IDS``
at import time, so the flow engine, the profiles and the model are imported where a function
first needs them — by then a model exists and has loaded them.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence, Set
from dataclasses import dataclass
from functools import cache, partial
from itertools import chain, groupby
from operator import attrgetter
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol

from shared.ast import MODEL_SCHEMA, VALIDATION_KEYS
from shared.ast._nodes import parsed_buffer
from shared.ast._records import (
    ARGV,
    PARAM,
    PARAM_HINT_ROLE,
    STORE,
    TEXT,
    UNPROVEN,
    hint_only,
    real_external,
)
from shared.ast.declines import render_origins
from shared.ast.limits import MAX_GROUP_SINKS
from shared.lines import parse_line
from shared.provenance import MERGED_LLM_MAX_ENTRIES, is_llm_provenance
from shared.tools.finding_collapse import reconciled_on_line, severity_rank
from shared.tools.snippet import extract_snippet

if TYPE_CHECKING:
    from shared.ast._records import Flow, Origins
    from shared.ast.answer import FileFacts
    from shared.ast.context import AuditContext

__all__ = [
    "CLASS_REPORTS",
    "COMMAND_PARAM",
    "OWNED_CHECK_IDS",
    "STATEMENT_PARAM",
    "FamilyRule",
    "RuleIdentity",
    "argument_lines",
    "command_param",
    "emit_for_line",
    "family_flows",
    "family_spans",
    "flow_to_finding",
    "fold_hint_groups",
    "group_to_finding",
    "hint_groups",
    "hint_rows",
    "process_flow",
    "rule_row",
    "sink_flows",
    "sink_lines",
    "stamp_member",
    "statement_flow",
    "statement_param",
    "without_rows",
]

type Finding = dict[str, Any]
# What ``emit_for_line`` applies to a row before it appends it: (row, rule.cwe_id) -> row.
type Enrich = Callable[[Finding, str], Finding]

# The check ids the AST tier owns on every file it parses cleanly (LLD §9): the ``path`` and
# ``request`` families' rules and the ``command`` family's CWE-78 rule (§9.2, §9.3). The command
# family's CWE-89 rule (feature 0105) owns no check id: its regex body runs on every line, and
# an AST row of it stands only where no regex row covers its flow.
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
# A2 (S3): ``validation.flow``'s key for a group row's member sink lines.
_SINKS_KEY = "sinks"
# A2: the private keys of a member row's stamp (its group's sink lines, the anchor's first) and
# of the member rows a group row stands for. Private, so no emit carries them (``_public_view``).
_GROUP_KEY = "_hint_group"
_ROWS_KEY = "_hint_rows"
# A2: what the line collapse leaves on the row it keeps, its absorbed ancestors. A member row
# that carries it stands for more than its line, so its group is refused.
_COLLAPSED_KEY = "collapsed_from"
# What the agent's dedup leaves on a deterministic row it keeps, the LLM rows it dropped against
# it (0074 C3). The group row carries its members' (``_llm_merges``).
_MERGED_LLM_KEY, _DROPPED_KEY = "merged_llm", "merged_llm_dropped"
# D25's token (A42 (1)): stable, it names the command parameter heuristic on every row it
# reports and in SKILLS.md.
COMMAND_PARAM = "command_param"
# The same heuristic's token on the CWE-89 rule's rows (``statement_param``; feature 0105, LLD
# §4.5).
STATEMENT_PARAM = "statement_param"
# What D25 keys on: ``unknown(param)``, and ``unknown(argv)`` read as it (A47 D22-c). One set,
# so a flow is tested by the hashes both sets store.
_COMMAND_KEYS: Origins = frozenset({PARAM, ARGV})


@dataclass(frozen=True, slots=True)
class FamilyRule:
    """One migrated check (§5, D11, D19): its ``family``, its check id and the identity strings
    both tiers emit, and ``cwe_id``, the catalog number ``enrich`` reads. Three optional hooks:

    * ``gate``, ``(flow, server_ctx) -> keep?``, set only for the SSRF rule, reading
      ``Flow.sink_key`` (§9.3, A40 (3)): ``decide`` returns ``none`` for a flow it refuses;
    * ``heuristic``, ``flow -> token or None``, set only for the command rules
      (``command_param``, D25, A42 (1); ``statement_param``, feature 0105): ``decide`` asks it
      for a flow with no external origin, and a token reports the flow unless a covering guard
      declines it;
    * ``accepts`` (feature 0105, LLD §4.5), the flows the rule may report (``process_flow``,
      ``statement_flow``; None: every flow): ``family_spans`` leaves out every other flow
      before ``decide``, so two rules of one family decide each accepted flow once (a flow
      neither rule accepts is never decided)."""

    family: str
    check_id: str
    category: str
    title: str
    severity: str
    recommendation: str
    cwe_id: str
    gate: Callable[[Flow, bool], bool] | None = None
    heuristic: Callable[[Flow], str | None] | None = None
    accepts: Callable[[Flow], bool] | None = None


def command_param(flow: Flow) -> str | None:
    """D25 (§8.5, A42 (1), A43 (1)), the CWE-78 command rule's hook: ``COMMAND_PARAM`` when the flow
    holds ``unknown(param)`` or ``unknown(argv)`` (A47 D22-c) at a sink that shells the
    argument, of a built argument or of a profile builtin's whole command, and no same-file
    caller bound the parameter (``Flow.shell_sink``, ``built_arg``, ``builtin_program``,
    ``param_bound``: set on a flow holding ``unknown(param)`` only, so it supersedes one holding
    both); else None. ``decide`` asks it only for a flow with no external origin."""
    return _param_token(COMMAND_PARAM, flow)


def statement_param(flow: Flow) -> str | None:
    """The CWE-89 command rule's hook (feature 0105, LLD §4.5): ``command_param``'s question
    (``_param_token``) under its own token, ``STATEMENT_PARAM``."""
    return _param_token(STATEMENT_PARAM, flow)


def _param_token(token: str, flow: Flow) -> str | None:
    """``token`` when the flow holds ``unknown(param)`` or ``unknown(argv)`` at a command
    (``_param_at_a_command``) and no same-file caller bound the parameter; else None."""
    return token if _param_at_a_command(flow) and not flow.param_bound else None


def _param_at_a_command(flow: Flow) -> bool:
    """The flow holds ``unknown(param)`` or ``unknown(argv)``, and its sink shells the
    argument, it is built or it is a profile builtin's whole command."""
    held = not flow.origins.isdisjoint(_COMMAND_KEYS)
    return held and (flow.shell_sink or flow.built_arg or flow.builtin_program)


# E4 (feature 0105, LLD §4.5): a flow's ``command_class`` -> the CWE of the rule that reports
# it, and whether the flow needs a real external origin (``real_external``) to be reported there.
CLASS_REPORTS: Mapping[str, tuple[str, bool]] = MappingProxyType({
    "": ("78", False), UNPROVEN: ("78", True), TEXT: ("89", False), STORE: ("89", True),
})


def _class_flow(rule: str, flow: Flow) -> bool:
    """0105 E4: the rule of CWE ``rule`` reports ``flow`` (``CLASS_REPORTS``)."""
    owner, real = CLASS_REPORTS[flow.command_class]
    return owner == rule and (not real or real_external(flow.origins))


# The two command rules' ``accepts`` (feature 0105, LLD §4.5): CWE-78's and CWE-89's flows.
process_flow: Callable[[Flow], bool] = partial(_class_flow, "78")
statement_flow: Callable[[Flow], bool] = partial(_class_flow, "89")


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
    named heuristic ``decide`` reported the flow on (D25), or ``param_hint`` on a hint-only
    flow (A1), only when one applies."""
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
    reported ``flow`` on (``flow.named_heuristic``, the one question both ask), else
    ``param_hint`` on a hint-only flow (A1, ``_hint_token``); nothing when neither applies."""
    from shared.ast.flow import named_heuristic

    token = named_heuristic(flow, rule) or _hint_token(flow)
    return {} if token is None else {_HEURISTIC_KEY: token}


def _hint_token(flow: Flow) -> str | None:
    """A1 (HT-9): ``param_hint`` on a hint-only flow, else None."""
    return PARAM_HINT_ROLE if hint_only(flow.origins) else None


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
    then, on the sink line itself (``sink_lines``), ``enrich(flow_to_finding(...),
    rule.cwe_id)`` appended to ``findings``: one row per sink, however many lines its call
    spans."""
    flow = spans.get(line_num)
    if flow is None:
        return False
    if line_num == flow.sink_line:
        row = flow_to_finding(flow, rule, file_path=file_path, nl_lines=nl_lines)
        findings.append(enrich(row, rule.cwe_id))
    return True


def sink_lines(spans: Mapping[int, Flow] | None) -> Iterator[int]:
    """The lines of ``spans`` ``emit_for_line`` appends a row at: of each reported span's lines,
    its flow's sink line alone (one row per sink, however many lines its call spans)."""
    return (n for n, flow in (spans or {}).items() if n == flow.sink_line)


# ── 0104 A2: a file's hint-only rows as one row (OD-2; S1–S4, R1, R2, R5) ────

# A group's key while its rows are gathered: the file, the check id and the stamp.
type _GroupKey = tuple[Any, Any, tuple[int, ...]]
# Where a row stands: its file as ``path_key`` names it, and its line.
type _Site = tuple[str, int]


def hint_groups(spans: Mapping[int, Flow] | None, excluded: Set[int]) -> tuple[int, ...]:
    """A2's candidate group of ``spans`` (one file, one rule): the sink lines of the rows
    ``emit_for_line`` appends, less ``excluded`` (those a child replaces and those the head's
    line loop never reads), sorted, the lowest (the anchor's, S3) first — when there are two to
    ``MAX_GROUP_SINKS`` of them (a larger file keeps its rows) and every row is hint-only (HT-7,
    per row); else ``()``. A D25 or mixed-origin row is not hint-only, so it keeps every row of
    its file apart (S1, S4)."""
    rows = _row_flows(spans or {}, excluded)
    return tuple(sorted(rows)) if _groupable(rows.values()) else ()


def _row_flows(spans: Mapping[int, Flow], excluded: Set[int]) -> dict[int, Flow]:
    """Sink line -> the flow of each row ``emit_for_line`` appends (``sink_lines``), less
    ``excluded``."""
    return {n: spans[n] for n in sink_lines(spans) if n not in excluded}


def _groupable(flows: Collection[Flow]) -> bool:
    """Two to ``MAX_GROUP_SINKS`` rows, each hint-only (``hint_only``, HT-7)."""
    return 2 <= len(flows) <= MAX_GROUP_SINKS and all(hint_only(f.origins) for f in flows)


def stamp_member(row: Finding, sinks: tuple[int, ...]) -> None:
    """A2: mark ``row`` a member of its file's group, ``sinks`` the group's sink lines (the
    anchor's first). The stamp is private, so no emit carries it."""
    row[_GROUP_KEY] = sinks


def fold_hint_groups(findings: list[Finding], path_key: Callable[[str], str]) -> list[Finding]:
    """A2: ``findings`` — every row the agent emits: the skills' rows after the line collapse
    and the LLM tier's — with each stamped group's member rows replaced, at the anchor's place,
    by the group row (``group_to_finding``), unless the group is refused. Refused, its rows stay
    as they are: a member's row missing, out of place or kept by the line collapse
    (``collapsed_from``), or a deterministic row (not ``_llm``) standing at a member's site that
    one line reconciles with it — of the CWE's dedup family, or a ChildOf ancestor or
    descendant (``reconciled_on_line``; R1, R2), the file named as ``path_key`` names it.
    D-S (2): an LLM-family row never stands beside a member — the model's answer varies from
    run to run — with one exception, D-S (5): one reconciled with the ANCHOR's row at its site,
    of a severity strictly above the anchor's (``_evicted``; the other members' severities do
    not count), refuses too. An LLM-family row is never touched: the same row, in its place. A
    member's LLM merges (``merged_llm``, ``merged_llm_dropped``) never refuse: they ride on the
    group row (``_llm_merges``). Every stamp is taken off.

    Both rules read one index, every row at a member line (``_standing``). ``path_key`` is pure
    within a fold, so it names each raw path once (``cache``); and while no LLM-family row
    stands at a member line, no anchor is looked up for eviction (``_unevicted``).

    Another agent's rows are not seen here; only this agent's own are. So the backend's eviction
    is refused here for this agent's LLM rows only (D-S (5)): in the backend's merge another
    agent's LLM row of a higher severity at the anchor's line still evicts the group, and a row
    corroborating the anchor's line lifts every member's confidence (OD-2 effects (f) and (g),
    R3 and R4)."""
    groups = _stamped(findings)
    if not groups:
        return findings
    file_key = cache(path_key)
    standing = _standing(findings, groups, file_key)
    crowded = partial(_crowded, standing=standing, path_key=file_key)
    evicted = (
        partial(_evicted, standing=standing, path_key=file_key)
        if any(map(_llm, chain.from_iterable(standing.values())))
        else _unevicted
    )
    return _replaced(findings, _folds(groups, crowded, evicted))


def _stamped(findings: Iterable[Finding]) -> dict[_GroupKey, list[Finding]]:
    """Each group's member rows, in their order, keyed by file, check id and stamp; every
    stamp taken off."""
    groups: dict[_GroupKey, list[Finding]] = {}
    for finding in findings:
        sinks = finding.pop(_GROUP_KEY, None)
        if sinks:
            key = (finding.get("file_path"), finding.get("check_id"), sinks)
            groups.setdefault(key, []).append(finding)
    return groups


def _standing(
    findings: Iterable[Finding], groups: Iterable[_GroupKey], path_key: Callable[[str], str]
) -> dict[_Site, list[Finding]]:
    """Every row of ``findings``, of either tier, on a member line of ``groups`` (each key's
    stamp; an anchor's line is one), by the site it stands at (``_site``): the rows both rules
    read (``_crowded``, ``_evicted``)."""
    lines = set(chain.from_iterable(key[-1] for key in groups))
    standing: dict[_Site, list[Finding]] = {}
    for finding in findings:
        if parse_line(finding.get("line_start")) in lines:
            standing.setdefault(_site(finding, path_key), []).append(finding)
    return standing


def _site(finding: Finding, path_key: Callable[[str], str]) -> _Site:
    """Where ``finding`` stands: its file as ``path_key`` names it, and its line."""
    return path_key(str(finding.get("file_path") or "")), parse_line(finding.get("line_start"))


def _folds(
    groups: Mapping[_GroupKey, list[Finding]],
    crowded: Callable[[Finding], bool],
    evicted: Callable[[Finding], bool],
) -> dict[int, list[Finding]]:
    """The groups to fold: the anchor row's identity -> the member rows."""
    return {
        id(rows[0]): rows
        for key, rows in groups.items()
        if _foldable(key[-1], rows, crowded, evicted)
    }


def _foldable(
    sinks: tuple[int, ...],
    rows: Sequence[Finding],
    crowded: Callable[[Finding], bool],
    evicted: Callable[[Finding], bool],
) -> bool:
    """Every member's row is there, once, in line order, none is ``crowded`` (``_crowded``,
    D-S (2)), and the anchor's, ``rows[0]``, is not ``evicted`` (``_evicted``, D-S (5))."""
    return _lines(rows) == sinks and not any(map(crowded, rows)) and not evicted(rows[0])


def _lines(rows: Iterable[Finding]) -> tuple[int, ...]:
    """The line of each of ``rows`` (``parse_line``), in their order."""
    return tuple(parse_line(row.get("line_start")) for row in rows)


def _crowded(
    row: Finding, standing: Mapping[_Site, list[Finding]], path_key: Callable[[str], str]
) -> bool:
    """The line collapse kept ``row`` for another row (``collapsed_from``), or a row reconciled
    with it at its site (``_reconciled``; R1, R2) is not LLM-family (``_llm``)."""
    if row.get(_COLLAPSED_KEY):
        return True
    return any(not _llm(other) for other in _reconciled(row, standing, path_key))


def _evicted(
    anchor: Finding, standing: Mapping[_Site, list[Finding]], path_key: Callable[[str], str]
) -> bool:
    """D-S (5): an LLM-family row reconciled with the ``anchor`` row at its site
    (``_reconciled``), of a severity strictly above the anchor's (``_outranks``). The backend's
    merge keeps that row in the anchor's place, so the group row and every member folded into
    it would leave the persisted set; no other LLM-family row refuses a group (D-S (2)).

    Reconciled is the backend's dedup family key PLUS ChildOf (``reconciled_on_line``), so this
    over-refuses on purpose for a ChildOf relation the Go backend does not merge — safe: the
    members just stay apart."""
    here = _reconciled(anchor, standing, path_key)
    return any(_llm(other) and _outranks(other, anchor) for other in here)


def _unevicted(_anchor: Finding) -> bool:
    """``_evicted`` while no LLM-family row stands at a member line: False, with no lookup."""
    return False


def _reconciled(
    row: Finding, standing: Mapping[_Site, list[Finding]], path_key: Callable[[str], str]
) -> Iterator[Finding]:
    """The rows of ``standing`` at ``row``'s site (``_site``), other than ``row``, that one line
    reconciles with it (``reconciled_on_line``), in their order, lazily."""
    here = standing.get(_site(row, path_key), ())
    return (other for other in here if other is not row and reconciled_on_line(other, row))


def _llm(row: Finding) -> bool:
    """``row`` is LLM-family (``is_llm_provenance``, the backend's rule; a row with no
    provenance is deterministic)."""
    return is_llm_provenance(row.get("provenance"))


def _outranks(row: Finding, anchor: Finding) -> bool:
    """``row``'s severity ranks strictly above ``anchor``'s (``severity_rank``, the project's
    order; an equal severity does not)."""
    return severity_rank(row.get("severity")) > severity_rank(anchor.get("severity"))


def _replaced(findings: Iterable[Finding], folds: Mapping[int, list[Finding]]) -> list[Finding]:
    """``findings`` with each folded group's anchor row replaced by the group row and its
    other members' rows left out."""
    hidden = _hidden(folds)
    return [_folded(finding, folds) for finding in findings if id(finding) not in hidden]


def _hidden(folds: Mapping[int, list[Finding]]) -> set[int]:
    """The identities of the folded groups' member rows other than the anchor's."""
    return {id(row) for rows in folds.values() for row in rows[1:]}


def _folded(finding: Finding, folds: Mapping[int, list[Finding]]) -> Finding:
    """The group row when ``finding`` is a folded group's anchor row, else ``finding``."""
    rows = folds.get(id(finding))
    return finding if rows is None else group_to_finding(rows)


def group_to_finding(rows: Sequence[Finding]) -> Finding:
    """A2 (S3): the group row of ``rows`` (a group's member rows, the anchor's first): the
    anchor's row, its description naming the count of sinks (never an identifier), and
    ``validation.flow.sinks``, the members' sink lines, sorted (``MAX_GROUP_SINKS`` at most:
    ``hint_groups`` makes no larger group), and the members' LLM merges in place of the
    anchor's own (``_llm_merges``). It keeps ``rows`` for ``hint_rows``, each with exactly its
    own merges."""
    anchor = rows[0]
    sinks = list(_lines(rows))
    validation = dict(anchor["validation"])
    validation[_FLOW_KEY] = {**validation[_FLOW_KEY], _SINKS_KEY: sinks}
    description = (
        f"{anchor['title']}: untrusted input reaches {len(sinks)} sinks, the first at line "
        f"{sinks[0]}"
    )
    return {
        **anchor, "description": description, "validation": validation, **_llm_merges(rows),
        _ROWS_KEY: tuple(rows),
    }


def _llm_merges(rows: Sequence[Finding]) -> dict[str, Any]:
    """The LLM tier's merges ``rows`` (a group's members) carry (0074 C3), on new containers:
    ``merged_llm``, their entries in member order (the anchor's first), each once
    (``_member_merges``), at most ``MERGED_LLM_MAX_ENTRIES`` of them (contract T3), and
    ``merged_llm_dropped``, the sum of their counts plus the entries past that cap — each key
    only when it holds one (C3: omitted when empty). No member's own list or count is touched."""
    entries = _member_merges(rows)
    kept, past = entries[:MERGED_LLM_MAX_ENTRIES], entries[MERGED_LLM_MAX_ENTRIES:]
    merges = {_MERGED_LLM_KEY: kept, _DROPPED_KEY: _dropped(rows) + len(past)}
    return {key: value for key, value in merges.items() if value}


def _dropped(rows: Iterable[Finding]) -> int:
    """The sum of the ``merged_llm_dropped`` counts of ``rows`` (none counts 0)."""
    return sum(row.get(_DROPPED_KEY) or 0 for row in rows)


def _member_merges(rows: Iterable[Finding]) -> list[dict[str, Any]]:
    """The ``merged_llm`` entries of ``rows``, in their order, each once — an entry equal (as a
    dict) to an earlier one is dropped — on a new list: one pass, a set lookup per entry by
    its items (its values are strings and flags, ``audit_runner._merged_llm_entry``)."""
    unique: dict[frozenset[tuple[str, Any]], dict[str, Any]] = {}
    for entry in chain.from_iterable(row.get(_MERGED_LLM_KEY) or () for row in rows):
        unique.setdefault(frozenset(entry.items()), entry)
    return list(unique.values())


def hint_rows(finding: Finding) -> Sequence[Finding]:
    """The rows ``finding`` stands for: a group row's member rows as they were folded (the
    anchor's first), which the validate stage restores when it ungroups (R5); any other row,
    itself."""
    return finding.get(_ROWS_KEY) or (finding,)


def without_rows(finding: Finding) -> Finding:
    """A copy of ``finding`` without the member rows a group row keeps: the validate stage is
    their last reader."""
    row = dict(finding)
    row.pop(_ROWS_KEY, None)
    return row


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
    (§8.5). The analysis' fact counts reach ``ctx``'s coverage once per file. The spans of
    ``family_flows``."""
    return family_flows(model, rule, ctx, path, server_ctx=server_ctx)[0]


def family_flows(
    model: FileFacts,
    rule: FamilyRule,
    ctx: AuditContext,
    path: str | Path,
    *,
    server_ctx: bool = True,
) -> tuple[dict[int, Flow], Sequence[Flow]]:
    """``family_spans``' spans, and the flows they are built from: every flow ``decide``
    reports, in its order, hint-only ones included, which ``sink_flows`` reads by sink (feature
    0105, LLD §4.6). One ``decide`` pass gives both, so each decline is recorded once
    (A30 (1))."""
    from shared.ast.profile import PROFILES

    analysis = model.analysis()
    ctx.coverage.record_analysis(path, analysis.tallies)
    server_like = server_ctx or not PROFILES[model.language].browser_capable
    reported = _reported(analysis.candidates(rule.family), rule, ctx, path, server_like)
    return _by_line(model, reported), reported


def _reported(
    flows: Iterable[Flow], rule: FamilyRule, ctx: AuditContext, path: str | Path, server_ctx: bool
) -> list[Flow]:
    """The ``flows`` ``decide`` reports, in their order; it records the declines (§8.5). A
    flow the rule does not accept (``_accepted``) is never decided for it."""
    from shared.ast.flow import decide

    found = _accepted(flows, rule)
    return [f for f in found if decide(f, rule, ctx, path=path, server_ctx=server_ctx) == "report"]


def _accepted(flows: Iterable[Flow], rule: FamilyRule) -> Iterable[Flow]:
    """The ``flows`` ``rule.accepts`` keeps (feature 0105, LLD §4.5), in their order; all of
    them without one."""
    return flows if rule.accepts is None else filter(rule.accepts, flows)


def _by_line(model: FileFacts, flows: Sequence[Flow]) -> dict[int, Flow]:
    """Each line of each flow's sink span -> the flow. A span is a byte span of the buffer the
    worker parsed (§4), so its lines are counted there, by ``\\n`` only (D21): the buffer is
    read once (``_parsed_buffer``), and only when a flow was reported. The flows come sorted by
    sink line, so a later one takes a line two spans share: every reported sink line maps to a
    flow at that line, which ``emit_for_line`` emits. Within one sink line the hint-only flows
    go first (A1, ``_hint_first``), so a non-hint flow there takes the lines they share."""
    if not flows:
        return {}
    buffer = _parsed_buffer(model.nl_lines.text)
    ordered = sorted(flows, key=_hint_first)
    return {line: flow for flow in ordered for line in _span_lines(flow, buffer)}


def _hint_first(flow: Flow) -> tuple[int, bool]:
    """A1 tie-break key: the sink line, then non-hint after hint-only (a stable sort keeps the
    order within each)."""
    return flow.sink_line, not hint_only(flow.origins)


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


def sink_flows(
    spans: Mapping[int, Flow], reported: Iterable[Flow] = ()
) -> dict[int, Sequence[Flow]]:
    """Each sink line of ``spans`` (``sink_lines``) -> every flow of ``reported``
    (``family_flows``' list) at the sink of the line's own flow (``Flow.sink``, its call),
    hint-only ones first (``_sink_first``): the flows of that one sink, never another sink's
    on the same line (feature 0105, LLD §4.6). A line whose sink has none of them (none
    recorded) -> its own flow alone. Line ownership keeps one flow per line (``_by_line``)."""
    ordered = sorted(reported, key=_sink_first)
    at = {sink: tuple(flows) for sink, flows in groupby(ordered, attrgetter("sink"))}
    return {line: at.get(spans[line].sink, (spans[line],)) for line in sink_lines(spans)}


def _sink_first(flow: Flow) -> tuple[int, bool]:
    """``sink_flows``' key: the sink node, then non-hint after hint-only, so each sink's flows
    keep ``_hint_first``'s order (a stable sort keeps the order within each; feature 0105, LLD
    §4.6)."""
    return flow.sink, not hint_only(flow.origins)


def argument_lines(
    spans: Mapping[int, Flow],
    nl_lines: Sequence[str],
    flows: Mapping[int, Sequence[Flow]] | None = None,
) -> dict[int, Sequence[int]]:
    """Each sink line of ``spans`` (``sink_lines``) -> that line, then the lines of the argument
    (``Flow.arg_span``) and of the sink's program argument (``Flow.program_span``; feature 0105,
    LLD §4.4) of each flow ``flows`` gives it (``sink_flows``' map: every flow reported at the
    sink), sorted, each once; without ``flows``, its own flow's alone (feature 0105, LLD §4.6).
    The lines a statement sink's arguments are written on, where its span's lines hold the whole
    call (a callback body, later arguments). Counted as ``_span_lines`` counts a span's, in the
    buffer the worker parsed, read once from the model's ``nl_lines`` (a ``Lines``, as
    ``_by_line`` reads them). None past the last of ``nl_lines``: D3' bounds a span by the bytes
    and the sink line by the lines, not one by another, so a forged answer can count lines past
    the file's end, which hold no text."""
    buffer = _parsed_buffer(nl_lines.text)
    at = sink_flows(spans) if flows is None else flows
    last = len(nl_lines)
    return {line: _flows_lines(at[line], buffer, last) for line in sink_lines(spans)}


def _flows_lines[B: (str, bytes)](
    flows: Iterable[Flow], buffer: tuple[B, B], last: int
) -> list[int]:
    """The sink line, the argument lines and the program argument's lines of every one of
    ``flows`` (``_flow_lines``), sorted, each once, none past ``last`` (feature 0105, LLD §4.6)."""
    return sorted({n for flow in flows for n in _flow_lines(flow, buffer) if n <= last})


def _flow_lines[B: (str, bytes)](flow: Flow, buffer: tuple[B, B]) -> Iterable[int]:
    """``flow``'s sink line and argument lines (``_arg_lines``), then its sink's program
    argument's lines (``Flow.program_span``; feature 0105, LLD §4.4) when recorded: the node
    the classifier reads statement text from, which may be no reported flow's argument (feature
    0105, LLD §4.6)."""
    if flow.program_span is None:
        return _arg_lines(flow, buffer)
    return chain(_arg_lines(flow, buffer), _node_lines(flow, flow.program_span, buffer))


def _arg_lines[B: (str, bytes)](flow: Flow, buffer: tuple[B, B]) -> Sequence[int]:
    """``flow``'s sink line, then its argument's lines (``_node_lines``). A flow built without
    an argument span (None) gets its whole sink span's lines (``_span_lines``), as a cover test
    read a sink before the field."""
    if flow.arg_span is None:
        return _span_lines(flow, buffer)
    return _node_lines(flow, flow.arg_span, buffer)


def _node_lines[B: (str, bytes)](
    flow: Flow, node: tuple[int, int], buffer: tuple[B, B]
) -> Sequence[int]:
    """``flow``'s sink line, then the lines of ``node``, the byte span of one of its sink's
    arguments, over the parsed buffer: the node starts as many lines below the sink line as
    newlines stand between the sink span's start and its own (feature 0105, LLD §4.6)."""
    data, newline = buffer
    start, end = node
    first = flow.sink_line + data.count(newline, flow.span[0], start)
    lines = range(first, first + data.count(newline, start, end) + 1)
    return lines if first == flow.sink_line else (flow.sink_line, *lines)
