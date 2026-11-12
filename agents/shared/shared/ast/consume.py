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

Feature 0104 A2 (OD-2, S1–S4) reports a file's hint-only rows of one rule as ONE row. The head
picks the file's group (``hint_groups``) and stamps each member's row as it appends it
(``stamp_member``), so the per-finding events, the line collapse, the LLM tier's dedup and the
code window see each member's own row; ``fold_hint_groups`` then makes the group row, once
every row the agent emits is known, unless a deterministic row would be reconciled with a
member at its line (R1, R2), or a strictly more severe LLM row with the anchor at its line, which
the backend's merge would keep in the group row's place (D-S (5)); no other LLM row refuses a
group (D-S (2)). The group row keeps its members' rows (``hint_rows``), which the validate
stage restores when its own reads disagree (R5).

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

from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence, Set
from dataclasses import dataclass
from functools import partial
from itertools import chain
from operator import is_not
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from shared.ast import MODEL_SCHEMA, VALIDATION_KEYS
from shared.ast._nodes import parsed_buffer
from shared.ast._records import ARGV, PARAM, PARAM_HINT_ROLE, hint_only
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
    "COMMAND_PARAM",
    "OWNED_CHECK_IDS",
    "FamilyRule",
    "RuleIdentity",
    "command_param",
    "emit_for_line",
    "family_spans",
    "flow_to_finding",
    "fold_hint_groups",
    "group_to_finding",
    "hint_groups",
    "hint_rows",
    "rule_row",
    "sink_lines",
    "stamp_member",
    "without_rows",
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
    by the group row (``group_to_finding``), unless the group is refused. It decides on the
    deterministic rows (D-S (2)), with one exception (D-S (5)). Refused, its rows stay as they
    are: a member's row missing, out of place or kept by the line collapse (``collapsed_from``),
    or another row of no LLM-family provenance (``is_llm_provenance``; a row with none is
    deterministic) standing at a member line that one line reconciles with it — of the CWE's
    dedup family, or a ChildOf ancestor or descendant (``reconciled_on_line``; R1, R2), the file
    named as ``path_key`` names it. D-S (5): an LLM-family row at the ANCHOR's site that one
    line reconciles with the anchor's row, of a severity strictly above the anchor's
    (``severity_rank``; the other members' severities do not count), refuses too. An LLM-family
    row is never touched: the same row, in its place. A member's LLM merges (``merged_llm``,
    ``merged_llm_dropped``) never refuse: they ride on the group row (``_llm_merges``). Every
    stamp is taken off.

    Another agent's rows are not seen here; only this agent's own are. So the backend's eviction
    is refused here for this agent's LLM rows only (D-S (5)): in the backend's merge another
    agent's LLM row of a higher severity at the anchor's line still evicts the group, and a row
    corroborating the anchor's line lifts every member's confidence (OD-2 effects (f) and (g),
    R3 and R4)."""
    groups = _stamped(findings)
    if not groups:
        return findings
    standing = _standing(findings, _member_lines(groups), path_key)
    beside = _standing(findings, _anchor_lines(groups), path_key, llm=True)
    crowded = partial(_crowded, standing=standing, path_key=path_key)
    evicted = partial(_evicted, beside=beside, path_key=path_key)
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


def _member_lines(groups: Iterable[_GroupKey]) -> set[int]:
    """Every member's line of ``groups`` (each key's stamp)."""
    return {line_num for key in groups for line_num in key[-1]}


def _anchor_lines(groups: Iterable[_GroupKey]) -> set[int]:
    """D-S (5): each anchor's line of ``groups`` (the first of each key's stamp)."""
    return {key[-1][0] for key in groups}


def _standing(
    findings: Iterable[Finding],
    lines: Set[int],
    path_key: Callable[[str], str],
    *,
    llm: bool = False,
) -> dict[_Site, list[Finding]]:
    """Every row of ``findings`` of the tier ``llm`` names on one of ``lines``, by the site it
    stands at (``_site``, ``_tier_on``): the deterministic rows at the members' lines, the only
    rows that stand beside a member (D-S (2)), or the LLM rows at the anchors' lines, the only
    ones that can evict an anchor (D-S (5))."""
    standing: dict[_Site, list[Finding]] = {}
    for finding in findings:
        if _tier_on(finding, lines, llm):
            standing.setdefault(_site(finding, path_key), []).append(finding)
    return standing


def _tier_on(finding: Finding, lines: Set[int], llm: bool) -> bool:
    """``finding`` stands on one of ``lines`` and is LLM-family exactly when ``llm`` is
    (``is_llm_provenance``, the backend's rule; a row with none is deterministic). The model's
    answer varies from run to run, so an LLM row never stands beside a member (D-S (2)); it
    only refuses a group whose anchor it would evict (D-S (5))."""
    on_line = parse_line(finding.get("line_start")) in lines
    return on_line and is_llm_provenance(finding.get("provenance")) == llm


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
    """The line collapse kept ``row`` for another row (``collapsed_from``), or another row of
    ``standing`` its line reconciles with it stands at its line (R1, R2)."""
    return bool(row.get(_COLLAPSED_KEY)) or _reconciled_at(row, standing, path_key)


def _reconciled_at(
    row: Finding,
    standing: Mapping[_Site, list[Finding]],
    path_key: Callable[[str], str],
    admits: Callable[[Finding, Finding], bool] = is_not,
) -> bool:
    """A row ``other`` of ``standing`` at ``row``'s site that one line reconciles with it
    (``reconciled_on_line``) and that ``admits(other, row)``: by default, any but ``row``."""
    here = standing.get(_site(row, path_key), ())
    return any(admits(other, row) and reconciled_on_line(other, row) for other in here)


def _evicted(
    anchor: Finding, beside: Mapping[_Site, list[Finding]], path_key: Callable[[str], str]
) -> bool:
    """D-S (5): an LLM row of ``beside`` at the ``anchor`` row's site that one line reconciles
    with it, of a severity strictly above the anchor's (``_outranks``). The backend's merge
    keeps that row in the anchor's place, so the group row and every member folded into it
    would leave the persisted set."""
    return _reconciled_at(anchor, beside, path_key, _outranks)


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
