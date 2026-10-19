"""Data flow (feature 0102, LLD §8; A21, A27-A32): what one file's model says about values
reaching path, request and command sinks.

``FlowAnalysis(model)`` — built once per model by ``FileModel.analysis()``, pure and
memoised — answers:

* ``origins(node)``: the §8.1 origins of a node, by the §8.2 table (``RULES``) and the §8.4
  same-file rules (``_origins``);
* ``candidates(family)``: every sink of the family (§8.5, ``_calls``) in every context — the
  base and each callee summary (§8.4: emitted once per sink argument and canonical origin
  set, the call site as the first hop) — with at least one origin of any class after R-P,
  which runs HERE (A28 (3), (5)): an external origin whose role is outside
  ``SOURCE_ROLES_BY_FAMILY[family]`` is removed and named in ``Flow.filtered_roles``. A source
  read is never also a sink (L6). Sorted by sink line;
* ``guards_for(sink, arg)``: the guards of one sink argument (§8.5, ``_guards``);
* ``summary(fn, arg_origins)``: a local function's return origins under one binding (§8.4);
* ``tallies``: the per-file fact counts (A28 (3)) — ``origin_overflow``, ``summary_cap``,
  ``branch_depth`` — like ``FileModel.tallies``; the consumer adds them to the audit coverage
  once per unique file.

**What an analysis keeps (A35, A38).** The build runs the passes once — scope, origins, hops,
guards — collects the candidates of every family the model's language owns
(``owned_families``, in ``profiles.FAMILIES`` order; D-H: C and C++ own no ``request``) and
keeps only them and the tallies: ``bytes_estimate``, the footprint of what it keeps, is
computed then, and the model cache adds it to the model's entry. The passes are dropped, so a
cached model costs its candidates, not its derivation. An analysis refers to its model weakly:
a model and its analysis form no cycle, so reference counting frees an unheld model with its
analysis (none waits for a cyclic collection). ``origins``, ``guards_for`` and ``summary`` are
diagnostic queries — never on a production path, which reads ``candidates`` and ``decide`` —
and need the model held: the first one derives the passes again, replays the build on them
and keeps them, outside the charge. The replay makes every answer the build gave the
same — a callee's summary signatures are capped in the order its calls are met (§8.4), so a
query must meet them in the build's order — and lets each fact count once: the derived
passes count into the analysis' tallies only after the replay, so a query adds what the build
never met (A28 (3)), never a fact the build counted.

``decide`` (§8.5, A29, A30) turns a candidate into ``report``, ``decline`` (recorded on the
consumer's file through ``ctx.decline``) or ``none``; ``covered`` reads ``COVERED_BY``. A
rule's named heuristic (``FamilyRule.heuristic``, D25, A42 (1)) is asked there, for a flow
with no external origin, and ``named_heuristic`` is that one question, which the finding asks
again to name what ``decide`` acted on. A ``command`` flow carries the heuristic's per-flow
facts (``Flow.shell_sink``, ``built_arg``, ``builtin_program``, ``param_bound``; A43 (1)), set
here as each flow is built (the shared ``True``/``False``, so they add nothing to a footprint
but the record's slots).
Every §9.1 table, ``COVERED_BY`` and ``COVERING_GUARDS`` included, is imported from ``roles``, never
copied (A27 (5)). A model is shared across audit threads: the candidates never change once
built, and every diagnostic query runs under one module lock (they are rare, so no analysis
keeps a lock of its own). Nothing here imports
``tree_sitter``, ``shared.tools`` or ``shared.validate`` (D1).
"""

from __future__ import annotations

import os
import sys
import weakref
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import replace
from itertools import chain
from operator import attrgetter
from threading import RLock
from typing import TYPE_CHECKING, Literal, Protocol

from shared.ast._guards import Guards
from shared.ast._hops import Hops
from shared.ast._origins import BASE, CONSTANTS, RULES, Context, Engine
from shared.ast._records import (
    ANY,
    EXTERNAL,
    PARAM,
    Flow,
    Guard,
    Hop,
    Origin,
    Origins,
    external,
    externals,
    has_external,
    role_set,
    unknown,
)
from shared.ast._sizing import own_ints, own_strs, sized_once
from shared.ast.coverage import ENV_ONLY_SINKS, ROLE_FILTERED_SINKS, UNKNOWN_ONLY_SINKS
from shared.ast.profile import PROFILES
from shared.ast.profiles import COMMAND, FAMILIES
from shared.ast.roles import COVERED_BY, COVERING_GUARDS, NO_ROLES, SOURCE_ROLES_BY_FAMILY

if TYPE_CHECKING:
    from shared.ast.model import FileModel

__all__ = [
    "RULES",
    "Flow",
    "FlowAnalysis",
    "Guard",
    "Hop",
    "Origin",
    "covered",
    "decide",
    "external",
    "named_heuristic",
    "unknown",
]

type Verdict = Literal["report", "decline", "none"]


class _Rule(Protocol):
    """What ``decide`` reads of a rule (``consume.FamilyRule``, §9.2)."""

    @property
    def family(self) -> str: ...

    @property
    def gate(self) -> Callable[[Flow, bool], bool] | None: ...

    @property
    def heuristic(self) -> Callable[[Flow], str | None] | None: ...


class _Context(Protocol):
    """What ``decide`` writes to (``context.AuditContext``, D20, A30 (1))."""

    def tally(self, name: str, n: int = 1) -> None: ...

    def decline(self, path: str | os.PathLike[str], flow: Flow, rule: _Rule, label: str) -> None: ...


# ── coverage and decision (§8.3, §8.5) ───────────────────────────────────────


def covered(o: Origin, family: str) -> bool:
    """§8.3: an external origin whose ``via`` meets ``COVERED_BY[family]``."""
    return o.cls == EXTERNAL and not o.via.isdisjoint(COVERED_BY[family])


def decide(
    flow: Flow, rule: _Rule, ctx: _Context, *, path: str | os.PathLike[str], server_ctx: bool = True
) -> Verdict:
    """§8.5 ``decide`` (A29 (7), A30 (1)): R-P's tally; ``none`` with no origin or a failed
    gate; ``none`` (tallied) with no external origin, unless the rule's named heuristic names
    the flow (D25, A42 (1)); ``decline`` when every external origin is covered
    (``sanitized:``), or on the FIRST guard whose roles cover the family (``guarded:`` + its
    smallest covering role); else ``report``. Each step is §8.5's statement, split into
    helpers only to keep each function's branches few."""
    _tally_policy(flow, ctx)
    ext = externals(flow.origins)
    return _unreportable(flow, ext, rule, ctx, server_ctx) or _judged(flow, ext, rule, ctx, path)


def _unreportable(
    flow: Flow, ext: Origins, rule: _Rule, ctx: _Context, server_ctx: bool
) -> Verdict | None:
    """``none`` with no origin (constant-only, W15 (c)) or a failed gate; ``none``, tallied
    ``unknown_only_sinks``, with no external origin ``ext`` that the rule's named heuristic
    does not name (v1: tallied, not reported)."""
    if not flow.origins or not _gated(flow, rule, server_ctx):
        return "none"
    if _unknown_only(flow, ext, rule):
        ctx.tally(UNKNOWN_ONLY_SINKS)
        return "none"
    return None


def _unknown_only(flow: Flow, ext: Origins, rule: _Rule) -> bool:
    """No external origin ``ext``, and no named heuristic of the rule's names the flow."""
    return not ext and named_heuristic(flow, rule) is None


def named_heuristic(flow: Flow, rule: _Rule) -> str | None:
    """D25 (§8.5, A42 (1)): the token of the rule's named heuristic (``FamilyRule.heuristic``)
    when ``decide`` acts on it — for a flow with no external origin, which the hook names —
    else None. Both callers ask only about a flow with origins: ``decide`` has returned
    ``none`` for one with none before it asks, and a row is a reported flow. The one question
    both ``decide`` and the finding ask (§10.1), so a row names exactly what ``decide``
    reported it on."""
    if rule.heuristic is None or has_external(flow.origins):
        return None
    return rule.heuristic(flow)


def _judged(
    flow: Flow, ext: Origins, rule: _Rule, ctx: _Context, path: str | os.PathLike[str]
) -> Verdict:
    """``decline`` on a full sanitiser cover, else on the first covering guard; ``report``.
    A flow the named heuristic reports has no external origin, so no sanitiser cover (D8)."""
    label = _sanitized(ext, rule) or _guarded(flow, rule)
    if label is None:
        return "report"
    ctx.decline(path, flow, rule, label)
    return "decline"


def _policed(origins: Origins, family: str) -> tuple[Origins, frozenset[str]]:
    """R-P (A28 (3)): what of ``origins`` the family may report (``constant`` still in it) and
    the roles removed — the one shared empty role set when none was."""
    filtered = _outside_family(origins, family)
    if not filtered:
        return origins, NO_ROLES
    return origins - filtered, role_set(frozenset(o.role for o in filtered))


def _outside_family(origins: Origins, family: str) -> Origins:
    """R-P (D22): the external origins whose role the family may not report — never the
    overflow collapse's ``external(any)``, which is reportable everywhere (§8.1)."""
    allowed = SOURCE_ROLES_BY_FAMILY[family]
    return frozenset(o for o in externals(origins) if o.role not in allowed and o != ANY)


def _tally_policy(flow: Flow, ctx: _Context) -> None:
    """R-P ran inside ``candidates`` (A28 (3)): ``env_only_sinks`` when env was all it
    removed and nothing remains, else ``role_filtered_sinks``."""
    if flow.filtered_roles:
        env_only = flow.filtered_roles == {"env"} and not flow.origins
        ctx.tally(ENV_ONLY_SINKS if env_only else ROLE_FILTERED_SINKS)


def _gated(flow: Flow, rule: _Rule, server_ctx: bool) -> bool:
    """The rule's gate holds (the SSRF ``server_ctx`` gate, §9.3); no gate always holds."""
    return rule.gate is None or rule.gate(flow, server_ctx)


def _sanitized(ext: Origins, rule: _Rule) -> str | None:
    """``sanitized:`` + the sorted ``via`` roles when no external origin is uncovered."""
    if not _all_covered(ext, rule.family):
        return None
    return "sanitized:" + "+".join(sorted(chain.from_iterable(o.via for o in ext)))


def _all_covered(ext: Origins, family: str) -> bool:
    """There are external origins ``ext``, and every one is covered (§8.3): a flow with none —
    one the named heuristic reports — is never ``sanitized``."""
    return bool(ext) and all(covered(o, family) for o in ext)


def _guarded(flow: Flow, rule: _Rule) -> str | None:
    """L4: ``guarded:`` + the smallest covering role of the FIRST covering guard (A29 (7))."""
    cover = COVERING_GUARDS[rule.family]
    found = next(filter(None, (g.roles & cover for g in flow.guards)), None)
    return None if found is None else "guarded:" + min(found)


# ── the analysis ─────────────────────────────────────────────────────────────


# The one lock of the diagnostic queries (``origins``, ``guards_for``, ``summary``), every
# analysis's: they are rare and off the production path, so none needs a lock of its own.
_DIAGNOSTICS = RLock()


class FlowAnalysis:
    """One file's flow analysis (module docstring), built by ``FileModel.analysis()``.

    The build runs the passes once and keeps only their answer (A35, A38): the candidates of
    every family the model's language owns and the tallies. ``bytes_estimate`` — what the
    model cache charges the model's entry with — is the footprint of that answer, computed
    once, here. The model is held weakly. A diagnostic query (``origins``, ``guards_for``,
    ``summary``) derives the passes again on first use, the build replayed first; what it
    keeps is outside the charge."""

    __slots__ = ("_candidates", "_derived", "_model", "bytes_estimate", "tallies")

    def __init__(self, model: FileModel) -> None:
        self._model = weakref.ref(model)
        passes = _Passes(model)
        self._candidates = passes.build()
        self.tallies: Counter[str] = passes.engine.tallies
        self._derived: _Passes | None = None
        self.bytes_estimate = _footprint(self)

    def candidates(self, family: str) -> tuple[Flow, ...]:
        """Every ``family`` sink argument with an origin left after R-P, sorted by sink line;
        none for a family the model's language does not own (A38: the build's lookup)."""
        return self._candidates.get(family, ())

    def origins(self, node: int) -> frozenset[Origin]:
        """§8.2: the origins of ``node`` (the base context), memoised."""
        with _DIAGNOSTICS:
            return self._passes().engine.origins(node)

    def guards_for(self, sink: int, arg: int) -> tuple[Guard, ...]:
        """§8.5: the guards of the sink argument ``arg`` (A29)."""
        with _DIAGNOSTICS:
            return self._passes().guards.of(sink, arg)

    def summary(self, fn: int, arg_origins: Sequence[Origins]) -> Origins:
        """§8.4: ``fn``'s return origins with its parameters bound positionally to
        ``arg_origins`` (memoised on the canonical binding; ``summary_cap`` past
        ``MAX_SUMMARY_SIGNATURES``)."""
        with _DIAGNOSTICS:
            return self._passes().engine.summary(fn, arg_origins)

    def _passes(self) -> _Passes:
        """The passes a diagnostic query reads: derived again once, the build replayed on them
        (module docstring), then counting into the analysis' tallies."""
        if self._derived is None:
            replay = _Passes(self._held_model())
            replay.build()
            self._derived = replay.counting_into(self.tallies)
        return self._derived

    def _held_model(self) -> FileModel:
        """The model, which a diagnostic query needs held (the analysis refers to it weakly)."""
        model = self._model()
        if model is None:
            raise ReferenceError("a diagnostic query of a FlowAnalysis whose FileModel is gone")
        return model


class _Passes:
    """One derivation of a file's flow facts: the origin engine, the hops and the guards, and
    the candidates collected from them (each family once)."""

    def __init__(self, model: FileModel) -> None:
        self._m = model
        self.engine = Engine(model)
        self.hops = Hops(self.engine)
        self.guards = Guards(self.engine)
        self._expanded = 0
        self._carried_sets: dict[Origins, Origins] = {}

    def build(self) -> dict[str, tuple[Flow, ...]]:
        """The candidates of every family the model's language owns (A38), collected in
        ``FAMILIES`` order — the order the build meets its calls in."""
        owned = PROFILES[self._m.language].owned_families
        return {family: self.collect(family) for family in FAMILIES if family in owned}

    def counting_into(self, tallies: Counter[str]) -> _Passes:
        """These passes, counting every fact they meet from now on into ``tallies``."""
        self.engine.tallies = tallies
        return self

    def collect(self, family: str) -> tuple[Flow, ...]:
        """Each context's flows, once per sink argument, origin set and filtered roles (the
        first context's wins): the key is known before the hops and guards are built."""
        self._expand()
        flows: dict[tuple[object, ...], Flow] = {}
        for ctx, context in enumerate(self.engine.contexts):
            for site, arg in self._sink_args(context, ctx, family):
                self._add(flows, ctx, site, arg, family)
        found = tuple(sorted(flows.values(), key=attrgetter("sink_line")))
        return _params_bound(found) if family in COMMAND else found

    def _expand(self) -> None:
        """Run every local call of every context whose callee reaches a sink, so each summary
        context that can add a candidate exists (§8.4); a context made on the way is expanded
        too."""
        while self._expanded < len(self.engine.contexts):
            ctx = self._expanded
            self._expanded += 1
            self._run_local_calls(ctx)

    def _run_local_calls(self, ctx: int) -> None:
        """``_expand`` of one context: the origins of each of its local calls whose callee
        reaches a sink."""
        calls = self.engine.calls
        local, reaching = calls.local, calls.reaching_sinks()
        sites = calls.local_calls(_analysed_by(self.engine.contexts[ctx]))
        for site in (s for s in sites if local(s) in reaching):
            self.engine.origins(site, ctx)

    def _sink_args(self, context: Context, ctx: int, family: str) -> Iterator[tuple[int, int]]:
        """``(sink, argument)`` for each ``family`` sink argument the context analyses
        (``_analysed_by``) whose sink is no source read (L6: ``Engine.source_read``)."""
        calls = self.engine.calls
        for site in calls.family_sites(family, _analysed_by(context)):
            if not self.engine.source_read(site, ctx):
                yield from ((site, arg) for arg in calls.sink_args(site, family))

    def _add(
        self, flows: dict[tuple[object, ...], Flow], ctx: int, site: int, arg: int, family: str
    ) -> None:
        """R-P (A28 (3), (5)): a sink argument with no origin left is no candidate. A flow
        already found is not built again."""
        kept, filtered_roles = _policed(self.engine.origins(arg, ctx), family)
        if not kept:
            return
        key = (site, arg, self._carried(kept), filtered_roles)
        if key not in flows:
            flows[key] = self._flow(ctx, family, key)

    def _carried(self, kept: Origins) -> Origins:
        """W15 (c): what a flow carries — ``kept`` without ``constant`` — one set per distinct
        value, which every equal flow of the file shares. Each is the analysis' own (made here,
        never a set the process shares), so the footprint counts what the analysis keeps."""
        origins = kept - CONSTANTS
        return self._carried_sets.setdefault(origins, origins)

    def _flow(self, ctx: int, family: str, key: tuple[int, int, Origins, frozenset[str]]) -> Flow:
        site, arg, origins, filtered_roles = key
        hops, truncated = self.hops.of(ctx, arg, site)
        shell_sink, built_arg, builtin_program = self._command_facts(family, site, arg)
        return Flow(
            family=family,
            sink=site,
            sink_line=self._m.line(site),
            span=self._m.span(site),
            arg=arg,
            origins=origins,
            hops=hops,
            guards=self.guards.of(site, arg),
            truncated=truncated,
            filtered_roles=filtered_roles,
            sink_key=self.engine.calls.key(site),
            shell_sink=shell_sink,
            built_arg=built_arg,
            builtin_program=builtin_program,
        )

    def _command_facts(self, family: str, site: int, arg: int) -> tuple[bool, bool, bool]:
        """D25 (b) (A42 (1), A43 (1)): whether the sink shells the argument, whether it is
        built and whether it is a profile builtin's whole command — a ``command`` flow's three
        per-argument facts (``Calls.shell_arg``, ``built``, ``builtin_program``); False for any
        other family."""
        if family not in COMMAND:
            return False, False, False
        calls = self.engine.calls
        return calls.shell_arg(site, arg), calls.built(arg), calls.builtin_program(site, arg)


def _params_bound(flows: tuple[Flow, ...]) -> tuple[Flow, ...]:
    """D25 (c) (A42 (1)): ``flows`` (one family's, sorted), each that holds ``unknown(param)``
    marked ``param_bound`` when another of them at its ``(sink, arg)`` holds none — a same-file
    caller's summary context bound the parameter there, and that flow decides. O(flows)."""
    free = _param_free(flows)
    return tuple(
        replace(f, param_bound=True) if PARAM in f.origins and (f.sink, f.arg) in free else f
        for f in flows
    )


def _param_free(flows: tuple[Flow, ...]) -> set[tuple[int, int]]:
    """The ``(sink, arg)`` of each of ``flows`` that holds no ``unknown(param)``."""
    return {(f.sink, f.arg) for f in flows if PARAM not in f.origins}


def _analysed_by(context: Context) -> int | None:
    """The call sites a context analyses, as ``Calls`` keys them: every one in the base
    (``None``), the summarised callee's own in a summary."""
    return None if context is BASE else context.fn


# ── what an analysis keeps (A35) ─────────────────────────────────────────────


def _footprint(analysis: FlowAnalysis) -> int:
    """A35: ``bytes_estimate`` is what the built analysis keeps — the analysis, its weak
    reference to its model, its candidates and tallies, and per flow its record, span, origin set, hops and guards with the
    ints, joined hop names and sink key they hold of their own — by ``sys.getsizeof``, each object once
    (``_sizing.sized_once``: a flow's hops, guards, sink key and node indices may be another flow's too),
    computed once at build in O(flows x MAX_HOPS). Origins and role sets are shared
    (``_records``); a one-segment hop name is the model's own text or a placeholder; the model
    is charged on its own (A17)."""
    total = sized_once(_kept(analysis))
    return total + sys.getsizeof(total)  # the estimate is an int the analysis keeps too


def _kept(analysis: FlowAnalysis) -> Iterator[object]:
    """Every object the analysis holds of its own, an object held twice yielded twice: itself,
    its model reference, its candidates (each family's tuple, but the shared ``()``), its
    tallies and the ints they hold, then each flow's own (``_flow_parts``)."""
    found = [flows for flows in analysis._candidates.values() if flows]
    own = (analysis, analysis._model, analysis._candidates, analysis.tallies, *found)
    flows = chain.from_iterable(found)
    return chain(own, own_ints(analysis.tallies.values()), chain.from_iterable(map(_flow_parts, flows)))


def _flow_parts(flow: Flow) -> Iterator[object]:
    """One flow's own objects: the record, its span, origin set and hops, its guards (a flow
    with none holds the shared ``()``), each hop and guard, the strings it holds of its own
    (``_sizing.own_strs``) — each ``.``-joined hop name, which the flow pass minted (a
    one-segment name is the model's text, D16: no segment holds a ``.``, or a placeholder),
    and its sink key, which ``glue`` made (A41 (2)) — and its own ints (``_flow_ints``)."""
    held = (flow, flow.span, flow.origins, flow.hops, *flow.hops, *flow.guards)
    guards = (flow.guards,) if flow.guards else ()
    names = (hop.name for hop in flow.hops if "." in hop.name)
    return chain(held, guards, own_strs(chain(names, (flow.sink_key,))), _flow_ints(flow))


def _flow_ints(flow: Flow) -> Iterator[int]:
    """The ints a flow holds that are objects of their own (``_sizing.own_ints``): its sink,
    sink line, argument and span, each hop's line, each guard's node."""
    lines = (hop.line for hop in flow.hops)
    nodes = (guard.node for guard in flow.guards)
    return own_ints(chain((flow.sink, flow.sink_line, flow.arg, *flow.span), lines, nodes))
