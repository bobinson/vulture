"""Feature 0102 Phase 2: what the scope, roles, flow, guard, context, declines, coverage,
property, egress and limits test modules share. Not a test module.

Phase 2 builds ``shared.ast.context``, ``declines``, ``coverage``, ``_render``, ``scope``,
``roles``, ``flow`` and (Phase 3) ``consume``. Each of them is reached here only through a
lazy accessor (``flow_mod()`` ...), called from a test body, so every module that imports
this one COLLECTS while those modules are missing, and each test fails on its own, with the
``ModuleNotFoundError`` (or ``AttributeError``) of the API it needs. Nothing at module level
names a Phase-2 module; the type names below are for readers only (``TYPE_CHECKING``).

What lives here, one helper per idea:

* models through the real worker pool, by language code (``model_of``, uncached; ``program``,
  dedented and shared) and by ``ast_v1`` fixture stem (``fixture_model``); ``subject`` takes
  either (a ``Spec``);
* locators over a model by source text: a node, a CALL by its head, an IF's TEST;
* the one spelling of each ``roles`` predicate the tests call (§8.5, A21: the model first),
  so a signature question is answered in one place, and the words of each §9.1 table
  (``entries``);
* the origins and flows of a model, and the ``Origin`` / ``Flow`` values a test compares;
* test doubles for ``decide`` (§8.5): a rule, a guard and a recording context; ``decided``
  (one flow) and ``judge`` (every candidate of a model), the one spelling of ``decide``'s
  call and of ``ctx.decline(path, flow, rule, label)`` (A30 (1)); ``finding_of``, the one
  spelling of ``consume.flow_to_finding``'s (plan 3.1);
* the guard programs and verdicts (§8.5) the guards and limits modules both read;
* a real ``AuditContext`` entered in isolation (D20), its coverage snapshot (§10.2), and the
  one spy on the pool (A18);
* ``safe_path`` and the printable-ASCII rule of §10.3, program text at a cap (§8.7), the
  JSON an egress test searches (invariant 4), a hop name's placeholders (A30 (2)) and a token
  of text.

A test module that uses a model marks itself ``pytest.mark.usefixtures("real_pool")``
(``conftest.py``): one W = 1 pool and one audit per module.
"""

from __future__ import annotations

import contextvars
import dataclasses
import functools
import importlib
import json
import re
import textwrap
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from operator import attrgetter
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Any, NamedTuple

from shared.ast import FileModel
from shared.ast.kinds import Field, Kind
from shared.ast.pool import WorkerPool
from shared.ast.profile import LanguageProfile, profile_for
from shared.tools.file_scanner import read_file_safe
from tests.unit.ast._support import AST_V1, parse_model
from tests.unit.ast._support import fixture_model as _fixture_build

if TYPE_CHECKING:
    from shared.ast.context import AuditContext
    from shared.ast.flow import Flow, FlowAnalysis, Origin
    from shared.ast.scope import ScopeTable

# ── the layer's Phase-2 modules, imported per test ───────────────────────────


def _layer(name: str) -> ModuleType:
    """``shared.ast.<name>``, imported when a test asks for it (never at collection)."""
    return importlib.import_module(f"shared.ast.{name}")


def context_mod() -> ModuleType:
    """``shared.ast.context`` (plan 2.4): ``AuditContext``, ``current``, ``enter``,
    ``reset_default``."""
    return _layer("context")


def declines_mod() -> ModuleType:
    """``shared.ast.declines`` (plan 2.4): ``DeclineRecord``, ``DeclineLedger``."""
    return _layer("declines")


def coverage_mod() -> ModuleType:
    """``shared.ast.coverage`` (plan 2.4): the tallies behind ``ast_coverage`` (§10.2)."""
    return _layer("coverage")


def render_mod() -> ModuleType:
    """``shared.ast._render`` (plan 2.4): ``safe_path`` (§10.3)."""
    return _layer("_render")


def scope_mod() -> ModuleType:
    """``shared.ast.scope`` (plan 2.1): ``ScopeTable``, ``Def``, ``Use`` (§7)."""
    return _layer("scope")


def roles_mod() -> ModuleType:
    """``shared.ast.roles`` (plan 2.2): the lexicons of §9.1 with ``COVERED_BY`` and
    ``COVERING_GUARDS`` (A27 (5): each defined once, here), ``words``, ``glue``,
    ``PREFILTER``, ``model_needed`` and the role predicates of §8.5."""
    return _layer("roles")


def flow_mod() -> ModuleType:
    """``shared.ast.flow`` (plan 2.3): ``Origin``, ``Flow``, ``Hop``, ``Guard``,
    ``FlowAnalysis``, ``decide``, ``covered`` (§8); the coverage tables it imports from
    ``roles`` (A27 (5))."""
    return _layer("flow")


def consume_mod() -> ModuleType:
    """``shared.ast.consume`` (plan 3.1): ``FamilyRule``, ``flow_to_finding``,
    ``emit_for_line``, ``family_spans(model, rule, ctx, path)`` (A30 (1))."""
    return _layer("consume")


# ── models by language code ──────────────────────────────────────────────────

# The nine v1 language codes Phase-2 tables are written in (plan 2.1) and the file suffix
# each stands for. ``profile_for`` maps the suffix to its profile, so the language NAMES
# come from the profiles, never from a second table here.
LANG_SUFFIX: Mapping[str, str] = MappingProxyType({
    "js": ".js", "ts": ".ts", "py": ".py", "go": ".go", "java": ".java",
    "rs": ".rs", "php": ".php", "c": ".c", "cpp": ".cpp",
})
LANGS: tuple[str, ...] = tuple(LANG_SUFFIX)

# The three taint families of v1 (§8.3), in the LLD's order, each with the ids the AST tier
# owns for it (§9.2, §9.3): family -> (check id, CWE number).
_RULE_IDS: Mapping[str, tuple[str, str]] = MappingProxyType({
    "path": ("cwe.input_validation.path_traversal", "22"),
    "request": ("cwe.injection.ssrf", "918"),
    "command": ("cwe.injection.command", "78"),
})
FAMILIES: tuple[str, ...] = tuple(_RULE_IDS)


@functools.cache
def profile_of(lang: str) -> LanguageProfile:
    """The v1 profile a code's suffix maps to (``rs`` -> the Rust profile)."""
    profile = profile_for(f"snippet{LANG_SUFFIX[lang]}")
    assert profile is not None, f"no v1 profile for {lang!r}"
    return profile


def language_of(lang: str) -> str:
    """The ``shared.language`` name a code's suffix maps to (``rs`` -> ``rust``)."""
    return profile_of(lang).language


def model_of(source: str, lang: str) -> FileModel:
    """``source``, verbatim, as a ``lang`` file's model: parsed by a real worker and admitted
    by the boundary validator. Not cached, so every call is a fresh, unshared model (a PHP
    source carries its own ``<?php``; ``program`` is the dedented, shared spelling)."""
    return parse_model(source, language_of(lang))


@functools.cache
def program(lang: str, source: str) -> FileModel:
    """An inline program's model, shared (a model is immutable, its analysis pure): ``source``
    dedented and its leading newline dropped, so its line 1 is the first line written."""
    return model_of(textwrap.dedent(source).lstrip("\n"), lang)


# A case's subject: an ``ast_v1`` fixture by stem, or an inline ``(lang code, source)``.
Spec = str | tuple[str, str]


def subject(spec: Spec) -> FileModel:
    """The model a case names: a fixture's shared one, or ``program(lang, source)``."""
    return fixture_model(spec) if isinstance(spec, str) else program(*spec)


# ── ast_v1 fixtures by stem ──────────────────────────────────────────────────


@functools.cache
def _fixture_index() -> Mapping[str, Path]:
    """Every ``ast_v1`` fixture by stem (``cwe_22_1``) and by file name (``cwe_22_1.js``)."""
    files = sorted(filter(Path.is_file, AST_V1.iterdir()))
    by_stem = dict(zip(map(attrgetter("stem"), files), files, strict=True))
    assert len(by_stem) == len(files), "two ast_v1 fixtures share a stem"
    return MappingProxyType(by_stem | dict(zip(map(attrgetter("name"), files), files, strict=True)))


def fixture_names() -> list[str]:
    """Every ``ast_v1`` fixture's file name, sorted, each once (``_fixture_index`` keys each
    file twice: by stem and by name)."""
    return sorted({path.name for path in _fixture_index().values()})


def fixture_path(name: str) -> Path:
    """The ``ast_v1`` fixture ``name`` (a stem, its suffix resolved from the directory, or a
    file name), read in place; a ``KeyError`` names a fixture that does not exist."""
    return _fixture_index()[name]


def fixture_text(name: str) -> str:
    """A fixture's text as the parent reads it (``read_file_safe``: the one decode)."""
    text = read_file_safe(fixture_path(name))
    assert text is not None, f"{name} is unreadable"
    return text


def fixture_model(name: str) -> FileModel:
    """A fixture's model, built once per session (a model is immutable)."""
    return _fixture_build(fixture_path(name).name)[0]


# ── source text and locators ─────────────────────────────────────────────────


def newline_row(text: str, needle: str) -> int:
    """The 1-based row ``needle`` first starts on, counting ``\\n`` only (D21)."""
    return text[: text.index(needle)].count("\n") + 1


@functools.lru_cache(maxsize=64)
def _encoded(model: FileModel) -> bytes:
    """The UTF-8 bytes the worker parsed, rebuilt from the model's own ``nl_lines`` (D21)."""
    return "\n".join(model.nl_lines).encode("utf-8")


def _source(model: FileModel, start: int, end: int) -> str:
    return _encoded(model)[start:end].decode("utf-8", "replace")


def source_of(model: FileModel, node: int) -> str:
    """The source text of ``node``: its byte span (§6.2) of the parsed encoding, decoded."""
    return _source(model, *model.span(node))


def call_head(model: FileModel, call: int) -> str:
    """A CALL's source up to its argument list, stripped: ``fs.readFile``, ``new URL``,
    Java ``Files.readString`` (whose receiver ships under OBJECT, not in the CALLEE)."""
    start, end = model.span(call)
    args = model.children(call, Field.ARGS)
    return _source(model, start, model.span(args[0])[0] if args else end).strip()


def _matches(model: FileModel, node: int, text: str | None, line: int | None) -> bool:
    return (text is None or source_of(model, node) == text) and (
        line is None or model.line(node) == line
    )


def nodes_of(
    model: FileModel, kind: Kind, *, text: str | None = None, line: int | None = None
) -> list[int]:
    """The ``kind`` nodes in document order, kept when their source is ``text`` and they
    start on ``line`` (1-based, newline-counted, D21); either filter may be left out.
    ``text`` is SOURCE text, so a PHP variable is ``$x``; ``_constructs.use_in`` is the one
    locator by a NAME's shipped ``ident`` (``x``, §6.3)."""
    return [i for i in model.nodes(kind) if _matches(model, i, text, line)]


def _nth[T](found: Sequence[T], nth: int, what: str, seen: Callable[[], object]) -> T:
    """``found[nth]``; else a failure naming what was wanted and what the model holds."""
    assert len(found) > nth, f"no {what} (#{nth}); the model holds {seen()}"
    return found[nth]


def node_at(
    model: FileModel, kind: Kind, *, text: str | None = None, line: int | None = None, nth: int = 0
) -> int:
    """The ``nth`` node ``nodes_of`` keeps."""
    found = nodes_of(model, kind, text=text, line=line)
    return _nth(found, nth, f"{kind.name} {text!r} on line {line}",
                lambda: [(model.line(i), source_of(model, i)) for i in model.nodes(kind)])


def call_at(model: FileModel, head: str, *, line: int | None = None, nth: int = 0) -> int:
    """The ``nth`` CALL whose ``call_head`` is ``head`` (on ``line``)."""
    found = [c for c in nodes_of(model, Kind.CALL, line=line) if call_head(model, c) == head]
    return _nth(found, nth, f"call {head!r} on line {line}",
                lambda: [(model.line(c), call_head(model, c)) for c in model.calls()])


def call_line(model: FileModel, head: str) -> int:
    """The line of the first CALL whose head is ``head``: a sink's line."""
    return model.line(call_at(model, head))


def if_test(model: FileModel, *, line: int | None = None, nth: int = 0) -> int:
    """The TEST of the ``nth`` IF (starting on ``line``): what a guard's roles are read
    from (§8.5). Named so pytest never collects it."""
    (test,) = model.children(node_at(model, Kind.IF, line=line, nth=nth), Field.TEST)
    return test


# ── the role predicates (§8.5, L12) and the §9.1 tables ──────────────────────
# A21: every role predicate takes the model first — ``roles.sanitizer_roles(model, call)``,
# ``roles.guard_roles(model, test)``, ``roles.host_allow(model, node)``. This is the one place
# that spells the calls.


def sanitizer_roles_of(model: FileModel, call: int) -> frozenset[str]:
    """``roles.sanitizer_roles`` of the CALL ``call``."""
    return frozenset(roles_mod().sanitizer_roles(model, call))


def guard_roles_of(model: FileModel, test: int) -> frozenset[str]:
    """``roles.guard_roles`` of an IF's TEST (``if_test``)."""
    return frozenset(roles_mod().guard_roles(model, test))


def host_allow_of(model: FileModel, node: int) -> bool:
    """``roles.host_allow`` of a guard TEST or a sanitiser CALL (L12)."""
    return bool(roles_mod().host_allow(model, node))


def inner(table: Mapping[str, Iterable[str]]) -> set[str]:
    """A table keyed by role, family or root: the union of its values (a dict value adds its
    keys: ``WORD_ROLES``'s words, ``CONDITIONAL_SOURCE_ROOTS``'s member words)."""
    return set().union(*table.values())


def _roots_and_members(table: Mapping[str, Mapping[str, str]]) -> set[str]:
    """``CONDITIONAL_SOURCE_ROOTS``: its root words and their member words (W9 (b))."""
    return set(table) | inner(table)


def _union(table: Iterable[Iterable[str]]) -> set[str]:
    """``PARAM_HINTS``: the words of its combinations."""
    return set().union(*table)


# How each §9.1 table holds its words; every other table is a flat set, or a dict keyed by
# word (``SOURCE_CALL_KEYS``, ``DEMOTED_WORDS``), whose ``set()`` is its words.
_EXTRACT: Mapping[str, Callable[[Any], set[str]]] = MappingProxyType({
    **dict.fromkeys(
        ("SOURCE_WORDS", "SINK_WORDS", "SANITIZER_WORDS", "SANITIZER_KEYS", "GUARD_WORDS",
         "GUARD_KEYS", "WORD_ROLES", "KEY_ROLES"),
        inner,
    ),
    "CONDITIONAL_SOURCE_ROOTS": _roots_and_members,
    "PARAM_HINTS": _union,
})


def entries(name: str) -> set[str]:
    """The words or glued keys of the ``shared.ast.roles`` table ``name`` (never its role,
    family or root KEYS, except a root's own word)."""
    return _EXTRACT.get(name, set)(getattr(roles_mod(), name))


def entries_of(names: Iterable[str]) -> set[str]:
    """The entries of several tables, together."""
    return set().union(*map(entries, names))


# ── scope and flow ───────────────────────────────────────────────────────────


def scope_of(model: FileModel, **options: Any) -> ScopeTable:
    """``ScopeTable.build(model, **options)`` (plan 2.1; ``state_factory=`` among them)."""
    return scope_mod().ScopeTable.build(model, **options)


def analysis_of(model: FileModel) -> FlowAnalysis:
    """The model's one pure ``FlowAnalysis`` (§5: ``model.analysis()``)."""
    return model.analysis()


def origins_of(model: FileModel, node: int) -> frozenset[Origin]:
    """``origins(node)`` of the model's analysis (§8.2)."""
    return analysis_of(model).origins(node)


def externals(origins: Iterable[Origin]) -> frozenset[Origin]:
    """The ``external`` members of an origin set (§8.1)."""
    return frozenset(o for o in origins if o.cls == "external")


def candidates_of(model: FileModel, family: str) -> Sequence[Flow]:
    """``candidates(family)``: every sink with at least one origin of any class after R-P
    (A28 (3), (5): R-P runs inside it), sorted by sink line (§5)."""
    return analysis_of(model).candidates(family)


def flows_on(model: FileModel, family: str, line: int) -> list[Flow]:
    """The ``family`` candidates whose sink is on ``line``, in candidate order (a request
    sink's R-V receiver is a flow of its own)."""
    return [f for f in candidates_of(model, family) if f.sink_line == line]


def flow_at(model: FileModel, family: str, line: int, *, nth: int = 0) -> Flow:
    """The ``nth`` ``family`` candidate whose sink is on ``line``."""
    return _nth(flows_on(model, family, line), nth, f"{family} flow on line {line}",
                lambda: [f.sink_line for f in candidates_of(model, family)])


def flow_at_call(model: FileModel, family: str, head: str, *, nth: int = 0) -> Flow:
    """The ``nth`` ``family`` candidate on the line of the sink CALL ``head``."""
    return flow_at(model, family, call_line(model, head), nth=nth)


def external(role: str, *via: str) -> Origin:
    """``external(role, via)`` (§8.1)."""
    return flow_mod().Origin(cls="external", role=role, via=frozenset(via))


def constant() -> Origin:
    """``constant`` (§8.1)."""
    return flow_mod().Origin(cls="constant")


def unknown(reason: str) -> Origin:
    """``unknown(reason)`` (§8.1): ``Origin`` has no reason field, so the reason is its
    ``role`` (§5)."""
    return flow_mod().Origin(cls="unknown", role=reason)


def flow_with(
    family: str,
    *origins: Origin,
    guards: Sequence[object] = (),
    sink_line: int = 1,
    filtered: Iterable[str] = (),
) -> Flow:
    """A ``Flow`` (§5) carrying only what ``decide`` reads: its origins, its guards, its sink
    line and the roles R-P removed from it (``filtered_roles``, A28 (3))."""
    return flow_mod().Flow(
        family=family, sink=0, sink_line=sink_line, span=(0, 1), arg=0,
        origins=frozenset(origins), hops=(), guards=tuple(guards), truncated=False,
        filtered_roles=frozenset(filtered),
    )


# ── doubles for decide (§8.5) ────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StubGuard:
    """A guard as ``decide`` reads it: its role SET (L4). The real one is ``Guard(node,
    roles)`` (A29 (5)); ``decide`` reads only ``roles``, so a ``decide`` test carries this
    stand-in, which needs no model and no ``shared.ast.flow``."""

    roles: frozenset[str]


def stub_guard(*roles: str) -> StubGuard:
    """A guard whose roles are ``roles``."""
    return StubGuard(frozenset(roles))


@dataclass(frozen=True, slots=True)
class StubRule:
    """A ``FamilyRule`` (§5) with the same fields: the real one is plan 3.1's (``consume``),
    so the Phase-2 ``decide`` tests carry this one."""

    family: str
    check_id: str
    category: str
    title: str
    severity: str
    recommendation: str
    cwe_id: str
    gate: Callable[[Any, bool], bool] | None = None


def stub_rule(family: str, gate: Callable[[Any, bool], bool] | None = None) -> StubRule:
    """The stand-in rule of ``family``; ``gate`` as ``FamilyRule.gate`` (the SSRF
    ``server_ctx`` gate, §9.3)."""
    check_id, cwe = _RULE_IDS[family]
    return StubRule(family, check_id, f"CWE-{cwe}", f"Stub {family} rule", "high", "Stub", cwe, gate)


class Decline(NamedTuple):
    """One ``ctx.decline(path, flow, rule, label)`` call (A30 (1)): the FILE is the
    consumer's, handed to ``decide`` as ``path``."""

    path: Path
    flow: Any
    rule: Any
    label: str


@dataclass
class RecordingContext:
    """An ``AuditContext`` as ``decide`` writes to it (§8.5, A30 (1)): ``tally(name)`` and
    ``decline(path, flow, rule, label)``, kept in call order. The real one is
    ``fresh_context``."""

    tallies: Counter[str] = field(default_factory=Counter)
    declines: list[Decline] = field(default_factory=list)

    def tally(self, name: str, n: int = 1) -> None:
        self.tallies[name] += n

    def decline(self, path: Path, flow: Any, rule: Any, label: str) -> None:
        self.declines.append(Decline(path, flow, rule, label))

    @property
    def labels(self) -> list[str]:
        """The decline labels (``guarded:validate`` ...), in call order."""
        return [decline.label for decline in self.declines]


# The file a harness ``decide`` names when a test gives none (A30 (1): ``decide`` takes the
# consumer's ``path``). A test deciding into a real ``AuditContext`` passes a path under that
# audit's root, which the ledger renders root-relative (§10.3).
DECIDED_PATH = Path("/audit/src/handler.js")


def decided(
    flow: Any,
    family: str,
    ctx: Any = None,
    *,
    path: Path = DECIDED_PATH,
    gate: Callable[[Any, bool], bool] | None = None,
    server_ctx: bool = True,
) -> tuple[str, Any]:
    """``decide(flow, stub_rule(family, gate), ctx, path=path, server_ctx=...)`` (§8.5,
    A30 (1)) and the context it wrote to: ``ctx`` (a real ``AuditContext``), else a new
    ``RecordingContext``."""
    ctx = RecordingContext() if ctx is None else ctx
    rule = stub_rule(family, gate)
    return flow_mod().decide(flow, rule, ctx, path=path, server_ctx=server_ctx), ctx


def finding_of(flow: Any, rule: Any, path: Path, nl_lines: Sequence[str]) -> dict[str, Any]:
    """``consume.flow_to_finding(flow, rule, *, file_path, nl_lines)`` (§5, plan 3.1): the row
    a reported flow becomes, ``path`` the consumer's file and ``nl_lines`` its
    ``text.split("\\n")`` (D21)."""
    return consume_mod().flow_to_finding(flow, rule, file_path=path, nl_lines=nl_lines)


class Judgement(NamedTuple):
    """What ``decide`` made of one model's candidates of one family."""

    outcomes: tuple[tuple[int, str], ...]  # (sink line, report | decline | none), candidate order
    declines: tuple[str, ...]  # the decline labels, in decide order
    tallies: Mapping[str, int]  # what decide tallied (unknown_only_sinks ...)
    # (sink line, the labels THAT candidate's decide recorded, else its outcome)
    verdicts: tuple[tuple[int, str], ...] = ()

    @property
    def reported(self) -> tuple[int, ...]:
        """The sink lines ``decide`` reported."""
        return tuple(line for line, outcome in self.outcomes if outcome == "report")


def _judged(
    flow: Any, family: str, ctx: RecordingContext, options: Mapping[str, Any]
) -> tuple[int, str, str]:
    """One candidate's ``(sink line, outcome, verdict)``: the verdict is the labels its own
    ``decide`` call recorded (comma-joined), else its outcome."""
    before = len(ctx.declines)
    outcome, _ = decided(flow, family, ctx, **options)
    return flow.sink_line, outcome, ",".join(ctx.labels[before:]) or outcome


def judge(
    model: FileModel,
    family: str,
    *,
    server_ctx: bool = True,
    gate: Callable[[Any, bool], bool] | None = None,
) -> Judgement:
    """``decided`` over every ``family`` candidate of ``model``, against ``stub_rule(family,
    gate)`` and one fresh ``RecordingContext``."""
    ctx, options = RecordingContext(), {"gate": gate, "server_ctx": server_ctx}
    judged = [_judged(f, family, ctx, options) for f in candidates_of(model, family)]
    return Judgement(
        tuple((line, outcome) for line, outcome, _ in judged),
        tuple(ctx.labels),
        dict(ctx.tallies),
        tuple((line, verdict) for line, _, verdict in judged),
    )


# ── guard programs and verdicts (§8.5) ───────────────────────────────────────

# Verdicts on one sink: a decline label, a report, or a report with no guard found at all.
REPORT = "report"
NO_GUARD = "no guard"
ALLOWLIST = "guarded:allowlist"
PATH_CONTAIN = "guarded:path_contain"
VALIDATE = "guarded:validate"
HOST_ALLOW = "guarded:host_allow"

# The JS handler most guard cases share: ``p`` is read from the request, then the one path
# sink.
READ = "const p = req.query.f;"
SINK = "fs.readFileSync"
SINK_P = f"{SINK}(p);"


def js_handler(*statements: str) -> tuple[str, str]:
    """A JS route handler whose body is ``statements``, one per line: ``req`` is its request
    parameter, so ``req.query.*`` is ``external(request)``. A ``Spec``."""
    body = "".join(f"  {statement}\n" for statement in statements)
    return "js", f"function handler(req, res) {{\n{body}}}\n"


def verdicts_at(model: FileModel, family: str, head: str) -> str:
    """``decide``'s verdicts on the ``family`` flows of the sink ``head``, sorted and joined by
    ``|``; a ``none`` (a constant-only argument) is left out unless it is all there is."""
    line = call_line(model, head)
    seen = {verdict for at, verdict in judge(model, family).verdicts if at == line} - {"none"}
    return "|".join(sorted(seen)) or "none"


def guard_role_sets(model: FileModel, family: str, head: str) -> list[frozenset[str]]:
    """The role sets of the guards ``guards_for`` found for the sink ``head``, over the flows
    on its line, each flow's in ``guards_for``'s order."""
    flows = flows_on(model, family, call_line(model, head))
    return [frozenset(g.roles) for flow in flows for g in flow.guards]


def guard_verdict(model: FileModel, family: str, head: str) -> str:
    """``verdicts_at``, with a report whose sink has no guard at all read as ``NO_GUARD``: a
    clause that rejects an IF leaves ``NO_GUARD``, while a guard whose roles do not cover the
    family leaves ``REPORT``."""
    verdict = verdicts_at(model, family, head)
    return NO_GUARD if verdict == REPORT and not guard_role_sets(model, family, head) else verdict


# ── a real AuditContext (D20, plan 2.4) ──────────────────────────────────────


def _entered[T](root: Path, fn: Callable[..., T], args: tuple[Any, ...]) -> T:
    context_mod().enter(root)
    return fn(*args)


def in_audit[T](root: Path, fn: Callable[..., T], *args: Any) -> T:
    """``fn(*args)`` inside a NEW audit: ``context.enter(root)`` runs in a copy of the
    caller's context, so the test thread's own context never moves and no two calls share
    an ``AuditContext``."""
    return contextvars.copy_context().run(_entered, root, fn, args)


def current_context() -> AuditContext:
    """``context.current()``: the audit's context, else the process default (D20)."""
    return context_mod().current()


def fresh_context(root: Path) -> AuditContext:
    """A new, real ``AuditContext`` for ``root``, made by ``context.enter`` in isolation."""
    return in_audit(root, current_context)


def coverage_snapshot(root: Path) -> dict[str, Any]:
    """The current context's ``ast_coverage`` (§10.2): ``coverage.snapshot(root)``."""
    return current_context().coverage.snapshot(root)


def tally_of(root: Path, name: str) -> int:
    """One ``ast_coverage.tallies`` counter of the current context (0 when absent)."""
    return coverage_snapshot(root)["tallies"].get(name, 0)


# ── the pool, observed (A18) ─────────────────────────────────────────────────

# ``PoolSpy.answer`` when the spy hands every file to the real worker.
NO_ANSWER: Any = object()
_GATE_S = 30.0  # a gated parse lets go by then, so a bug fails instead of wedging the run


class PoolSpy:
    """Stands in for ``WorkerPool.parse``: records every request that reaches a pool, then
    hands the file to ``real`` (the parse it replaced) or answers ``answer`` for it,
    optionally late (``delay_s``), gated (``close_gate``) or raising on the first call."""

    def __init__(self, real: Callable[..., Any], answer: Any = NO_ANSWER) -> None:
        self.real = real
        self.answer = answer
        self.calls: list[tuple[str, bytes]] = []
        self.entered = threading.Event()
        self.gate = threading.Event()
        self.gate.set()
        self.gate_data: bytes | None = None
        self.delay_s = 0.0
        self.fail_first = False
        self._lock = threading.Lock()

    def __call__(self, pool: WorkerPool, language: str, data: bytes, grammar: str | None) -> Any:
        first = self._record(language, data)
        self.entered.set()
        self._hold(data)
        if self.fail_first and first:
            raise RuntimeError("hostile: the leader's parse raised")
        if self.answer is NO_ANSWER:
            return self.real(pool, language, data, grammar)
        return self.answer

    def close_gate(self, data: bytes | None = None) -> None:
        """Hold every parse (or only the one shipping ``data``) until ``gate.set()``."""
        self.gate_data = data
        self.gate.clear()

    def languages(self) -> list[str]:
        """The language of every request, in arrival order."""
        return [language for language, _ in self.calls]

    def _record(self, language: str, data: bytes) -> bool:
        with self._lock:
            self.calls.append((language, bytes(data)))
            return len(self.calls) == 1

    def _hold(self, data: bytes) -> None:
        if self.gate_data in (None, data):
            self.gate.wait(_GATE_S)
        time.sleep(self.delay_s)


def spy_pool(patch: Any, answer: Any = NO_ANSWER) -> PoolSpy:
    """Route every ``WorkerPool.parse`` through a new ``PoolSpy`` answering ``answer`` (a
    fallback reason or a document; ``NO_ANSWER``: the real worker). ``patch`` is a
    ``MonkeyPatch``, which undoes it."""
    spy = PoolSpy(WorkerPool.parse, answer)

    def parse(pool: WorkerPool, language: str, data: bytes, grammar: str | None = None) -> Any:
        return spy(pool, language, data, grammar)

    patch.setattr(WorkerPool, "parse", parse)
    return spy


# ── §10.3: the one renderer of a path ────────────────────────────────────────


def safe_path(root: Path, path: Path) -> str:
    """``_render.safe_path(root, path)`` (§10.3)."""
    return render_mod().safe_path(root, path)


def unprintable(text: str) -> str:
    """The characters of ``text`` outside printable ASCII (§10.3, T15), in order."""
    return "".join(c for c in text if not " " <= c <= "~")


# ── programs at a cap (§8.7) ─────────────────────────────────────────────────


def numbered(template: str, count: int) -> str:
    """``template`` once per ``i`` in ``range(count)``, each ``{i}`` replaced by ``i``
    (``"const v{i} = req.q{i};\\n"``); any other brace is literal."""
    return "".join(template.replace("{i}", str(i)) for i in range(count))


def nested(head: str, tail: str, depth: int, core: str) -> str:
    """``core`` inside ``depth`` levels of ``head`` ... ``tail`` (``"if (c) {\\n"`` ...
    ``"}\\n"``)."""
    return head * depth + core + tail * depth


# ── egress (invariant 4, D16) ────────────────────────────────────────────────

# A30 (2): what a hop-name segment is when it names no identifier (an M1 subscript key, an M4
# flag), and the whole hop name of an expression no segment can name.
HOP_PLACEHOLDERS = frozenset({"<index>", "<flag>"})
HOP_EXPR = "<expr>"
# A token of text that may be an identifier: what a search for a leaked name splits text into.
TOKEN = re.compile(r"[A-Za-z_$][\w$]*")


def _plain(value: Any) -> Any:
    """``json.dumps``' fallback: a dataclass as its fields, a set sorted (D14)."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=repr)
    raise TypeError(f"{type(value).__name__} is not JSON-serialisable")


def dumped(value: Any) -> str:
    """``value`` as the JSON an egress test searches: a ``Flow``, its ``Origin``s, a
    ``DeclineRecord`` by their fields; sets sorted; keys sorted."""
    return json.dumps(value, default=_plain, sort_keys=True)
