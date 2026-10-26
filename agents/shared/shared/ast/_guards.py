"""Guards (feature 0102, LLD §8.5 "Guard", §8.4 R-R, §8.7; L4, L11, L12, W2, W8, A29, A32).

``guards_for(sink, arg)`` answers the ``Guard(node, roles)`` records of one sink argument, in a
deterministic order — the sink's IF ancestors (nearest first, at most ``MAX_DEPTH``), then the
``GUARD_WINDOW`` nearest IF or TRY siblings preceding ``stmt(sink)`` in ``block_of(sink)`` (a
plain statement takes no window slot, A29 (4)).

**Reads (A29 (3), W8).** ``roots(arg)`` is the reads of the argument subtree — its FIRST
``MAX_ARG_NAMES`` read sites in document order (A32) — each a ``(Def, member path)`` pair, the
Def by its position (``Def.position``), bucketed by it once per sink argument: a
NAME to its Defs; a MEMBER / SUBSCRIPT chain to the Defs of its longest bound dotted path, else
of its base NAME, with the rest of the chain as its member path. Segments follow the scope
pass's M1 rule (``_nodes.segment``: a dynamic subscript key is a ``None`` segment, which
matches only another dynamic key), and a PROPERTY or KEY NAME, or any other W8 non-read, is
never resolved on its own (``_nodes.is_read``, the scope pass's predicate). A guard TEST's
reads (over at most ``MAX_TEST_NODES`` nodes, its root counted) meet the roots when a pair
shares the Def and one member path is a prefix of the other (``req.query`` guards
``req.query.f``; ``req.query.g`` does not). A read inside a nested function of the subtree is
a read of it too — ``ROOTS.some(r => p.startsWith(r))`` reads ``p``, which the scope pass
resolves through the closure to the enclosing Def.

**An IF is a guard** when its reads meet the roots and (a) it ends before the sink and
``exits(CONSEQ)``, or (b) the sink is inside CONSEQ under a TEST that is no negation, or inside
ALT under a negated (``!`` / ``not``) one (A29 (1)). A TEST-less IF (a Python ``else``) never is
(A29 (6)); one that meets and exits with no role still is — ``decide`` then reports (A29 (2)).
``exits(S)`` (W2): S's direct statements — its children when S is a BLOCK, else S itself —
hold a RETURN, THROW or JUMP, or a CALL whose glued key is an ``EXIT_WORDS`` entry. **A TRY is a
guard** only through R-R: its body has a direct ``relativeto`` CALL on the roots' Defs and
every CATCH exits (a ``try``/``finally`` has none, so a failing check propagates) — role
``path_contain``. An IF's roles are ``roles.guard_roles`` (A21).

**Cost (§8.7).** Every fact of a guard candidate — a TEST's reads, a body's ``exits``, a TRY's
checked Defs, an IF's roles — is computed once per node, and a block's IF / TRY children once
per block, so one sink costs the caps (``MAX_DEPTH`` ancestors, ``GUARD_WINDOW`` siblings found
by bisection, ``MAX_TEST_NODES`` × ``MAX_ARG_NAMES`` read pairs), never the size of its block.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import chain, islice
from types import MappingProxyType
from typing import TYPE_CHECKING

from shared.ast._nodes import (
    CHAINS,
    ancestors,
    cached,
    chain_links,
    edges_up,
    first,
    is_kind,
    is_read,
    kids_of,
    preorder,
    segment,
    unawaited,
    union,
)
from shared.ast._records import Guard, role_set
from shared.ast.kinds import Field, Kind
from shared.ast.limits import GUARD_WINDOW, MAX_ARG_NAMES, MAX_TEST_NODES
from shared.ast.model import BLOCK_KINDS
from shared.ast.roles import (
    CONTAINMENT_KEYS,
    CONTAINMENT_ROLES,
    EXIT_WORDS,
    NEGATION_OPERATORS,
    NO_ROLES,
    checked_roles,
    guard_roles,
)

if TYPE_CHECKING:
    from shared.ast._origins import Engine
    from shared.ast.scope import Def

__all__ = ["Guards"]

type _Path = tuple[str | None, ...]  # a read's member path (M1: None is a dynamic key)
type _Read = tuple[int, _Path]  # (the Def's position, member path)
type _Roots = Mapping[int, list[_Path]]  # a sink argument's reads, by the Def's position

_EXITS = frozenset({Kind.RETURN, Kind.THROW, Kind.JUMP})
_NO_DEFS: frozenset[int] = frozenset()  # a TRY that checks no Def (memoised per TRY)
_WINDOWED = frozenset({Kind.IF, Kind.TRY})


@dataclass(slots=True)
class _Facts:
    """One memo per guard fact, each keyed by the node it is about (a sink argument's by its
    ``(sink, arg)`` pair; §8.7)."""

    guards: dict[tuple[int, int], tuple[Guard, ...]] = field(default_factory=dict)
    reads: dict[int, tuple[_Read, ...]] = field(default_factory=dict)  # a TEST's
    windowed: dict[int, list[int]] = field(default_factory=dict)  # a block's IF / TRY children
    checked: dict[int, frozenset[int]] = field(default_factory=dict)  # a TRY's Defs (R-R)
    exits: dict[int, bool] = field(default_factory=dict)  # W2's exits(S)
    roles: dict[int, frozenset[str]] = field(default_factory=dict)  # a guard's
    # A44 (1) (d): a block's check statements and CALLs; a check CALL's callee roles and its
    # arguments' reads; a same-file function's checked parameter slots.
    checks: dict[int, tuple[list[int], list[int]]] = field(default_factory=dict)
    callee_roles: dict[int, frozenset[str]] = field(default_factory=dict)
    arg_reads: dict[int, tuple[tuple[_Read, ...], ...]] = field(default_factory=dict)
    helpers: dict[int, tuple[tuple[int, frozenset[str]], ...]] = field(default_factory=dict)


class Guards:
    """One file's guards, memoised per sink argument and per candidate node."""

    def __init__(self, engine: Engine) -> None:
        self._e = engine
        self._m = engine.m
        self._facts = _Facts()

    def of(self, sink: int, arg: int) -> tuple[Guard, ...]:
        """``guards_for(sink, arg)`` (module docstring), memoised per sink argument."""
        return cached(self._facts.guards, (sink, arg), self._guards)

    def _guards(self, at: tuple[int, int]) -> tuple[Guard, ...]:
        sink, arg = at
        roots = _by_def(self._reads_of(islice(self._sites(arg, self._m.node_count), MAX_ARG_NAMES)))
        if not roots:
            return ()
        return (*self._ancestors(sink, roots), *self._window(sink, roots), *self._checks_of(sink, roots))

    # ── reads (A29 (3), W8) ──

    def _sites(self, root: int, budget: int) -> Iterator[int]:
        """The read sites under ``root`` in document order, over at most ``budget`` nodes."""
        kind = self._m.kind
        nodes = preorder(self._m, root, budget)
        return (node for node in nodes if _SITES.get(kind(node), Guards._no_site)(self, node))

    def _no_site(self, node: int) -> bool:
        return False

    def _name_site(self, node: int) -> bool:
        """A NAME read: not a chain's base (its chain is the site) and not a W8 non-read."""
        return not self._linked(node) and is_read(self._m, node)

    def _chain_site(self, node: int) -> bool:
        """The outermost node of a MEMBER / SUBSCRIPT chain."""
        return not self._linked(node)

    def _linked(self, node: int) -> bool:
        """``node`` is the OBJECT of a MEMBER / SUBSCRIPT: a link of a longer chain."""
        return self._m.field(node) is Field.OBJECT and self._m.kind(self._m.parent(node)) in CHAINS

    def _reads_of(self, sites: Iterator[int]) -> Iterator[_Read]:
        for site in sites:
            yield from self._read(site)

    def _read(self, site: int) -> list[_Read]:
        """A read site's ``(Def, member path)`` pairs (W8): the Defs of the chain's longest
        bound dotted path — tried outermost first, the base NAME last — with the segments past
        that path."""
        links, base = chain_links(self._m, site)
        segments = [segment(self._m, link) for link in reversed(links)]
        found = self._longest(links, base)
        return [(d.position, tuple(segments[d.name.count(".") :])) for d in found]

    def _longest(self, links: list[int], base: int) -> Sequence[Def]:
        """The Defs of the first of ``links`` (outermost first), then ``base``, that resolves."""
        resolved = map(self._e.scope.resolve, (*links, base))
        return next(filter(None, resolved), ())

    def _meets(self, test: int, roots: _Roots) -> bool:
        """A29 (3): a TEST read and a root share the Def (one probe of the roots' bucket) and
        one member path is a prefix of the other — O(reads + matches), not reads x roots."""
        return _meets_reads(cached(self._facts.reads, test, self._test_reads), roots)

    def _test_reads(self, test: int) -> tuple[_Read, ...]:
        """A TEST's reads, over at most ``MAX_TEST_NODES`` nodes, its root counted (A32)."""
        return tuple(self._reads_of(self._sites(test, MAX_TEST_NODES)))

    # ── candidates ──

    def _ancestors(self, sink: int, roots: _Roots) -> Iterator[Guard]:
        """Clause (b): every IF ancestor (at most ``MAX_DEPTH``) whose chosen branch holds the
        sink."""
        for child, node in edges_up(self._m, sink):
            if self._m.kind(node) is Kind.IF and self._inside(node, self._m.field(child), roots):
                yield self._guard(node)

    def _inside(self, branch_if: int, branch: Field, roots: _Roots) -> bool:
        """A29 (1): the sink is in CONSEQ under a plain TEST, in ALT under a negated one."""
        test = self._test(branch_if)
        if test < 0:
            return False
        chosen = Field.ALT if self._negated(test) else Field.CONSEQ
        return branch is chosen and self._meets(test, roots)

    def _negated(self, test: int) -> bool:
        return self._m.kind(test) is Kind.UNARY and self._m.ident(test) in NEGATION_OPERATORS

    def _window(self, sink: int, roots: _Roots) -> Iterator[Guard]:
        """Clause (a) and R-R: the ``GUARD_WINDOW`` nearest IF / TRY siblings before
        ``stmt(sink)``."""
        for sibling in self._earlier(sink):
            if _WINDOW_TESTS[self._m.kind(sibling)](self, sibling, roots):
                yield self._guard(sibling)

    def _earlier(self, sink: int) -> Sequence[int]:
        """The ``GUARD_WINDOW`` IF and TRY siblings preceding ``stmt(sink)`` in
        ``block_of(sink)``, nearest first (a plain statement takes no slot, A29 (4)): node ids
        are in document order, so the block's IF / TRY children bisect at ``stmt(sink)``."""
        block = self._m.block_of(sink)
        if block < 0:
            return ()
        windowed = cached(self._facts.windowed, block, self._windowed)
        return _nearest_before(windowed, windowed, self._statement(sink, block))

    def _windowed(self, block: int) -> list[int]:
        """``block``'s IF and TRY children, in document order."""
        return [s for s in self._m.children(block) if self._m.kind(s) in _WINDOWED]

    def _statement(self, sink: int, block: int) -> int:
        """``stmt(sink)``: the sink's ancestor that is a direct child of ``block`` (the last
        one ``ancestors`` reads when none is)."""
        node = sink
        for parent in ancestors(self._m, sink):
            if parent == block:
                break
            node = parent
        return node

    def _early_exit(self, branch_if: int, roots: _Roots) -> bool:
        """Clause (a): a TEST, a CONSEQ that exits, and reads that meet the roots."""
        return self._exits_early(branch_if) and self._meets(self._test(branch_if), roots)

    def _exits_early(self, branch_if: int) -> bool:
        """Clause (a)'s shape: a TEST, and a CONSEQ that exits."""
        conseq = first(self._m, branch_if, Field.CONSEQ)
        return self._test(branch_if) >= 0 and conseq >= 0 and self._exits(conseq)

    def _contained(self, attempt: int, roots: _Roots) -> bool:
        """R-R: a body ``relativeto`` call on a root's Def, and every CATCH exits."""
        checked = cached(self._facts.checked, attempt, self._checked)
        return not checked.isdisjoint(roots)

    def _checked(self, attempt: int) -> frozenset[int]:
        """The Defs (by position) whose reads a direct ``CONTAINMENT_KEYS`` CALL of
        ``attempt``'s body takes as receiver or argument — none unless every CATCH exits."""
        if not all(map(self._catch_exits, kids_of(self._m, attempt, Kind.CATCH))):
            return _NO_DEFS
        return frozenset(self._checked_positions(attempt)) or _NO_DEFS

    def _checked_positions(self, attempt: int) -> Iterator[int]:
        return (d for call in self._checks(attempt) for d in self._checked_defs(call))

    def _checks(self, attempt: int) -> Iterator[int]:
        """The ``CONTAINMENT_KEYS`` CALLs among the direct statements of ``attempt``'s body."""
        bodies = kids_of(self._m, attempt, Kind.BLOCK)
        return filter(self._containment, (s for body in bodies for s in self._m.children(body)))

    def _checked_defs(self, call: int) -> set[int]:
        """The Defs (by position) the reads of ``call``'s receiver and arguments resolve to
        (``-1`` reads nothing)."""
        nodes = (self._e.calls.receiver(call), *self._e.calls.args(call))
        return {d.position for node in nodes for d in self._e.scope.resolve(node)}

    def _containment(self, call: int) -> bool:
        return self._m.kind(call) is Kind.CALL and self._e.calls.key(call) in CONTAINMENT_KEYS

    def _catch_exits(self, catch: int) -> bool:
        bodies = kids_of(self._m, catch, Kind.BLOCK)
        return self._exits(bodies[-1] if bodies else catch)

    def _exits(self, body: int) -> bool:
        """W2's ``exits(S)``, once per S."""
        return cached(self._facts.exits, body, self._exits_now)

    def _exits_now(self, body: int) -> bool:
        statements = self._m.children(body) if self._m.kind(body) is Kind.BLOCK else (body,)
        return any(map(self._exit, statements))

    def _exit(self, statement: int) -> bool:
        kind = self._m.kind(statement)
        return kind in _EXITS or (kind is Kind.CALL and self._e.calls.key(statement) in EXIT_WORDS)

    def _test(self, branch_if: int) -> int:
        return first(self._m, branch_if, Field.TEST)

    # ── statement-level checks (A44 (1) (d) (i), (iii)) ──

    def _checks_of(self, sink: int, roots: _Roots) -> Iterator[Guard]:
        """The check CALL statements that dominate the sink: in each block enclosing it (at
        most ``MAX_DEPTH`` up), the ``GUARD_WINDOW`` nearest before the sink's statement there,
        nearest block first, each a guard when it checks a root (``_check_roles``)."""
        for statement, block in self._enclosing(sink):
            for call in self._preceding(block, statement):
                roles = self._check_roles(call, roots)
                if roles:
                    yield Guard(call, roles)

    def _enclosing(self, sink: int) -> Iterator[tuple[int, int]]:
        """``(stmt, block)`` for each BLOCK or MODULE above the sink, ``stmt`` its child on the
        way down to the sink."""
        edges = edges_up(self._m, sink)
        return ((child, node) for child, node in edges if self._m.kind(node) in BLOCK_KINDS)

    def _preceding(self, block: int, statement: int) -> Sequence[int]:
        """The check CALLs of ``block``'s statements before ``statement``, the
        ``GUARD_WINDOW`` nearest, nearest first (``_block_checks``, bisected)."""
        statements, calls = cached(self._facts.checks, block, self._block_checks)
        return _nearest_before(statements, calls, statement)

    def _block_checks(self, block: int) -> tuple[list[int], list[int]]:
        """``block``'s check statements in document order, and their CALLs: a CALL statement
        (awaited or not) whose callee is a same-file function or carries a validation verb."""
        statements: list[int] = []
        calls: list[int] = []
        for statement in self._m.children(block):
            call = self._statement_call(statement)
            if call >= 0 and self._check_shaped(call):
                statements.append(statement)
                calls.append(call)
        return statements, calls

    def _statement_call(self, statement: int) -> int:
        """The CALL a statement is (an AWAIT's own CALL, ``unawaited``), else ``-1``."""
        call = unawaited(self._m, statement)
        return call if is_kind(self._m, call, Kind.CALL) else -1

    def _check_shaped(self, call: int) -> bool:
        return self._e.calls.local(call) >= 0 or bool(self._callee_roles(call))

    def _callee_roles(self, call: int) -> frozenset[str]:
        """(i): the roles the callee's words check (``roles.checked_roles``), memoised."""
        return cached(self._facts.callee_roles, call, self._checked_by_words)

    def _checked_by_words(self, call: int) -> frozenset[str]:
        return role_set(checked_roles(self._e.calls.ident(call)))

    def _check_roles(self, call: int, roots: _Roots) -> frozenset[str]:
        """(iii) for a same-file callee — the roles of the parameters it checks whose argument
        reads a root — else (i): the callee's roles when an argument reads a root."""
        reads = cached(self._facts.arg_reads, call, self._arg_reads)
        fn = self._e.calls.local(call)
        if fn >= 0:
            return self._helper_roles(fn, reads, roots)
        return self._callee_roles(call) if any(_meets_reads(r, roots) for r in reads) else NO_ROLES

    def _helper_roles(self, fn: int, reads: Sequence[tuple[_Read, ...]], roots: _Roots) -> frozenset[str]:
        checked = cached(self._facts.helpers, fn, self._param_checks)
        return union((roles for i, roles in checked if i < len(reads) and _meets_reads(reads[i], roots)), NO_ROLES)

    def _arg_reads(self, call: int) -> tuple[tuple[_Read, ...], ...]:
        """Each positional argument's reads (``MAX_TEST_NODES`` nodes each), in order."""
        return tuple(tuple(self._reads_of(self._sites(a, MAX_TEST_NODES))) for a in self._e.calls.args(call))

    def _param_checks(self, fn: int) -> tuple[tuple[int, frozenset[str]], ...]:
        """(iii): ``fn``'s parameter slots an early-exit IF among the first ``GUARD_WINDOW`` IF
        or TRY statements of its body tests with a guard role — ``(slot, roles)`` pairs."""
        body = first(self._m, fn, Field.BODY)
        if not is_kind(self._m, body, Kind.BLOCK):
            return ()
        slots = self._e.params.slots(fn)
        return tuple(chain.from_iterable(self._tested_slots(n, fn, slots) for n in self._exiting_ifs(body)))

    def _exiting_ifs(self, body: int) -> list[int]:
        """The first ``GUARD_WINDOW`` IF / TRY statements of ``body`` that are early-exit IFs
        with a guard role."""
        return list(filter(self._exiting, cached(self._facts.windowed, body, self._windowed)[:GUARD_WINDOW]))

    def _exiting(self, node: int) -> bool:
        """An IF of clause (a)'s shape (``_exits_early``) with a guard role."""
        return self._m.kind(node) is Kind.IF and self._exits_early(node) and bool(self._guard(node).roles)

    def _tested_slots(self, branch_if: int, fn: int, slots: Sequence[int]) -> Iterator[tuple[int, frozenset[str]]]:
        """The slots of ``fn`` whose parameter Def the IF's TEST reads, with the IF's roles."""
        roles = self._guard(branch_if).roles
        tested = {self._e.scope.defs[position] for position, _ in self._test_reads_of(branch_if)}
        return ((slots.index(d.value), roles) for d in tested if self._slot_def(d, fn, slots))

    def _test_reads_of(self, branch_if: int) -> tuple[_Read, ...]:
        return cached(self._facts.reads, self._test(branch_if), self._test_reads)

    @staticmethod
    def _slot_def(d: Def, fn: int, slots: Sequence[int]) -> bool:
        return d.kind == "param" and d.scope == fn and d.value in slots

    # ── the record ──

    def _guard(self, node: int) -> Guard:
        return Guard(node, cached(self._facts.roles, node, self._roles_of))

    def _roles_of(self, node: int) -> frozenset[str]:
        """The guard's roles, as the one shared copy of that role set (``role_set``)."""
        if self._m.kind(node) is Kind.TRY:
            return CONTAINMENT_ROLES
        return role_set(guard_roles(self._m, self._test(node), symbol_of=self._e.calls.symbol_of))


def _by_def(reads: Iterator[_Read]) -> dict[int, list[_Path]]:
    """A sink argument's reads, bucketed by the Def's position (``_Roots``)."""
    roots: dict[int, list[_Path]] = {}
    for position, path in reads:
        roots.setdefault(position, []).append(path)
    return roots


def _nearest_before(ordered: Sequence[int], values: Sequence[int], statement: int) -> Sequence[int]:
    """The ``GUARD_WINDOW`` entries of ``values`` — parallel to ``ordered``, a block's
    statements in document order — nearest before ``statement``, nearest first (bisected)."""
    end = bisect_left(ordered, statement)
    return values[max(0, end - GUARD_WINDOW) : end][::-1]


def _meets_reads(reads: Sequence[_Read], roots: _Roots) -> bool:
    """A29 (3) over a call argument's reads: one shares a root's Def and a related path."""
    return any(_related(path, roots.get(position, ())) for position, path in reads)


def _related(path: _Path, paths: Sequence[_Path]) -> bool:
    """A29 (3): one of ``paths`` — the root paths read of the same Def — and ``path``, one a
    prefix of the other."""
    return any(_prefixed(path, other) for other in paths)


def _prefixed(path: _Path, other: _Path) -> bool:
    shorter = min(len(path), len(other))
    return path[:shorter] == other[:shorter]


# A window sibling's kind -> the clause that makes it a guard.
_WINDOW_TESTS: Mapping[Kind, Callable[[Guards, int, _Roots], bool]] = MappingProxyType({
    Kind.IF: Guards._early_exit,
    Kind.TRY: Guards._contained,
})
# A node's kind -> whether it is a read site.
_SITES: Mapping[Kind, Callable[[Guards, int], bool]] = MappingProxyType({
    Kind.NAME: Guards._name_site,
    Kind.MEMBER: Guards._chain_site,
    Kind.SUBSCRIPT: Guards._chain_site,
})
