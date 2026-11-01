"""A flow's hops (feature 0102, LLD §8.6, §10.1; A28 (4), A30 (2), A32; D16, invariant 4).

A flow's hops run from the source side to the sink: the Def chain that carries an external
value into the sink argument — each Def's predecessor is the first read of its value (in
document order) whose Defs hold an external origin, else the first read that has Defs — then
the ``sink`` hop. The chain starts at a parameter (``param``; in a summary, the CALL site that
bound it: ``call``, §8.4), a CATCH (``catch``) or an import; a loop target is a ``loop`` hop, a
path write a ``member`` hop, every other binding an ``assign`` hop.

Each Def's trail — its first ``MAX_HOPS`` hops from the source side and how many there are — is
memoised, so a flow's hops cost O(1) amortised; the walk to an unmemoised Def is an explicit
loop (a long copy chain never recurses) that stops at a Def it met before (a loop-carried
write). A flow keeps its FIRST ``MAX_HOPS`` hops and is ``truncated`` when there were more (A32):
a trail already full shares its hops with every longer one, and no hop past it is built.

A hop's ``name`` (A30 (2)) is built from the model's structure, never from a Def's dotted name:
up to three ``.``-joined segments, each a D16 identifier, ``<index>`` for an M1 subscript key
or ``<flag>`` for an M4 literal; anything else is ``<expr>``. A literal's text never leaves as
a name (invariant 4). A node's name is built once, so every flow naming it shares the string.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING

from shared.ast._nodes import CHAINS, cached, first, preorder
from shared.ast._records import EXPR, FLAG, INDEX, Hop, has_external
from shared.ast._validate import IDENTIFIER
from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_HOP_SEGMENTS, MAX_HOPS

if TYPE_CHECKING:
    from shared.ast._origins import Engine
    from shared.ast.model import FileModel
    from shared.ast.scope import Def

__all__ = ["Hops"]

type _Trail = tuple[tuple[Hop, ...], int]
type _At = tuple[int, int]  # (context, Def position)

_EMPTY_TRAIL: _Trail = ((), 0)
# A Def's kind -> its hop kind; any other is ``assign`` (``member`` for a path write).
_HOP_KINDS: Mapping[str, str] = MappingProxyType({
    "param": "param", "catch": "catch", "loop_target": "loop",
})
# The Def kinds a trail starts at (they read no value of the file).
_STARTS = frozenset({"param", "catch", "import", "function"})


class Hops:
    """One file's hop trails, memoised per (context, Def)."""

    def __init__(self, engine: Engine) -> None:
        self._e = engine
        self._m = engine.m
        self._trails: dict[_At, _Trail] = {}
        self._names: dict[int, str] = {}

    def of(self, ctx: int, arg: int, sink: int) -> tuple[tuple[Hop, ...], bool]:
        """The flow's hops into ``arg`` of ``sink`` in context ``ctx`` — its first
        ``MAX_HOPS`` — and whether more were cut (A32: a full trail cuts the sink hop)."""
        before = self._carrier(ctx, arg)
        hops, count = self._trail(*before) if before else _EMPTY_TRAIL
        if count >= MAX_HOPS:
            return hops, True
        return (*hops, Hop(self._m.line(sink), "sink", self.site_name(sink))), False

    # ── trails ──

    def _trail(self, ctx: int, position: int) -> _Trail:
        """The trail of a Def: walk back to a memoised Def (or a start), then extend forward."""
        chain, at = self._back((ctx, position))
        trail = self._trails.get(at, _EMPTY_TRAIL) if at is not None else _EMPTY_TRAIL
        for step in reversed(chain):
            hops, count = trail
            trail = self._trails[step] = (self._extended(hops, step), count + 1)
        return trail

    def _extended(self, hops: tuple[Hop, ...], step: _At) -> tuple[Hop, ...]:
        """``hops`` and the hop of ``step`` — ``hops`` itself once it holds ``MAX_HOPS``."""
        return hops if len(hops) >= MAX_HOPS else (*hops, self._hop(*step))

    def _back(self, at: _At | None) -> tuple[list[_At], _At | None]:
        """The unmemoised Defs from ``at`` back towards the source (each once: a
        loop-carried write ends the walk), and where the walk stopped."""
        chain: dict[_At, None] = {}  # an ordered set: the walk's order and an O(1) seen test
        while self._open(at, chain):
            chain[at] = None  # type: ignore[index]
            at = self._previous(*at)  # type: ignore[misc]
        return list(chain), at

    def _open(self, at: _At | None, chain: Mapping[_At, None]) -> bool:
        """The walk goes on: a Def neither memoised nor already met on this walk."""
        return at is not None and at not in self._trails and at not in chain

    def _previous(self, ctx: int, position: int) -> _At | None:
        """The Def a Def's value was read from, or None where the trail starts."""
        d = self._e.scope.defs[position]
        if d.kind in _STARTS or d.symbol is not None:
            return None
        found = (self._carrier(ctx, node) for node in self._read_from(d))
        return next(filter(None, found), None)

    @staticmethod
    def _read_from(d: Def) -> tuple[int, ...]:
        """What a Def's value is read from: its value, and an ``aug`` Def's earlier binding
        (read at its own node, §7.2)."""
        held = (d.value,) if d.value is not None else ()
        return (*held, d.node) if d.kind == "aug" else held

    def _carrier(self, ctx: int, expr: int) -> _At | None:
        """The first read of ``expr`` (document order, at most ``MAX_TEST_NODES`` nodes, no
        nested function) whose Defs hold an external origin, else the first read with Defs."""
        fallback: _At | None = None
        for at in self._reads(ctx, expr):
            if self._external(at):
                return at
            fallback = fallback or at
        return fallback

    def _reads(self, ctx: int, expr: int) -> Iterator[_At]:
        """Where each Def reaching a read in ``expr`` is read (``_at``): the reads in
        ``_carrier``'s order, each read's Defs in the scope table's."""
        resolve, nodes = self._e.scope.resolve, preorder(self._m, expr, below=_this_scope)
        return (self._at(ctx, d) for node in nodes for d in resolve(node))

    def _at(self, ctx: int, d: Def) -> _At:
        return self._e.def_at(ctx, d)

    def _external(self, at: _At) -> bool:
        return has_external(self._e.held(*at))

    def _hop(self, ctx: int, position: int) -> Hop:
        d = self._e.scope.defs[position]
        site = self._binding_site(ctx, d)
        if site >= 0:
            return Hop(self._m.line(site), "call", self.site_name(site))
        kind = _HOP_KINDS.get(d.kind) or ("member" if self._m.kind(d.node) in CHAINS else "assign")
        return Hop(self._m.line(d.node), kind, self.name(d.node))

    def _binding_site(self, ctx: int, d: Def) -> int:
        """The call site whose summary bound the parameter Def ``d`` (§8.4), else ``-1``."""
        context = self._e.contexts[ctx]
        bound = d.kind == "param" and d.value in context.params
        return context.site if bound else -1

    # ── names (A30 (2)) ──

    def site_name(self, site: int) -> str:
        """A call site's name: a CALL by its callee (and a Java/PHP receiver); an R-X
        declaration by its declared type."""
        if site in self._e.calls.constructors:
            return self.name(self._e.calls.callee(site))
        return self.name(site)

    def name(self, node: int) -> str:
        """A30 (2): ``node`` as a hop name — up to three ``.``-joined segments, else
        ``<expr>`` — memoised per node."""
        return cached(self._names, node, self._name)

    def _name(self, node: int) -> str:
        segments = self._segments(node, MAX_HOP_SEGMENTS)
        return ".".join(segments) if segments else EXPR

    def _segments(self, node: int, budget: int) -> list[str] | None:
        """``node``'s name segments, or None past ``budget`` segments or for anything else."""
        if node < 0 or budget <= 0:
            return None
        read = _NAMERS.get(self._m.kind(node))
        return read(self, node, budget) if read is not None else None

    def _name_segment(self, node: int, budget: int) -> list[str] | None:
        text = self._m.ident(node) or ""
        return [text] if "." not in text and IDENTIFIER.fullmatch(text) else None

    def _literal_segment(self, node: int, budget: int) -> list[str] | None:
        return [FLAG] if self._m.ident(node) else None

    def _member_segments(self, node: int, budget: int) -> list[str] | None:
        """The object's segments, then the property's — a compound PROPERTY (C++
        ``filesystem::remove``, W3) brings its own."""
        tail = self._segments(first(self._m, node, Field.PROPERTY), budget - 1)
        return self._joined(first(self._m, node, Field.OBJECT), tail, budget)

    def _subscript_segments(self, node: int, budget: int) -> list[str] | None:
        return self._joined(first(self._m, node, Field.OBJECT), [INDEX], budget)

    def _call_segments(self, node: int, budget: int) -> list[str] | None:
        callee = self._segments(first(self._m, node, Field.CALLEE), budget)
        holder = first(self._m, node, Field.OBJECT)
        return self._joined(holder, callee, budget) if holder >= 0 and callee else callee

    def _joined(self, head: int, tail: list[str] | None, budget: int) -> list[str] | None:
        if tail is None:
            return None
        front = self._segments(head, budget - len(tail))
        return [*front, *tail] if front is not None else None


def _this_scope(model: FileModel, node: int) -> Sequence[int]:
    """The children a carrier search reads: none of a nested FUNCTION (another scope's)."""
    return () if model.kind(node) is Kind.FUNCTION else model.children(node)


# A node kind -> how its name segments are read; any other kind is ``<expr>``.
_NAMERS: Mapping[Kind, Callable[[Hops, int, int], list[str] | None]] = MappingProxyType({
    Kind.NAME: Hops._name_segment,
    Kind.PARAM: Hops._name_segment,  # a bare-identifier PARAM carries its own name (W7)
    Kind.LITERAL: Hops._literal_segment,
    Kind.MEMBER: Hops._member_segments,
    Kind.SUBSCRIPT: Hops._subscript_segments,
    Kind.CALL: Hops._call_segments,
})
