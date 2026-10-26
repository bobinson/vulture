"""The origin pass (feature 0102, LLD §8.1, §8.2, §8.4, §8.7; L6, W6, W8, W9, W11, W12, R-I,
R-J, R-K, R-O, R-Q, R-S, A28).

``Engine`` answers ``origins`` for three kinds of KEY, each memoised: a node in a context
(``_NODE``), a Def in a context (``_DEF``) and the union of a summarised function's return
values (``_RETURNS``). A context is the base (index 0: every function analysed on its own) or
a SUMMARY — a local callee run with its parameters bound to one call's argument origins
(§8.4), memoised on ``(callee, canonical origins)``: at most ``MAX_SUMMARY_SIGNATURES`` per
callee, nested at most ``MAX_SUMMARY_DEPTH`` deep, re-entering a callee already on the summary
stack answering ``unknown(recursion)`` first (A28 (10)).

**The table.** ``RULES`` maps each node kind to its §8.2 row; a CALL is further dispatched by
its MODEL-ONLY class (a local summary, R-U's accessor, a reading function) and then by its
value-level class: the accessor shape (L6, W9 (c)), a request sink (R-I), numeric (R-Q), a
sanitiser, R-S's method form, else rule 15's propagate-through.

**The solver.** A rule is a plain origin set, or a generator that YIELDS the keys it needs and
receives their origins. ``_Solver`` drives them on an explicit stack — a long def chain never
meets the interpreter's recursion limit — and treats the key graph's strongly connected
components (a loop-carried write, ``p = p + x``) by Tarjan's low-link: a key read while it is
still being computed answers its assumed value (first the empty set), the component's members
are kept provisional, and the component's root re-runs until its value is stable — at most
``MAX_ORIGINS + 2`` rounds, since a value only grows towards the ``TOP`` collapse — before
any member is memoised. Each component costs O(members x rounds); everything else O(1)
amortised per key.

Every value passes through ``bound``: an origin set past ``MAX_ORIGINS`` collapses to ``TOP``
and is tallied ``origin_overflow`` (A28 (3)); ``summary_cap`` is tallied where a summary is
refused, and the scope pass's ``branch_depth`` is carried over.

**Memory.** A key is one int (tag, context and index packed: no tuple per lookup or entry), a
union that adds nothing returns the set it already has (``_nodes.union``), and ``bound``
interns every value, so the memo holds each distinct origin set once however many keys share
it. Nothing here imports ``tree_sitter`` (D1).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Generator, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

from shared.ast._calls import Calls, call_writes
from shared.ast._nodes import (
    NOT_READ,
    cached,
    first,
    is_kind,
    kids_outside,
    object_of,
    open_links,
    segment,
    union,
)
from shared.ast._params import Params
from shared.ast._records import (
    CONSTANT,
    EMPTY,
    EXTERNAL,
    OVERFLOW,
    PARAM,
    TOP,
    Origins,
    external,
    externals,
    only,
    role_set,
    unknown,
)
from shared.ast.coverage import ORIGIN_OVERFLOW, SUMMARY_CAP
from shared.ast.kinds import Field, Kind
from shared.ast.limits import (
    MAX_ORIGINS,
    MAX_SUMMARY_DEPTH,
    MAX_SUMMARY_SIGNATURES,
    WORDS_MEMO,
)
from shared.ast.profile import PROFILES
from shared.ast.profiles import EMPTY_MAP
from shared.ast.roles import (
    BOUND_SOURCE_WORDS,
    CONDITIONAL_SOURCE_ROOTS,
    FILE_NAME_WORDS,
    NO_ROLES,
    PATH_RESULT_WORDS,
    SOURCE_WORDS,
    glue,
    sanitizer_roles,
    words,
)
from shared.ast.scope import ScopeTable

if TYPE_CHECKING:
    from shared.ast.model import FileModel
    from shared.ast.scope import Def

__all__ = ["BASE", "CONSTANTS", "DEF", "NODE", "RULES", "Context", "Engine", "Key"]

# The three kinds of key. A key packs (tag, context, index) into ONE int: the tag in its low
# _TAG_BITS, the index (a node id below MAX_NODES, a Def position or a FUNCTION node) in the
# next _INDEX_BITS, the context above them.
NODE, DEF, RETURNS = 0, 1, 2
type Key = int
_TAG_BITS, _INDEX_BITS = 2, 32
_TAG_MASK, _INDEX_MASK = (1 << _TAG_BITS) - 1, (1 << _INDEX_BITS) - 1
_CTX_SHIFT = _TAG_BITS + _INDEX_BITS
type Need = Generator[Key, Origins, Origins]
type Answer = Origins | Need

CONSTANTS: Origins = frozenset({CONSTANT})
# The collapse's marker as a set: ``bound`` tests a set against it by the hashes both sets
# store, never calling ``Origin.__hash__`` (a dataclass's, in Python) once per value.
_OVERFLOWED: Origins = frozenset({OVERFLOW})
_UNRESOLVED: Origins = frozenset({unknown("unresolved")})
_PARAM: Origins = frozenset({PARAM})
_ERROR = only("error")
_NETWORK = only("network")
_REQUEST = only("request")
_DYNAMIC: Origins = frozenset({unknown("dynamic")})
_DEPTH: Origins = frozenset({unknown("depth")})
_RECURSION: Origins = frozenset({unknown("recursion")})
_SUMMARY_CAP: Origins = frozenset({unknown(SUMMARY_CAP)})
_ARITY: Origins = frozenset({unknown("arity")})
_EXTERNAL_CALL: Origins = frozenset({unknown("external_call")})
_PATH_NORMALIZE = frozenset({"path_normalize"})
_NUMERIC = "numeric"
# A composite's children that are no value: W8's non-reads but a target (a PAIR's key, a
# declared name, a type), which a composite holds none of.
_NOT_VALUES = NOT_READ - {Field.LHS, Field.TARGET, Field.SOURCE}
_STATEMENTS = frozenset({
    Kind.ASSIGN, Kind.AUG_ASSIGN, Kind.IF, Kind.LOOP, Kind.TRY, Kind.RETURN, Kind.THROW,
    Kind.JUMP, Kind.FUNCTION, Kind.CLASS, Kind.IMPORT, Kind.OTHER, Kind.WITH,
})


@dataclass(frozen=True, slots=True)
class Context:
    """One context (§8.4): the base (``fn == -1``), or the summary of the FUNCTION ``fn`` with
    its PARAM nodes bound (``params``), the functions on the summary stack, its depth and the
    call site that made it (a flow's first hop)."""

    fn: int
    params: Mapping[int, Origins]
    stack: frozenset[int]
    depth: int
    site: int


BASE = Context(-1, EMPTY_MAP, frozenset(), 0, -1)


@dataclass(slots=True)
class _Facts:
    """One memo per model-only fact the rules read, each keyed by node (§8.7; ``_nodes.cached``)."""

    call_class: dict[int, str] = field(default_factory=dict)  # a CALL's model-only class
    source: dict[int, Origins] = field(default_factory=dict)  # an unbound chain's source roles
    named: dict[int, bool] = field(default_factory=dict)  # R-S: a ``.name`` of a path result
    roles: dict[int, frozenset[str]] = field(default_factory=dict)  # a CALL's sanitiser roles
    renames: dict[int, bool] = field(default_factory=dict)  # R-S's method form
    roots: dict[int, tuple[int, str]] = field(default_factory=dict)  # a chain link's ``_root``


class _Caller(NamedTuple):
    """Where a summary is asked for: the caller's summary stack, its depth and the site."""

    stack: frozenset[int]
    depth: int
    site: int


def _key(tag: int, ctx: int, index: int) -> Key:
    return (ctx << _CTX_SHIFT) | (index << _TAG_BITS) | tag


def _union(parts: Iterable[Origins]) -> Origins:
    return union(parts, EMPTY)


def _gather(keys: Iterable[Key]) -> Generator[Key, Origins, list[Origins]]:
    """Yield each key; the origins received, in order."""
    found: list[Origins] = []
    for key in keys:
        found.append((yield key))
    return found


def _via(origins: Origins, roles: frozenset[str]) -> Origins:
    """§8.2 sanitiser row: each external origin gains ``roles`` in ``via``; the rest stay."""
    return frozenset(external(o.role, o.via | roles) if o.cls == EXTERNAL else o for o in origins)


# ── the solver ───────────────────────────────────────────────────────────────


@dataclass(slots=True, eq=False)
class _Frame:
    """One key being computed: its generator, stack index, Tarjan low-link, the members
    mark, whether a read reached it while open (``cyclic``) and the value those reads got."""

    key: Key
    gen: Need
    index: int
    low: int
    mark: int
    cyclic: bool = False
    assumed: Origins = EMPTY
    rounds: int = 0


class _Solver:
    """One demand-driven solve of a key (module docstring: the explicit stack and the
    strongly connected components)."""

    __slots__ = ("engine", "frames", "index", "members", "provisional")

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.frames: list[_Frame] = []
        self.index: dict[Key, int] = {}
        self.members: list[Key] = []
        self.provisional: dict[Key, tuple[Origins, int]] = {}

    def solve(self, key: Key) -> Origins:
        sent = self._push(key)
        if sent is not None:
            return sent
        while self.frames:
            sent = self._step(sent)
        return self.engine.memo[key]

    def _push(self, key: Key) -> Origins | None:
        """Start ``key``: an immediate answer is memoised and returned; a generator is framed."""
        started = self.engine.start(key)
        if isinstance(started, frozenset):
            value = self.engine.memo[key] = self.engine.bound(started)
            return value
        at = len(self.frames)
        self.frames.append(_Frame(key, started, at, at, len(self.members)))
        self.index[key] = at
        return None

    def _step(self, sent: Origins | None) -> Origins | None:
        frame = self.frames[-1]
        try:
            need = frame.gen.send(sent)  # type: ignore[arg-type]
        except StopIteration as done:
            return self._done(frame, self.engine.bound(done.value))
        return self._read(frame, need)

    def _read(self, frame: _Frame, need: Key) -> Origins | None:
        found = self.engine.memo.get(need)
        if found is not None:
            return found
        at = self.index.get(need)
        if at is not None:
            return self._back_edge(frame, at)
        held = self.provisional.get(need)
        if held is not None:
            frame.low = min(frame.low, held[1])
            return held[0]
        return self._push(need)

    def _back_edge(self, frame: _Frame, at: int) -> Origins:
        """A read of a key still being computed: its assumed value, the reader joining its
        component."""
        target = self.frames[at]
        target.cyclic = True
        frame.low = min(frame.low, at)
        return target.assumed

    def _done(self, frame: _Frame, value: Origins) -> Origins | None:
        self.frames.pop()
        del self.index[frame.key]
        if frame.low < frame.index:
            return self._member(frame, value)
        if frame.cyclic:
            return self._root_done(frame, value)
        return self._settle(frame, value)

    def _root_done(self, frame: _Frame, value: Origins) -> Origins | None:
        """A component's root: run again while its value moves (at most ``MAX_ORIGINS + 2``
        rounds, module docstring), else settled."""
        if value != frame.assumed and frame.rounds <= MAX_ORIGINS:
            return self._again(frame, value)
        return self._settle(frame, value)

    def _member(self, frame: _Frame, value: Origins) -> Origins:
        """A key inside a component whose root is still open: provisional until it settles."""
        self.provisional[frame.key] = (value, frame.low)
        self.members.append(frame.key)
        parent = self.frames[-1]
        parent.low = min(parent.low, frame.low)
        return value

    def _again(self, frame: _Frame, value: Origins) -> None:
        """A component root whose value moved: forget its members and run it again."""
        self._forget(frame.mark)
        frame.assumed, frame.rounds, frame.cyclic = value, frame.rounds + 1, False
        frame.low = frame.index
        frame.gen = self.engine.start(frame.key)  # type: ignore[assignment]
        self.frames.append(frame)
        self.index[frame.key] = frame.index

    def _settle(self, frame: _Frame, value: Origins) -> Origins:
        """The root's value is stable: it and its component's members (if any) are final —
        each member is provisional by construction (``_member``), once. Its value."""
        memo, mark = self.engine.memo, frame.mark
        memo[frame.key] = value
        for key in self.members[mark:]:
            memo[key] = self.provisional.pop(key)[0]
        del self.members[mark:]
        return value

    def _forget(self, mark: int) -> None:
        for key in self.members[mark:]:
            self.provisional.pop(key, None)
        del self.members[mark:]


# ── the engine ───────────────────────────────────────────────────────────────


class Engine:
    """One file's origin pass: the scope table, the call and parameter facts, the contexts
    and the memo (module docstring)."""

    def __init__(self, model: FileModel) -> None:
        self.m = model
        self._kinds = model.kind_ids
        self.scope = ScopeTable.on_demand(model, call_writes=call_writes)
        self.calls = Calls(model, self.scope)
        self.params = Params(model, self.scope, self.calls)
        self.tallies: Counter[str] = Counter(self.scope.tallies)
        self.contexts: list[Context] = [BASE]
        self.memo: dict[Key, Origins] = {}
        self._interned: dict[Origins, Origins] = {}
        self._summaries: dict[tuple[int, tuple[Origins, ...]], int] = {}
        self._signatures: Counter[int] = Counter()
        self._facts = _Facts()
        self._returns: dict[int, list[int]] | None = None  # built on the first summary
        profile = PROFILES[model.language]  # a model is of a validated language
        self._builtin_sources = profile.builtin_sources
        self._block_value = profile.block_value

    # ── reading ──

    def value(self, key: Key) -> Origins:
        """The origins of ``key``, solved on demand and memoised."""
        found = self.memo.get(key)
        return found if found is not None else _Solver(self).solve(key)

    def origins(self, node: int, ctx: int = 0) -> Origins:
        """``origins(node)`` in context ``ctx`` (the base by default)."""
        return self.value(_key(NODE, ctx, node))

    def def_origins(self, d: Def, ctx: int = 0) -> Origins:
        """The origins a Def binds, read in ``ctx`` (a Def of another scope in the base)."""
        return self.value(self.def_key(ctx, d))

    def held(self, ctx: int, position: int) -> Origins:
        """The origins the Def at ``position`` binds in context ``ctx`` — where ``def_at``
        reads it."""
        return self.value(_key(DEF, ctx, position))

    def start(self, key: Key) -> Answer:
        ctx, index = key >> _CTX_SHIFT, (key >> _TAG_BITS) & _INDEX_MASK
        return _STARTS[key & _TAG_MASK](self, ctx, index)

    def bound(self, origins: Origins) -> Origins:
        """§8.1: past ``MAX_ORIGINS`` (or holding the collapse) an origin set is ``TOP``;
        any other is interned (the memo keeps one object per distinct set)."""
        if len(origins) > MAX_ORIGINS:
            self.tallies[ORIGIN_OVERFLOW] += 1
            return TOP
        if not origins.isdisjoint(_OVERFLOWED):
            return TOP
        return self._interned.setdefault(origins, origins)

    def node_key(self, ctx: int, node: int) -> Key:
        return _key(NODE, ctx, node)

    def def_key(self, ctx: int, d: Def) -> Key:
        return _key(DEF, *self.def_at(ctx, d))

    def def_at(self, ctx: int, d: Def) -> tuple[int, int]:
        """Where a Def is read: ``(context, position)`` — in ``ctx`` when it is a Def of the
        function ``ctx`` summarises, else in the base (a Def of another scope never depends on
        this binding)."""
        own = ctx if self.contexts[ctx].fn == d.scope else 0
        return own, d.position

    # ── nodes (§8.2) ──

    def _node(self, ctx: int, node: int) -> Answer:
        return _RULE_OF_KIND[self._kinds[node]](self, ctx, node)

    def _unresolved(self, ctx: int, node: int) -> Answer:
        """§8.2 "anything else"."""
        return _UNRESOLVED

    def _constant(self, ctx: int, node: int) -> Answer:
        return CONSTANTS

    def _composite(self, ctx: int, node: int) -> Answer:
        """TEMPLATE, BINOP, TERNARY, ARRAY, OBJECT, PAIR, SPREAD, AWAIT, UNARY ...: the union of
        the value children (a PAIR's key is none); with none, a constant (an empty literal)."""
        kids = kids_outside(self.m, node, _NOT_VALUES)
        return self._union_of(ctx, kids) if kids else CONSTANTS

    def _union_of(self, ctx: int, nodes: Iterable[int]) -> Need:
        parts = yield from _gather(self.node_key(ctx, n) for n in nodes)
        return _union(parts)

    def _assign(self, ctx: int, node: int) -> Answer:
        """An ASSIGN read as a value: its RHS; an R-X declaration: its constructor call."""
        if node in self.calls.constructors:
            return self._union_of(ctx, self.calls.args(node))
        values = self.m.children(node, Field.RHS)
        return self._union_of(ctx, values) if values else CONSTANTS

    def _kwarg(self, ctx: int, node: int) -> Answer:
        return self._union_of(ctx, self.m.children(node, Field.VALUE))

    def _name(self, ctx: int, node: int) -> Answer:
        """NAME: ``read(x)`` if bound; else a source word's role, else unresolved (W9 (b))."""
        defs = self.scope.resolve(node)
        return self._read(ctx, node, defs) if defs else self._unbound(node)

    def _read(self, ctx: int, node: int, defs: Sequence[Def]) -> Need:
        """The union of the Defs' origins (one Def, most reads: its own set, or ``EMPTY`` as
        ``_union`` gives it, without gathering), with ``unknown(depth)`` past a cap."""
        if len(defs) == 1:
            found = yield self.def_key(ctx, defs[0])
        else:
            found = _union((yield from _gather(self.def_key(ctx, d) for d in defs)))
        return self._at_depth(node, found or EMPTY)

    def _at_depth(self, node: int, found: Origins) -> Origins:
        """``found``, and ``unknown(depth)`` for a read the scope pass capped (§7.1, §7.2)."""
        return found | _DEPTH if self.scope.depth_capped(node) else found

    def _unbound(self, node: int) -> Origins:
        name = self.m.ident(node) or ""
        role = self._builtin_sources.get(name)
        if role is not None:
            return only(role)
        return _source_roles(name, bound=False) or _UNRESOLVED

    def _chain(self, ctx: int, node: int) -> Answer:
        """MEMBER / SUBSCRIPT: ``read("o.f")`` if bound; else the object's (and a subscript's
        key's) origins, plus the chain's source role (W8, W9 (b)) and R-S's ``.name``."""
        defs = self.scope.resolve(node)
        return self._read(ctx, node, defs) if defs else self._unbound_chain(ctx, node)

    def _unbound_chain(self, ctx: int, node: int) -> Need:
        links = (*self.m.children(node, Field.OBJECT), *self.m.children(node, Field.INDEX))
        parts = yield from _gather(self.node_key(ctx, k) for k in links)
        found = _union((*parts, cached(self._facts.source, node, self._chain_source)))
        return _via(found, _PATH_NORMALIZE) if cached(self._facts.named, node, self._file_name) else found

    def _chain_source(self, node: int) -> Origins:
        """W9 (b): the chain's ROOT identifier's words against ``SOURCE_WORDS``
        (``_root_source``) and ``CONDITIONAL_SOURCE_ROOTS`` on the root and the next segment."""
        root, following = self._root(node)
        if root < 0:
            return EMPTY
        ident = self.m.ident(root) or ""
        return _union((self._root_source(root, ident, following), _conditional_source(ident, following)))

    def _root_source(self, root: int, ident: str, following: str) -> Origins:
        """The root's words, read as a bound name when a Def binds it (``_source_roles``); a
        root bound by an import (a module) is skipped for the next segment."""
        defs = self.scope.resolve(root)
        word = following if any(d.kind == "import" for d in defs) else ident
        return _source_roles(word, bound=bool(defs))

    def _root(self, node: int) -> tuple[int, str]:
        """The chain's root NAME (through MEMBER / SUBSCRIPT objects only) and the segment
        that follows it (M1: ``""`` for a dynamic key); ``-1`` when the chain starts at
        anything else (a call result). Every link of a chain has the same answer, so each is
        memoised once its chain is walked (``_nodes.open_links``)."""
        found = self._facts.roots.get(node)
        return found if found is not None else self._fill_roots(node)

    def _fill_roots(self, node: int) -> tuple[int, str]:
        roots = self._facts.roots
        links, below = open_links(self.m, node, roots)
        found = roots.get(below) or self._chain_start(below, links[-1])
        for link in links:
            roots[link] = found
        return found

    def _chain_start(self, start: int, innermost: int) -> tuple[int, str]:
        """``_root``'s answer for a chain that starts at ``start``, ``innermost`` its link."""
        if not is_kind(self.m, start, Kind.NAME):
            return -1, ""
        return start, segment(self.m, innermost) or ""

    def _file_name(self, node: int) -> bool:
        """R-S (W12): a ``.name`` / ``.stem`` member of a CALL result whose chain says ``path``."""
        if self.m.kind(node) is not Kind.MEMBER:
            return False
        named = not FILE_NAME_WORDS.isdisjoint(words(segment(self.m, node) or ""))
        return named and self._path_result(object_of(self.m, node))

    def _path_result(self, node: int) -> bool:
        if not is_kind(self.m, node, Kind.CALL):
            return False
        return not self.calls.chain_words(node).isdisjoint(PATH_RESULT_WORDS)

    # ── calls (§8.2 CALL rows, §8.4) ──

    def _call(self, ctx: int, node: int) -> Answer:
        return _CALL_CLASSES[cached(self._facts.call_class, node, self._call_class)](self, ctx, node)

    def _call_class(self, call: int) -> str:
        """The model-only class of a CALL: a local summary (a local def wins), a source read
        (R-U, then a reading function: L6, W9), else one decided on values."""
        if self.calls.local(call) >= 0:
            return "summary"
        return "source" if self.params.source_role(call) else "value"

    def _source_call(self, ctx: int, call: int) -> Need:
        """R-U: ``external(request)``; a reading function: ``external(role)`` ∪ its arguments."""
        role = self.params.source_role(call) or ""
        parts = yield from _gather(self.node_key(ctx, a) for a in self.calls.values(call))
        return _union((only(role), *parts))

    def _value_call(self, ctx: int, call: int) -> Need:
        """The value-level CALL rows, in §8.2's order: the accessor shape (L6, W9 (c)), a
        request sink (R-I), numeric (R-Q), a sanitiser, R-S's method form, rule 15."""
        args = self.calls.values(call)
        parts = yield from _gather(self.node_key(ctx, a) for a in args)
        holder = self.calls.receiver(call)
        received = (yield self.node_key(ctx, holder)) if self._evaluated(holder) else self._qualifier(holder)
        if self._accessor_shape(call, parts, received):
            return _union((_REQUEST, *parts, received))
        return self._transfer(call, _union(parts), received)

    def _evaluated(self, holder: int) -> bool:
        """A receiver whose origins are read: anything but a bare NAME no Def binds."""
        return holder >= 0 and (self.m.kind(holder) is not Kind.NAME or bool(self.scope.resolve(holder)))

    @staticmethod
    def _qualifier(holder: int) -> Origins:
        """W9 (a): an unbound bare-NAME receiver is the callee chain's qualifier
        (``HttpRequest.newBuilder``): its words never make the call a source."""
        return _UNRESOLVED if holder >= 0 else EMPTY

    def source_read(self, call: int, ctx: int) -> bool:
        """L6: ``call`` is a source read, so never also a sink — by its memoised model-only
        class (R-U, a reading function; a sink is never a local summary), else by the accessor
        shape read in ``ctx``."""
        found = cached(self._facts.call_class, call, self._call_class) == "source"
        return found or self._accessor_read(call, ctx)

    def _accessor_read(self, call: int, ctx: int) -> bool:
        """L6, W9 (c), read outside the solver: ``call`` is an accessor-shaped source read.
        The receiver is read only once every positional argument is constant."""
        positional = self.calls.args(call)
        holder = self.calls.receiver(call)
        if not positional or not self._evaluated(holder):
            return False
        return self._all_constant_at(positional, ctx) and _holds_request(self.origins(holder, ctx))

    def _all_constant_at(self, nodes: Sequence[int], ctx: int) -> bool:
        """``_all_constant`` of the origins of ``nodes`` in ``ctx``, each one read."""
        return _all_constant([self.origins(n, ctx) for n in nodes])

    def _accessor_shape(self, call: int, parts: Sequence[Origins], received: Origins) -> bool:
        """≥ 1 positional argument, each constant, on a receiver holding external(request)."""
        positional = parts[: len(self.calls.args(call))]
        return _all_constant(positional) and _holds_request(received)

    def _transfer(self, call: int, args: Origins, received: Origins) -> Origins:
        if self.calls.sink_args(call, "request"):
            return _union((_NETWORK, args))  # R-I
        roles = cached(self._facts.roles, call, self._sanitiser_roles)
        if roles:
            return _sanitised(args, roles)
        if cached(self._facts.renames, call, self._method_name):
            return _union((_via(received, _PATH_NORMALIZE), args))  # R-S, method form (W12)
        return self._propagated(call, args, received)

    def _propagated(self, call: int, args: Origins, received: Origins) -> Origins:
        """Rule 15: a call with an argument or a receiver propagates their origins; one with
        neither is ``unknown(external_call)``."""
        shaped = bool(self.calls.values(call)) or self.calls.receiver(call) >= 0
        return _union((args, received)) if shaped else _EXTERNAL_CALL

    def _sanitiser_roles(self, call: int) -> frozenset[str]:
        """A CALL's sanitiser roles, as the one shared copy of that role set (an R-X
        declaration has none)."""
        if call in self.calls.constructors:
            return NO_ROLES
        return role_set(sanitizer_roles(self.m, call, symbol_of=self.calls.symbol_of))

    def _method_name(self, call: int) -> bool:
        """R-S (W12): ``file_name()`` / ``getFileName()`` on a CALL result whose chain says path."""
        named = not FILE_NAME_WORDS.isdisjoint(words(self.calls.ident(call)))
        return named and self._path_result(self.calls.receiver(call))

    # ── summaries (§8.4) ──

    def _summary(self, ctx: int, call: int) -> Answer:
        """A local callee: its summary under this call's argument origins, cut to
        ``unknown(recursion)`` when it is already on the summary stack (tested first, A28
        (10)) and to ``unknown(summary_cap)`` past ``MAX_SUMMARY_DEPTH``."""
        fn = self.calls.local(call)
        context = self.contexts[ctx]
        stack = context.stack if context.fn >= 0 else frozenset({self.m.function_of(call)})
        if fn in stack:
            return _RECURSION
        if context.depth >= MAX_SUMMARY_DEPTH:
            return self._refused()
        return self._summarise(ctx, call, fn, stack)

    def _summarise(self, ctx: int, call: int, fn: int, stack: frozenset[int]) -> Need:
        values = self.calls.values(call)
        parts = yield from _gather(self.node_key(ctx, a) for a in values)
        bound = self._bind(call, fn, parts)
        child = self._context(fn, bound, _Caller(stack, self.contexts[ctx].depth, call))
        return (yield _key(RETURNS, child, fn)) if child >= 0 else self._refused()

    def _refused(self) -> Origins:
        """A summary refused at a cap: ``unknown(summary_cap)``, tallied (A28 (3), A32)."""
        self.tallies[SUMMARY_CAP] += 1
        return _SUMMARY_CAP

    def _bind(self, call: int, fn: int, parts: Sequence[Origins]) -> tuple[Origins, ...]:
        """§8.4: each parameter's origins — positionally, then by keyword name; an unmatched
        one is ``unknown(arity)`` (a leading ``self`` / ``cls`` is no positional slot)."""
        positional = parts[: len(self.calls.args(call))]
        named = dict(zip(self.calls.kwargs(call), parts[len(positional) :], strict=True))
        return tuple(self._bound_param(p, i, positional, named) for i, p in enumerate(self.params.slots(fn)))

    def _bound_param(
        self, param: int, i: int, positional: Sequence[Origins], named: Mapping[str, Origins]
    ) -> Origins:
        """One parameter's binding: a keyword argument of one of its names, else the ``i``-th
        positional argument, else ``unknown(arity)``."""
        by_name = self._keyword(param, named)
        if by_name is not None:
            return by_name
        return positional[i] if i < len(positional) else _ARITY

    def _keyword(self, param: int, named: Mapping[str, Origins]) -> Origins | None:
        """The keyword argument of the first of ``param``'s names one is passed by, else None."""
        return next((named[n] for n in self.scope.param_names(param) if n in named), None)

    def _context(self, fn: int, bound: tuple[Origins, ...], caller: _Caller) -> int:
        """The summary context of ``(fn, bound)``: memoised; a new one only below
        ``MAX_SUMMARY_SIGNATURES`` signatures of ``fn``, else ``-1``."""
        found = self._summaries.get((fn, bound))
        if found is not None:
            return found
        if self._signatures[fn] >= MAX_SUMMARY_SIGNATURES:
            return -1
        self._signatures[fn] += 1
        binding = MappingProxyType(dict(zip(self.params.slots(fn), bound, strict=True)))
        context = Context(fn, binding, caller.stack | {fn}, caller.depth + 1, caller.site)
        self.contexts.append(context)
        self._summaries[fn, bound] = len(self.contexts) - 1
        return len(self.contexts) - 1

    def summary(self, fn: int, arg_origins: Sequence[Origins]) -> Origins:
        """``fn``'s summary from the base with its parameters bound positionally to
        ``arg_origins`` (an unmatched one ``unknown(arity)``), as a call site makes it."""
        slots = self.params.slots(fn)
        bound = tuple(self._bound_param(p, i, arg_origins, EMPTY_MAP) for i, p in enumerate(slots))
        child = self._context(fn, bound, _Caller(frozenset(), 0, -1))
        return self.value(_key(RETURNS, child, fn)) if child >= 0 else self._refused()

    def _returned(self, ctx: int, fn: int) -> Answer:
        """A summary's value: the union of ``fn``'s return values in ``ctx``; none returns a
        constant (``undefined`` / ``None``)."""
        if self._returns is None:
            self._returns = self._indexed_returns()
        values = self._returns.get(fn, ())
        return self._union_of(ctx, values) if values else CONSTANTS

    def _indexed_returns(self) -> dict[int, list[int]]:
        """Each FUNCTION's return values: its RETURNs' children, an expression body (``x =>
        x``) and, in Rust, a body's last expression."""
        returns: dict[int, list[int]] = {}
        for ret in self.m.nodes(Kind.RETURN):
            returns.setdefault(self.m.function_of(ret), []).extend(self.m.children(ret))
        for fn in self.m.functions():
            returns.setdefault(fn, []).extend(self._body_values(fn))
        return returns

    def _body_values(self, fn: int) -> list[int]:
        body = first(self.m, fn, Field.BODY)
        if body < 0:
            return []
        return self._tail(body) if self.m.kind(body) is Kind.BLOCK else [body]

    def _tail(self, body: int) -> list[int]:
        """A ``block_value`` body's last expression (Rust: no ``return``), else nothing."""
        if not self._block_value:
            return []
        return [n for n in self.m.children(body)[-1:] if self.m.kind(n) not in _STATEMENTS]

    # ── Defs (§7, §8.2) ──

    def _def(self, ctx: int, position: int) -> Answer:
        d = self.scope.defs[position]
        return _DEF_RULES.get(d.kind, Engine._valued)(self, ctx, d)

    def _valued(self, ctx: int, d: Def) -> Answer:
        """An ASSIGN, DESTRUCT, loop or ``with`` binding: its value's origins (a constant for a
        declaration with no value); a binding from a ``require`` / ``import`` answers with its
        imported symbol (R-H, W6)."""
        if d.symbol is not None:
            return _imported(d.symbol)
        return CONSTANTS if d.value is None else _one(self.node_key(ctx, d.value))

    def _import(self, ctx: int, d: Def) -> Answer:
        return _imported(d.symbol or d.name)

    def _catch(self, ctx: int, d: Def) -> Answer:
        return _ERROR

    def _function(self, ctx: int, d: Def) -> Answer:
        return _UNRESOLVED

    def _param(self, ctx: int, d: Def) -> Answer:
        """A parameter: its bound origins in its own summary; else its base origins (§8.2
        PARAM row) with R-B's receiver, else ``unknown(param)``."""
        bound = self.contexts[ctx].params.get(d.value) if d.value is not None else None
        return bound if bound is not None else self._base_param(d)

    def _base_param(self, d: Def) -> Answer:
        """A parameter no summary binds: its base origins (§8.2 PARAM row) with R-B's
        receiver, else ``unknown(param)``."""
        base = self.params.origins(d)
        holder = self.params.iteration_receiver(d)
        if holder < 0:
            return base or _PARAM
        return _joined(self.node_key(0, holder), base)  # R-B: the receiver, read where it stands

    def _aug(self, ctx: int, d: Def) -> Need:
        """§7.2 AUG, W8, R-J, R-W: what the name held (the Defs reaching the Def's node) and
        what the write adds."""
        added, extra = self._added(d)
        prior = [self.def_key(ctx, p) for p in self.scope.resolve(d.node)]
        parts = yield from _gather([*prior, *(self.node_key(ctx, n) for n in added)])
        return _union((*parts, extra))

    def _added(self, d: Def) -> tuple[Sequence[int], Origins]:
        """What an ``aug`` Def adds: R-J's other arguments and ``unknown(dynamic)``; R-W's
        receiver and other arguments; W8's value and ``unknown(dynamic)``; AUG's value."""
        if d.value is None:
            return (), EMPTY
        if self._writes_in_place(d):
            return self._call_written(d)
        dynamic = _DYNAMIC if self.m.kind(d.node) is Kind.SUBSCRIPT else EMPTY
        return (d.value,), dynamic

    def _writes_in_place(self, d: Def) -> bool:
        return self.m.kind(d.value) is Kind.CALL and d.node in call_writes(self.m, d.value)  # type: ignore[arg-type]

    def _call_written(self, d: Def) -> tuple[Sequence[int], Origins]:
        call: int = d.value  # type: ignore[assignment]
        args = self.calls.args(call)
        if args and args[0] == d.node:
            return args[1:], _DYNAMIC  # R-J: merged into arg 0
        holder = self.calls.receiver(call)
        held = [holder] if holder >= 0 else []
        return held + self._other_args(args, d.node), EMPTY  # R-W

    def _other_args(self, args: Sequence[int], written: int) -> list[int]:
        """R-W: the arguments other than the reference the written NAME is taken by."""
        return [a for a in args if written not in (a, *self.m.children(a))]


def _one(key: Key) -> Need:
    return (yield key)


def _joined(key: Key, base: Origins) -> Need:
    found = yield key
    return _union((found, base))


def _all_constant(parts: Sequence[Origins]) -> bool:
    """L6, W9 (c): at least one argument, each exactly constant."""
    return bool(parts) and all(p == CONSTANTS for p in parts)


def _holds_request(origins: Origins) -> bool:
    """W9 (c): an external origin of role ``request``, by any rule (whatever its ``via``)."""
    return any(o.cls == EXTERNAL and o.role == "request" for o in origins)


def _sanitised(args: Origins, roles: frozenset[str]) -> Origins:
    """R-Q: a numeric coercion keeps no external origin (a constant); any other sanitiser
    adds its roles to ``via`` (§8.2)."""
    if _NUMERIC in roles:
        return CONSTANTS | (args - externals(args))
    return _via(args, roles)


# A44 (1) (b): a generic container word names a request only as a member of a request-rooted
# chain or as a parameter in handler context (``_params``), so a BOUND name - a chain root a Def
# binds, an import's symbol - is read by ``BOUND_SOURCE_WORDS``. An unbound name, or a chain
# rooted at one, binds no parameter and keeps every source word (`requests.get(user_input)`).
# Indexed by ``bound``.
_SOURCE_TABLES: tuple[Mapping[str, frozenset[str]], ...] = (SOURCE_WORDS, BOUND_SOURCE_WORDS)


@lru_cache(maxsize=WORDS_MEMO)
def _source_roles(text: str, *, bound: bool) -> Origins:
    """``external(role)`` for each source role a word of ``text`` hits (W9 (b)), read as a
    bound name or not (``_SOURCE_TABLES``); memoised like ``words()``, under the same bound."""
    found = words(text)
    return _union(only(role) for role, lexicon in _SOURCE_TABLES[bound].items() if not lexicon.isdisjoint(found))


def _conditional_source(root: str, following: str) -> Origins:
    """W9 (b): ``external(role)`` when ``CONDITIONAL_SOURCE_ROOTS`` names the chain's root
    identifier with the segment that follows it, else nothing."""
    role = CONDITIONAL_SOURCE_ROOTS.get(glue(root), EMPTY_MAP).get(glue(following))
    return only(role) if role else EMPTY


def _imported(symbol: str) -> Origins:
    """R-H: an import binding answers with its symbol — a source word's role, else
    unresolved (``from flask import request`` is ``external(request)``)."""
    return _source_roles(symbol, bound=True) or _UNRESOLVED


# §8.2: each node kind's row.
RULES: Mapping[Kind, Callable[[Engine, int, int], Answer]] = MappingProxyType({
    Kind.LITERAL: Engine._constant,
    **dict.fromkeys(
        (Kind.TEMPLATE, Kind.BINOP, Kind.TERNARY, Kind.ARRAY, Kind.OBJECT, Kind.PAIR,
         Kind.SPREAD, Kind.AWAIT, Kind.UNARY, Kind.ARGS, Kind.DESTRUCT, Kind.COMPREHENSION,
         Kind.YIELD),
        Engine._composite,
    ),
    Kind.NAME: Engine._name,
    Kind.MEMBER: Engine._chain,
    Kind.SUBSCRIPT: Engine._chain,
    Kind.CALL: Engine._call,
    Kind.KWARG: Engine._kwarg,
    Kind.ASSIGN: Engine._assign,
})
# The same rows by the kind's int (``FileModel.kind_ids``); any other kind is unresolved.
_RULE_OF_KIND: tuple[Callable[[Engine, int, int], Answer], ...] = tuple(
    RULES.get(kind, Engine._unresolved) for kind in Kind
)
# A CALL's model-only class -> its row.
_CALL_CLASSES: Mapping[str, Callable[[Engine, int, int], Answer]] = MappingProxyType({
    "summary": Engine._summary,
    "source": Engine._source_call,
    "value": Engine._value_call,
})
# A Def's kind -> its row; every other kind is valued (assign, destruct, loop, with).
_DEF_RULES: Mapping[str, Callable[[Engine, int, Def], Answer]] = MappingProxyType({
    "param": Engine._param,
    "catch": Engine._catch,
    "function": Engine._function,
    "import": Engine._import,
    "aug": Engine._aug,
})
# A key's tag -> what computes it.
_STARTS: Mapping[int, Callable[[Engine, int, int], Answer]] = MappingProxyType({
    NODE: Engine._node,
    DEF: Engine._def,
    RETURNS: Engine._returned,
})
