"""Scopes and def-use (feature 0102, LLD §7; A22-A26; W6, W7, W8, W11, W13; L10; C2, C4).

``ScopeTable.build(model)`` runs one pass per scope — the MODULE, then every FUNCTION in the
order the pass meets it — over the file model and answers the def-use question the flow pass
(§8) asks of every read: which bindings (``Def``) reach it. The pass is lexicon-free: it knows
the node kinds and fields of §6.1 and the scope rules of the file's profile (``ScopeRules``),
never a word but R-H's two import callees.

**The state (§7.2, D6).** A scope's state maps a name to the set of Defs that may reach the
current point. It is LAYERED: a base plus one delta per open branch. A read looks the deltas
up innermost-first, then the base, so it costs the number of open branches, at most
``MAX_BRANCH_DEPTH``; a write goes to the innermost delta. Closing a branch joins its
alternatives key-wise over the keys THEIR deltas hold — a missing side reads the state below
— so a join costs ``O(|Δa| + |Δb|)``, never the size of the state. ``state_factory`` builds
every one of those dicts, the base and each delta, and nothing else (A22). A binding set
holds Def ids (ints: a join hashes in C); a name that may have NO Def in the scope on some
path carries the ``_UNBOUND`` id in its set.

**Statements** are dispatched by kind (``STATEMENTS``): an unconditional write overwrites; an
IF's alternatives, the arms of a switch/match (L10, A25: the BLOCK children with Field NONE
of an OTHER node, each run from the pre-state, post = ``join(pre, Δ1, …, Δk)``), a TRY's body
and handlers and a LOOP's body (twice — once only inside an enclosing loop's second pass, so
nested loops cost O(nodes x loop depth), never 2^depth) are deltas joined as §7.2 states. Past
``MAX_BRANCH_DEPTH`` open deltas a branch opens none: its writes are weak (unioned into the
innermost delta) and its reads are ``depth_capped`` — the flow pass's ``unknown(depth)`` —
and the branch is counted in ``tallies["branch_depth"]`` (§8.7, A28 (3), A32).

**Bindings.** A NAME, a pattern's leaves (W6: a PAIR binds its VALUE, a rest leaf and an
array-pattern leaf the whole RHS), a two-segment MEMBER path (``o.f``; a deeper write binds
nothing, R-K), a parameter (W7, A26; only from the ARGS under Field PARAMS of a FUNCTION,
A3), a loop or ``with`` target, a CATCH parameter, an import (W6, R-H: ``Def.symbol``) and a
function (also an ASSIGN of one, R-G). ``k > 1`` targets bind pairwise when the RHS holds
``k`` values, else each binds the one RHS (W11). An AUG write, a dynamic-key subscript write
(W8) and a write a caller's ``call_writes`` names (R-J, R-W) KEEP what the name held: it
takes one ``aug`` Def whose prior binding is the read recorded at the Def's node — so a
chain of them stays one Def wide — and every bound ``name.*`` gains it besides its own
(W8). A ``global``/PHP ``global`` statement is no Def (A24): the name is the MODULE's for the
rest of the function. C/C++ declarators are unwrapped by the worker (C4); a C++ declaration
that parses as a function prototype is a stack-constructor call only when every parameter is
a bare type naming an in-scope local or param Def (C2, R-X: ``constructors``), else it binds
nothing; a parameter list the worker shipped as a synthetic CALL (A36: one parameter read as a
subscript, ``in(argv[1])``) is kept a call on the same condition, read by the SUBSCRIPT's
OBJECT, else it is no call site (``prototypes``).

**Reads.** A NAME read resolves to the Defs reaching it; a MEMBER/SUBSCRIPT read to those of
its bound two-segment path (W8; a longer path is truncated to two segments and
``depth_capped``, §7.1), else to nothing — the flow pass then reads its object. A read that
may reach no Def of its scope is free (R-O, W13): it also resolves to every Def of that name
in each scope enclosing its function, the MODULE included. Reads accumulate over a loop's
passes; free reads are resolved once every scope has run.

Linear in the file's nodes per loop-nesting level (§8.7), run on an explicit work stack, so
nesting depth never meets the interpreter's recursion limit; ``resolve`` materialises a read's
Defs only when asked, once. Nothing here imports ``tree_sitter``, ``shared.tools`` or
``shared.validate`` (D1).

**On demand (§8.7).** ``build`` runs every scope. ``on_demand`` — the table the flow pass
reads — runs the MODULE and every function whose pass can leave a fact outside its own scope
(``_up_front``: a branch past the cap, tallied per file; a ``global`` write, a MODULE Def; an
R-X declaration, a constructor or prototype) up front, and any other function only when a read
in it, or a parameter of it, is first asked: the scopes enclosing it to their end first (R-O
reads all their Defs), its own as far as the top-level statement holding the read, where it
pauses — a read is final once its top-level statement has run, a loop's second pass included —
so every answer is ``build``'s. A function no question reaches never runs, nor do the
statements after the last one a question reaches.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, deque
from collections.abc import (
    Callable,
    Container,
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    Sequence,
)
from dataclasses import dataclass, field
from itertools import chain, repeat, takewhile
from operator import attrgetter
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from shared.ast._nodes import (
    CHAINS,
    cached,
    first,
    first_segment,
    is_kind,
    is_read,
    kids_of,
    kids_outside,
    last_segment,
    open_links,
    params_in,
    segment,
    union,
)
from shared.ast.coverage import BRANCH_DEPTH  # the branches past MAX_BRANCH_DEPTH (A28 (3), A32)
from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_BRANCH_DEPTH
from shared.ast.profile import PROFILES

if TYPE_CHECKING:
    from shared.ast.model import FileModel

__all__ = [
    "BRANCH_DEPTH",
    "STATEMENTS",
    "CallWrites",
    "Def",
    "DefKind",
    "ScopeTable",
    "StateFactory",
    "Use",
    "decorators",
]

# ── records (§7.1, A22, A24) ─────────────────────────────────────────────────

DefKind = Literal[
    "param", "assign", "aug", "destruct", "loop_target", "catch", "with", "import", "function"
]


@dataclass(frozen=True, slots=True)
class Def:
    """One binding (§7.1, A22).

    ``node`` is what is bound: a NAME (a pattern leaf, a target, a declared name), a
    bare-identifier PARAM, or the MEMBER/SUBSCRIPT a path write targets. ``value`` is the
    node whose value it binds: the RHS (pairwise, W11), the iterable of a loop or ``with``,
    the FUNCTION of a ``function`` Def, the PARAM of a ``param`` Def (the bare NAME of a JS
    ``x => …``), the CATCH of a ``catch`` Def, the IMPORT of an ``import`` Def, the CALL of a
    ``call_writes`` write and the declaration of an R-X constructor; None when there is none.
    ``scope`` is the FUNCTION node that owns the binding, ``0`` for the MODULE (also a write
    under ``global``, A24). ``symbol`` is the R-H symbol of an import binding, else None.

    An ``aug`` Def (AUG, W8's dynamic-key write, R-J, R-W) keeps what its name held: its
    value joins with the Defs ``ScopeTable.resolve(def.node)`` gives — the binding just
    before it (§7.2: ``write(x, read(x) | origins(e))``).

    ``position`` is the Def's index in ``ScopeTable.defs`` (document order; in an
    ``on_demand`` table, the order its scopes ran in), set when the table takes the Def: what
    the flow pass keys a Def by (an int hashes in C; the six fields do not), never part of its
    value (``-1`` for a Def no table holds).
    """

    node: int
    name: str
    kind: DefKind
    value: int | None
    scope: int
    symbol: str | None = None
    position: int = field(default=-1, compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class Use:
    """One read (§7.1): its node, the name or two-segment path it reads, and its scope."""

    node: int
    name: str
    scope: int


# What builds every State dict: the base and each delta (A22).
type StateFactory = Callable[[], MutableMapping[str, Any]]
# R-J / R-W, supplied by the flow pass: the NAME nodes a CALL writes in place.
type CallWrites = Callable[[FileModel, int], Iterable[int]]


# A binding set: the ids of the Defs that may reach a point. ``_UNBOUND`` means "no Def of
# this scope on some path": the read also reaches the enclosing scopes' Defs (R-O), a path
# read its root's (W8).
type _Binding = frozenset[int]
type _Layer = MutableMapping[str, _Binding]
type _Path = tuple[str, ...] | None
_UNBOUND = -1
_FREE: _Binding = frozenset((_UNBOUND,))

# ── grammar-free shape facts the pass reads ──────────────────────────────────

# §7.1: a bound name is a dotted path of at most two segments; a third one only marks a
# deeper read or write (R-K).
_BOUND_SEGMENTS = 2
# W6/W7: the patterns whose leaves bind, and the field their candidate leaves hang under
# (None: every child).
_PATTERNS: Mapping[Kind, Field | None] = MappingProxyType({
    Kind.DESTRUCT: Field.NONE, Kind.ARRAY: Field.NONE, Kind.OBJECT: Field.NONE,
    Kind.PARAM: Field.NONE, Kind.SPREAD: None,
})
_BRANCH_FIELDS = frozenset({Field.CONSEQ, Field.ALT})
_FUNCTION_OWN = frozenset({Field.PARAMS, Field.BODY, Field.NAME})  # the rest is read outside
_ASSIGN_OWN = frozenset({Field.LHS, Field.ANNOTATION, Field.NAME, Field.PARAMS})
_WITH_OWN = frozenset({Field.BODY, Field.TARGET})
_CATCH_FIELDS = frozenset({Field.PARAMS, Field.TARGET})
_HANDLERS = frozenset({Kind.CATCH, Kind.FINALLY})
_DECLARING = frozenset({Kind.FUNCTION, Kind.EXPORT})  # what may declare a function (hoisting)
_PARAM_HOLDERS = frozenset({Kind.ARGS, Kind.PARAM})
# A FUNCTION under one of these is a declaration: its name is a ``function`` Def.
_STATEMENT_PARENTS = frozenset({Kind.MODULE, Kind.BLOCK, Kind.CLASS, Kind.EXPORT, Kind.OTHER})
_IMPORTED = frozenset({Kind.NAME, Kind.PAIR, Kind.MEMBER})
# R-H (W6, every language): a DESTRUCT of a call to one of these builtins is an import binding.
_IMPORT_CALLS = frozenset({"require", "import"})
# C2 (R-X): a bare ``parameter_declaration`` ships as a PARAM whose one child is this.
_BARE_TYPE = (Field.ANNOTATION, Kind.NAME)
# The kinds whose node opens a delta, and the CATCH whose handler delta opens over its TRY's
# body delta: each delta open at a point is one of them above it, in the same scope's pass.
_BRANCHING = (Kind.IF, Kind.LOOP, Kind.TRY, Kind.CATCH, Kind.OTHER)
# A read's Defs come in document order: by node, then name (a Def's identity in its table).
_DOCUMENT_ORDER = attrgetter("node", "name")
# Past every node id: a scope run to its end.
_EVERY = 1 << 62


# ── the layered state (§7.2, D6) ─────────────────────────────────────────────


def _lookup(layers: Sequence[_Layer], key: str) -> _Binding | None:
    """``key``'s binding in the innermost layer that holds it, else None (a binding is a set,
    never None)."""
    for layer in reversed(layers):
        found = layer.get(key)
        if found is not None:
            return found
    return None


def _merged(prior: _Binding, found: _Binding) -> _Binding:
    """Two passes' Defs at one read: the larger set itself when it holds the other."""
    if found <= prior:
        return prior
    return found if prior <= found else prior | found


def _keys(alternatives: Sequence[Sequence[_Layer]]) -> Iterable[str]:
    """Every key the alternatives' deltas hold, each once (the join's key set)."""
    return dict.fromkeys(key for alt in alternatives for layer in alt for key in layer)


class _State:
    """A scope's layered state (§7.2): the base, then one delta per open branch."""

    __slots__ = ("_factory", "layers")

    def __init__(self, factory: StateFactory) -> None:
        self._factory = factory
        self.layers: list[_Layer] = [factory()]

    @property
    def depth(self) -> int:
        """How many deltas are open."""
        return len(self.layers) - 1

    def bound(self, key: str) -> _Binding:
        """``key``'s Defs; ``_FREE`` when no layer binds it (``_lookup``, inlined: every read
        asks it; a binding is a set, never None)."""
        for layer in reversed(self.layers):
            found = layer.get(key)
            if found is not None:
                return found
        return _FREE

    def write(self, key: str, binding: _Binding) -> None:
        self.layers[-1][key] = binding

    def push(self) -> None:
        self.layers.append(self._factory())

    def pop(self) -> _Layer:
        return self.layers.pop()

    def join(self, alternatives: Sequence[Sequence[_Layer]]) -> None:
        """Apply the key-wise union of ``alternatives`` — each its own stack of deltas over
        this state, a key it lacks read from this state; an empty stack is the pre-state
        itself — to the innermost open layer: ``O(Σ |Δ|)`` keys, never the state's."""
        for key in _keys(alternatives):
            below = self.bound(key)
            self.write(key, union([_through(alt, key, below) for alt in alternatives], _FREE))


def _through(alt: Sequence[_Layer], key: str, below: _Binding) -> _Binding:
    """``key``'s Defs as one alternative leaves them: its innermost delta's, else ``below``."""
    found = _lookup(alt, key)
    return below if found is None else found


@dataclass(slots=True, eq=False)
class _Branch:
    """One branching statement while it runs: its alternatives' closed deltas (each a stack
    of deltas: a TRY handler reads through its body's), and which opens pushed a delta."""

    node: int
    with_pre: bool
    alternatives: list[tuple[_Layer, ...]] = field(default_factory=list)
    opened: list[bool] = field(default_factory=list)
    handlers: list[_Layer] = field(default_factory=list)


# ── pairing targets with values (W11) ────────────────────────────────────────


def _paired(targets: Sequence[int], values: Sequence[int]) -> Iterator[tuple[int, int | None]]:
    """W11: ``k`` targets and ``k`` values pair by position; one value binds every target;
    otherwise (C's ``int a, b = 2``) each target takes the value that follows it before the
    next target, if any."""
    if len(values) == len(targets):
        return zip(targets, values, strict=True)
    if len(values) > 1:
        return _interleaved(targets, values)
    return zip(targets, repeat(values[0] if values else None, len(targets)), strict=True)


def _interleaved(
    targets: Sequence[int], values: Sequence[int]
) -> Iterator[tuple[int, int | None]]:
    """Each target and the first value between it and the next target (node indices are
    document order), else None."""
    limits = [*targets[1:], values[-1] + 1]
    for target, limit in zip(targets, limits, strict=True):
        k = bisect_right(values, target)
        yield target, values[k] if k < len(values) and values[k] < limit else None


def _loop_slot(fld: Field, after_body: bool) -> int:
    """Where a LOOP child goes: 0 the head, 1 the body, 2 the tail; ``-1`` a TARGET."""
    if fld is Field.TARGET:
        return -1
    if fld is Field.BODY:
        return 1
    return 2 if after_body else 0


def _split(nodes: Iterable[int], keep: Callable[[int], bool]) -> tuple[list[int], list[int]]:
    """``nodes`` that ``keep``, and the others, each in order."""
    kept: list[int] = []
    rest: list[int] = []
    for node in nodes:
        (kept if keep(node) else rest).append(node)
    return kept, rest


def _extended(path: _Path, segment: str | None) -> _Path:
    """``path`` plus ``segment``, kept to one segment past a bound name (§7.1)."""
    if path is None or segment is None:
        return None
    return path if len(path) > _BOUND_SEGMENTS else (*path, segment)


# ── the pass ─────────────────────────────────────────────────────────────────

# A Def's fields as the pass makes them (``Def`` but its position, which ``_table`` sets).
type _Binds = tuple[int, str, DefKind, int | None, int, str | None]
type _Step = tuple[Callable[[Any, Any], None], Any]
type _Work = int | _Step  # a node to visit by its kind, or a step


class _Paused(NamedTuple):
    """A scope's own state, as ``_Pass._enter`` takes it: its pending work, state, ``global``
    names and bound member paths — fresh (``_Pass._fresh``), or kept by a function scope paused
    at a top-level statement (``on_demand``, ``_Pass._pause``)."""

    todo: list[_Work]
    state: _State
    globals: set[str]
    members: dict[str, set[str]]


def _enclosers(model: FileModel, node: int) -> Iterator[int]:
    """The FUNCTIONs strictly above ``node``, nearest first (``function_of`` repeated)."""
    fn = model.function_of(node)
    while fn >= 0:
        yield fn
        fn = model.function_of(fn)


class _Pass:
    """One file's scope pass: the MODULE, then each FUNCTION it meets, each with its own state.

    Work is an explicit stack: a handler pushes the work of its node in reverse, so it runs in
    order, before anything pushed earlier. A node id on the stack is that node's visit,
    dispatched by its kind when it is popped (``_VISITS``); any other work is a
    ``(step, argument)`` pair.

    ``up_front`` None runs every function a pass meets (``build``); else only those in it, and
    any other one met is deferred until ``ensure`` asks for it (``on_demand``). A deferred
    function's pass touches its own scope's state alone, so running it later changes no
    answer of the scopes already run."""

    def __init__(
        self,
        model: FileModel,
        factory: StateFactory,
        call_writes: CallWrites | None,
        up_front: Container[int] | None = None,
    ) -> None:
        rules = PROFILES[model.language].scope_rules  # a model is of a validated language
        self._m = model
        self._kinds = model.kind_ids
        self._factory = factory
        self._call_writes = call_writes
        self._hoist = rules.functions_hoist
        self._vexing = rules.vexing_parse
        # W6: the segment of a dotted import that binds - Python's first, every other's last.
        self._bound_segment = first_segment if rules.import_binds_first else last_segment
        self._text_imports = rules.import_spec_text
        self._queue: deque[int] = deque()
        self._queued: set[int] = set()
        self._hoisted: set[int] = set()
        self._ids: dict[tuple[int, str], int] = {}
        self._defs: list[_Binds] = []  # by id, in the order the pass made them
        self._reads: dict[int, _Binding] = {}
        self._read_at: dict[int, tuple[str, int]] = {}  # a FREE read's name and scope (R-O)
        self._capped: set[int] = set()
        self._over: set[int] = set()
        self._constructors: dict[int, tuple[int, ...]] = {}
        self._prototypes: set[int] = set()  # A36: the synthetic CALLs R-X did not keep
        self._paths: dict[int, _Path] = {}
        self._param_names: dict[int, tuple[str, ...]] = {}  # each bound PARAM's (``_param``)
        self._up_front = up_front
        # Per started scope: the last node id whose reads are final (``_EVERY`` once run to its
        # end), and its own state while paused. A function met (``_queued``: every ``_drain``
        # empties the queue) and not started is deferred (``on_demand``).
        self._final: dict[int, int] = {}
        self._paused: dict[int, _Paused] = {}
        self._enter(0, self._fresh([]))

    # ── driving ──

    def run(self) -> ScopeTable:
        """The MODULE, then each function it runs now, then the table (free reads resolve once
        every Def they may reach is known)."""
        self._scope(0, _Pass._block)
        self._drain()
        return self._table()

    def _drain(self) -> None:
        """Every function met and not yet run: run now, or left deferred (``on_demand``)."""
        while self._queue:
            fn = self._queue.popleft()
            if self._up_front is None or fn in self._up_front:
                self._scope(fn, _Pass._function_body)

    def ensure(self, node: int) -> bool:
        """``on_demand``: make the read at ``node`` final — every scope enclosing ``node``'s run
        to its end (R-O reads all their Defs; a pass meets a function only while its encloser's
        runs), ``node``'s own as far as the top-level statement holding it (``_stop_for``).
        Whether a scope ran (the table then takes the Defs it made)."""
        fn = self._m.function_of(node)
        if fn < 0 or node <= self._final.get(fn, -1):
            return False
        for outer in self._unfinished_enclosers(fn):
            self._advance(outer, _EVERY)
        self._advance(fn, self._stop_for(fn, node))
        return True

    def _unfinished_enclosers(self, fn: int) -> list[int]:
        """The functions enclosing ``fn`` whose scope has not run to its end, outermost first."""
        return [*takewhile(self._unfinished, _enclosers(self._m, fn))][::-1]

    def _unfinished(self, fn: int) -> bool:
        return self._final.get(fn, -1) < _EVERY

    def _advance(self, fn: int, stop: int) -> None:
        """``fn``'s scope run on to ``stop`` (``_steps``): resumed when paused, started when met
        but not started; a function no pass has met stays unrun (none does in the whole file,
        ``build`` included). Then the functions it met."""
        if fn in self._paused:
            self._resume(fn, stop)
        elif fn in self._queued and fn not in self._final:  # met, not started
            self._scope(fn, _Pass._function_body, stop)
        self._drain()

    def _stop_for(self, fn: int, node: int) -> int:
        """The last node ``fn``'s pass must visit for the read at ``node`` to be final: the last
        of the top-level statement of ``fn``'s body holding it — node ids are document order,
        so it ends where the next one starts — or the last before the body, for a node of the
        parameters (bound, and their defaults read, before the body runs)."""
        body = self._m.children(fn, Field.BODY)
        if not body:
            return _EVERY
        if node < body[0]:
            return body[0] - 1
        starts = self._statements(body)
        k = bisect_right(starts, node)
        return starts[k] - 1 if k < len(starts) else _EVERY

    def _statements(self, body: Sequence[int]) -> Sequence[int]:
        """A function body's top-level units, as ``_function_body`` and ``_block`` push them:
        a lone BLOCK's statements, else the body's own nodes."""
        lone_block = len(body) == 1 and self._kinds[body[0]] == Kind.BLOCK
        return self._m.children(body[0]) if lone_block else body

    def _enter(self, fn: int, held: _Paused) -> None:
        """The scope owned by ``fn``, with ``held``'s work, state and bookkeeping: the one
        writer of a scope's own fields (``_pause`` is its inverse)."""
        self._fn = fn
        self._todo, self._state, self._globals, self._members = held
        self._single = 0  # > 0 inside a loop's second pass: nested loops run once
        self._over_cap = 0

    def _fresh(self, todo: list[_Work]) -> _Paused:
        """A scope's state before its pass: ``todo`` its first work, nothing bound."""
        return _Paused(todo, _State(self._factory), set(), {})

    def _scope(self, fn: int, start: Callable[[_Pass, int], None], stop: int = _EVERY) -> None:
        self._enter(fn, self._fresh([(start, fn)]))
        self._steps(fn, stop)

    def _steps(self, fn: int, stop: int) -> None:
        """``fn``'s pending work, until none is left or the next node to visit lies past
        ``stop``: then the scope pauses there (``_pause``)."""
        todo, kinds = self._todo, self._kinds
        while todo:
            work = todo.pop()
            if work.__class__ is int:
                if work > stop:
                    todo.append(work)
                    return self._pause(fn, stop)
                _VISITS[kinds[work]](self, work)  # type: ignore[index]
            else:
                work[0](self, work[1])  # type: ignore[index]
        self._final[fn] = _EVERY
        return None

    def _pause(self, fn: int, stop: int) -> None:
        """Keep ``fn``'s pending work and state for ``_resume``. A stop is the end of a
        top-level statement (``_stop_for``), where no delta is open, no loop pass runs and no
        branch is past the cap: the base state is the scope's whole state."""
        self._paused[fn] = _Paused(self._todo, self._state, self._globals, self._members)
        self._todo = []
        self._final[fn] = stop

    def _resume(self, fn: int, stop: int) -> None:
        self._enter(fn, self._paused.pop(fn))
        self._steps(fn, stop)

    def _later(self, steps: Sequence[_Work]) -> None:
        """Run ``steps`` next, in order: a node id is its own visit (``_VISITS``)."""
        self._todo.extend(reversed(steps))

    # ── generic nodes, blocks, functions ──

    def _children(self, node: int) -> None:
        """The most frequent visit: ``_later`` of the children, reversed as a list (a
        memoryview's own reverse iteration is several times slower)."""
        kids = self._m.children(node).tolist()  # type: ignore[attr-defined]
        kids.reverse()
        self._todo.extend(kids)

    def _skip(self, node: int) -> None:
        """A PARAM: bound by its owner, never read where it stands."""

    def _block(self, node: int) -> None:
        """A statement list; a hoisting profile declares its functions first (§7.2)."""
        kids = self._m.children(node)
        if self._hoist:
            self._hoist_functions(kids)
        self._later(kids)

    def _hoist_functions(self, kids: Sequence[int]) -> None:
        for fn in self._declarations(kids):
            self._bind_function(fn)
            self._hoisted.add(fn)

    def _declarations(self, kids: Sequence[int]) -> list[int]:
        """The function declarations among statements (only a FUNCTION or an EXPORT holds one,
        so no other statement is asked)."""
        kinds = self._kinds
        return [fn for kid in kids if kinds[kid] in _DECLARING for fn in self._declared(kid)]

    def _declared(self, node: int) -> Sequence[int]:
        """The function declarations a statement holds: itself, or those an EXPORT wraps."""
        kids = self._m.children(node) if self._m.kind(node) is Kind.EXPORT else (node,)
        return [kid for kid in kids if self._m.kind(kid) is Kind.FUNCTION]

    def _function(self, node: int) -> None:
        """A FUNCTION met by a pass: a declaration binds its name; its decorators and the
        other parts outside its parameters and body are read here; its body is a scope of
        its own, run later (§7.2)."""
        if self._declares(node):
            self._bind_function(node)
        self._later(self._outside(node))
        self._enqueue(node)

    def _declares(self, fn: int) -> bool:
        """A FUNCTION not hoisted already whose parent holds statements declares its name."""
        return fn not in self._hoisted and self._m.kind(self._m.parent(fn)) in _STATEMENT_PARENTS

    def _outside(self, fn: int) -> list[int]:
        """A FUNCTION's parts read where it stands: its decorators, a Go result list, a PHP
        ``use`` clause — everything but its name, parameters and body."""
        return kids_outside(self._m, fn, _FUNCTION_OWN)

    def _enqueue(self, fn: int) -> None:
        if fn not in self._queued:
            self._queued.add(fn)
            self._queue.append(fn)

    def _bind_function(self, fn: int) -> None:
        declared = first(self._m, fn, Field.NAME)
        self._bind(declared, self._m.ident(declared), "function", fn)

    def _function_body(self, fn: int) -> None:
        self._later([(_Pass._bind_params, fn), *self._m.children(fn, Field.BODY)])

    def _bind_params(self, fn: int) -> None:
        """A3: the ARGS under Field PARAMS hold the parameters (a Go receiver list is one; a
        Go result list, Field NONE, is not); a NAME under PARAMS is one (``x => …``)."""
        for holder in self._m.children(fn, Field.PARAMS):
            for param in params_in(self._m, holder):
                self._param(param)

    def _param(self, param: int) -> None:
        """W7: a default value is read in the function's state; the parameter binds, and the
        names it binds are kept under it in document order (A26: several for a pattern;
        ``ScopeTable.param_names``), made once — linear in its leaves."""
        self._later(self._m.children(param, Field.VALUE))
        names: list[str] = []
        for leaf, _ in self._param_leaves(param):
            name = self._m.ident(leaf)
            self._bind(leaf, name, "param", param)
            if name:  # as ``_bind``: no name, no Def
                names.append(name)
        self._param_names[param] = tuple(names)

    def _param_leaves(self, param: int) -> list[tuple[int, int]]:
        """W7, A26: a PARAM binds its own text; else each child under Field NAME (each leaf
        of a pattern there); else the leaves of its other children (a pattern PARAM, Python's
        ``typed_parameter``, a rest parameter)."""
        if self._m.ident(param):
            return [(param, -1)]
        names = self._m.children(param, Field.NAME)
        return self._leaves(names if names else (param,))

    # ── patterns (W6, W7) ──

    def _leaves(self, roots: Iterable[int]) -> list[tuple[int, int]]:
        """Every NAME a pattern binds, in document order, each with the PAIR it is the value
        of (``-1`` for none): R-H's symbol is that PAIR's key."""
        out: list[tuple[int, int]] = []
        stack = [(root, -1) for root in reversed(list(roots))]
        while stack:
            node, pair = stack.pop()
            self._expand(node, pair, stack, out)
        return out

    def _expand(
        self, node: int, pair: int, stack: list[tuple[int, int]], out: list[tuple[int, int]]
    ) -> None:
        kind = self._m.kind(node)
        if kind is Kind.NAME:
            out.append((node, pair))
            return
        owner = node if kind is Kind.PAIR else -1
        stack.extend((part, owner) for part in reversed(self._pattern_parts(node, kind)))

    def _pattern_parts(self, node: int, kind: Kind) -> Sequence[int]:
        """W6: a PAIR's value (its key when it has none: ``import { c }``); a pattern's
        positional parts; nothing else holds a leaf."""
        if kind is Kind.PAIR:
            return self._m.children(node, Field.VALUE) or self._m.children(node, Field.KEY)
        return self._m.children(node, _PATTERNS[kind]) if kind in _PATTERNS else ()

    # ── binding ──

    def _owner(self, name: str) -> int:
        """A24: a name under ``global`` is the MODULE's; anything else the scope's."""
        if not self._globals:
            return self._fn
        return 0 if name.partition(".")[0] in self._globals else self._fn

    def _def(
        self, node: int, name: str, kind: DefKind, value: int | None, symbol: str | None = None
    ) -> int:
        """The id of the one Def of ``name`` at ``node`` (a loop's second pass meets it
        again)."""
        found = self._ids.get((node, name))
        if found is None:
            found = self._ids[node, name] = len(self._defs)
            self._defs.append((node, name, kind, value, self._owner(name), symbol))
        return found

    def _bound(self, key: str) -> _Binding:
        return self._state.bound(key)

    def _put(self, key: str, binding: _Binding) -> None:
        """A write; weak (unioned) past MAX_BRANCH_DEPTH, where no delta isolates it
        (``_State.write``, inlined: every bind writes)."""
        self._state.layers[-1][key] = binding | self._bound(key) if self._over_cap else binding

    def _bind(
        self, node: int, name: str | None, kind: DefKind, value: int | None,
        symbol: str | None = None,
    ) -> None:
        """An overwrite of ``name``: it now has this one Def, and no bound member path."""
        if not name:
            return
        self._put(name, frozenset((self._def(node, name, kind, value, symbol),)))
        for key in self._members.get(name, ()):
            self._put(key, _FREE)

    def _augment(self, node: int, key: str, value: int | None) -> None:
        """§7.2 AUG, W8, R-J, R-W: a write that KEEPS what ``key`` held. ``key`` takes one
        ``aug`` Def whose prior binding is the read recorded at its node
        (``resolve(def.node)``), so a chain of them stays one Def wide; every bound
        ``key.*`` gains it besides its own (W8)."""
        self._keep(node, key)
        added = self._def(node, key, "aug", value)
        self._put(key, frozenset((added,)))
        self._register(key)
        for member in self._members.get(key, ()):
            self._state.write(member, self._bound(member) | {added})

    def _keep(self, node: int, key: str) -> None:
        """Record at ``node`` what ``key`` holds: a path's Defs, its root's while unbound."""
        root, dot, _ = key.partition(".")
        found = self._member_binding(root, key) if dot else None
        self._read(node, key, self._bound(root) if found is None else found)

    def _bind_member(self, node: int, path: tuple[str, ...], value: int | None) -> None:
        """A two-segment path write: ``o.f`` has this one Def (§7.1, W8)."""
        key = f"{path[0]}.{path[1]}"
        self._put(key, frozenset((self._def(node, key, "assign", value),)))
        self._register(key)

    def _register(self, key: str) -> None:
        """A path key is a member of its root: an overwrite of the root unbinds it."""
        root, dot, _ = key.partition(".")
        if dot:
            self._members.setdefault(root, set()).add(key)

    # ── reads ──

    def _read(self, node: int, name: str, found: _Binding) -> None:
        """Record what reaches the read of ``name`` at ``node``, over every pass; a read that
        may reach no Def of its scope keeps its name and scope for R-O's resolution (the
        name and scope are the same on every pass)."""
        prior = self._reads.get(node)
        self._reads[node] = found if prior is None else _merged(prior, found)
        if _UNBOUND in found:
            self._read_at[node] = (name, self._fn)
        if self._over_cap:
            self._capped.add(node)

    def _name(self, node: int) -> None:
        name = self._m.ident(node)
        if name and is_read(self._m, node):  # W8: a property, key, declared name ... is none
            self._read(node, name, self._state.bound(name))

    def _chain_read(self, node: int) -> None:
        """A MEMBER or SUBSCRIPT: its object and index are read; the node reads its path."""
        self._children(node)
        path = self._path(node)
        if path is not None and len(path) >= _BOUND_SEGMENTS:
            self._read_path(node, path)

    def _read_path(self, node: int, path: tuple[str, ...]) -> None:
        """W8, §7.1: a read of a bound two-segment path; a longer one reads its first two
        segments and is ``depth_capped``."""
        key = f"{path[0]}.{path[1]}"
        found = self._member_binding(path[0], key)
        if found is None:
            return
        self._read(node, key, found)
        if len(path) > _BOUND_SEGMENTS:
            self._capped.add(node)

    def _member_binding(self, root: str, key: str) -> _Binding | None:
        """A path's Defs: None while it is unbound (the flow pass then reads its object); a
        path bound on some paths only — or written to before — adds its root's Defs."""
        found = self._bound(key)
        if found == _FREE:
            return None
        if _UNBOUND not in found:
            return found
        return (found - _FREE) | self._bound(root)

    def _path(self, node: int) -> _Path:
        """The dotted path a NAME, MEMBER or SUBSCRIPT reads — at most one segment past a
        bound name (§7.1) — or None (a call result, a dynamic key). Memoised per node."""
        if node < 0:
            return None
        if self._kinds[node] not in CHAINS:
            return self._root_path(node)
        if node not in self._paths:
            self._fill_paths(node)
        return self._paths[node]

    def _fill_paths(self, node: int) -> None:
        """``node``'s path and that of each unmemoised link below it (``open_links``), from
        the innermost out."""
        links, below = open_links(self._m, node, self._paths)
        path = self._path(below)
        for link in reversed(links):
            path = self._paths[link] = _extended(path, segment(self._m, link))

    def _root_path(self, node: int) -> _Path:
        name = self._m.ident(node) if self._kinds[node] == Kind.NAME else None
        return (name,) if name else None

    # ── assignment (§7.2, W6, W8, W11, R-G, R-K, C2) ──

    def _assign(self, node: int) -> None:
        if first(self._m, node, Field.PARAMS) >= 0:
            self._declarator(node)
            return
        reads = kids_outside(self._m, node, _ASSIGN_OWN)
        reads += self._target_reads(self._m.children(node, Field.LHS))
        self._later([*reads, (_Pass._bind_assign, node)])

    def _target_reads(self, targets: Iterable[int]) -> list[int]:
        """What a write reads before it binds: a path target's object and index; a target
        that binds nothing (C's ``*p = …``) whole."""
        return [part for target in targets for part in self._target_parts(target)]

    def _target_parts(self, target: int) -> Sequence[int]:
        kind = self._m.kind(target)
        if kind in CHAINS:
            return self._m.children(target)
        return () if kind in _TARGETS else (target,)

    def _bind_assign(self, node: int) -> None:
        rhs = self._m.children(node, Field.RHS)
        targets, kind = self._targets(self._m.children(node, Field.LHS), len(rhs))
        for target, value in _paired(targets, rhs):
            _TARGETS.get(self._m.kind(target), _Pass._no_target)(self, target, value, kind)

    def _targets(self, lhs: Sequence[int], values: int) -> tuple[Sequence[int], DefKind]:
        """W11: a lone DESTRUCT's own items are the targets when the RHS holds several
        values (``a, b = x, y``)."""
        if len(lhs) == 1 and values > 1 and self._m.kind(lhs[0]) is Kind.DESTRUCT:
            return self._m.children(lhs[0], Field.NONE), "destruct"
        return lhs, "assign"

    def _no_target(self, target: int, value: int | None, kind: DefKind) -> None:
        """A target that binds nothing (C's ``*p = …``; ``_target_reads`` read it)."""

    def _bind_name(self, target: int, value: int | None, kind: DefKind) -> None:
        """A NAME target; R-G: an assigned FUNCTION makes a ``function`` Def."""
        if value is not None and self._m.kind(value) is Kind.FUNCTION:
            kind = "function"
        self._bind(target, self._m.ident(target), kind, value)

    def _bind_pattern(self, target: int, value: int | None, kind: DefKind) -> None:
        """W6: every leaf binds the RHS; R-H: from a ``require``/``import`` call, each leaf
        carries its symbol."""
        imported = self._imports_from(value)
        for leaf, pair in self._leaves((target,)):
            symbol = self._symbol(leaf, pair) if imported else None
            self._bind(leaf, self._m.ident(leaf), "destruct", value, symbol)

    def _imports_from(self, value: int | None) -> bool:
        call = self._unawaited(value)
        callee = self._m.callee(call) if is_kind(self._m, call, Kind.CALL) else -1
        return callee >= 0 and self._m.ident(callee) in _IMPORT_CALLS

    def _unawaited(self, value: int | None) -> int:
        if value is None:
            return -1
        return first(self._m, value, Field.NONE) if self._m.kind(value) is Kind.AWAIT else value

    def _symbol(self, leaf: int, pair: int) -> str | None:
        """R-H: a PAIR leaf's symbol is its key's last identifier, any other leaf's its name."""
        key = first(self._m, pair, Field.KEY) if pair >= 0 else -1
        return self._last_text(key if key >= 0 else leaf)

    def _last_text(self, node: int) -> str | None:
        """The text of a compound name's last segment (W3: ``last_segment``; a name's own)."""
        return self._m.ident(last_segment(self._m, node))

    def _bind_member_target(self, target: int, value: int | None, kind: DefKind) -> None:
        self._bind_path(target, self._path(target), value)

    def _bind_subscript_target(self, target: int, value: int | None, kind: DefKind) -> None:
        """M1: ``o["k"] = e`` writes the path ``o.k``; W8: ``o[k] = e`` with any other key
        lands somewhere in ``o`` — it keeps what ``o`` held, and every bound ``o.*`` gains
        it."""
        path = self._path(target)
        if path is None:
            self._bind_dynamic(target, value)
        else:
            self._bind_path(target, path, value)

    def _bind_path(self, target: int, path: _Path, value: int | None) -> None:
        """A two-segment path binds; a deeper one is R-K's deep write and binds nothing."""
        if path is not None and len(path) == _BOUND_SEGMENTS:
            self._bind_member(target, path, value)

    def _bind_dynamic(self, target: int, value: int | None) -> None:
        base = self._path(first(self._m, target, Field.OBJECT))
        if base is not None and len(base) <= _BOUND_SEGMENTS:
            self._augment(target, ".".join(base), value)

    def _aug(self, node: int) -> None:
        targets = self._target_reads(self._m.children(node, Field.LHS))
        reads = [*self._m.children(node, Field.RHS), *targets]
        self._later([*reads, (_Pass._bind_aug, node)])

    def _bind_aug(self, node: int) -> None:
        """§7.2 AUG ``x += e``: ``x`` keeps what it held and gains ``e``."""
        value = first(self._m, node, Field.RHS)
        for target in self._m.children(node, Field.LHS):
            self._aug_target(target, value if value >= 0 else None)

    def _aug_target(self, target: int, value: int | None) -> None:
        path = self._path(target)
        if path is not None and len(path) <= _BOUND_SEGMENTS:
            self._augment(target, ".".join(path), value)
        elif self._m.kind(target) is Kind.SUBSCRIPT:
            self._bind_dynamic(target, value)

    def _declarator(self, node: int) -> None:
        """A C/C++ declaration whose declarator is a function declarator binds nothing (a
        local prototype; its parameters bind nothing, A3) — unless, C2 (R-X), it is in a C++
        function body and every parameter is a bare type naming an in-scope local or param
        Def: then it is a stack-constructor call that declares its name. A36: a synthetic
        CALL the worker shipped for a parameter list is then kept; else it is no call site."""
        holders = self._m.children(node, Field.PARAMS)
        calls = self._synthetic(holders)
        names = self._constructor_args(holders) if self._in_cpp_body() else []
        if names and all(map(self._is_local, names)):
            self._construct(node, names, calls)
        else:
            self._prototypes.update(calls)

    def _in_cpp_body(self) -> bool:
        """R-X applies in a function body of a vexing-parse language only."""
        return self._vexing and self._fn > 0

    def _constructor_args(self, holders: Sequence[int]) -> list[int]:
        """The bare type NAME of every parameter of the parameter lists ``holders`` (A36: a
        synthetic CALL's arguments), or nothing when one is not bare."""
        names = [self._bare_type(param) for param in self._declared_params(holders)]
        return names if names and min(names) >= 0 else []

    def _declared_params(self, holders: Sequence[int]) -> list[int]:
        """Each parameter list's parameters; A36: a synthetic CALL's arguments."""
        return [param for held in holders for param in self._params_held(held)]

    def _synthetic(self, holders: Sequence[int]) -> list[int]:
        """A36: the parameter lists the worker shipped as synthetic CALLs."""
        return [held for held in holders if self._m.kind(held) is Kind.CALL]

    def _params_held(self, held: int) -> Sequence[int]:
        return self._m.args(held) if self._m.kind(held) is Kind.CALL else self._m.children(held)

    def _bare_type(self, param: int) -> int:
        """A parameter that is a type name only (no declarator): that NAME; A36: one the worker
        read as a SUBSCRIPT, the type name it shipped as the OBJECT; else ``-1``."""
        if self._m.kind(param) is Kind.SUBSCRIPT:
            return first(self._m, param, Field.OBJECT)
        kids = self._m.children(param)
        if len(kids) != 1:
            return -1
        lone = kids[0]
        return lone if (self._m.field(lone), self._m.kind(lone)) == _BARE_TYPE else -1

    def _is_local(self, node: int) -> bool:
        """Some Def of this scope reaches the name (not only the enclosing ones)."""
        return not self._bound(self._m.ident(node) or "") <= _FREE

    def _construct(self, node: int, names: Sequence[int], calls: list[int]) -> None:
        """R-X: the declaration is a constructor call. A36: with synthetic ``calls``, those are
        the call sites — read as any CALL is, then declared."""
        if calls:
            self._later([*calls, (_Pass._declare_calls, (node, calls))])
            return
        for name in names:
            ident = self._m.ident(name) or ""
            self._read(name, ident, self._bound(ident))
        declared = first(self._m, node, Field.NAME)
        self._bind(declared, self._m.ident(declared), "assign", node)
        self._constructors[node] = tuple(names)

    def _declare_calls(self, synthetic: tuple[int, list[int]]) -> None:
        """A36: a declared name whose parameter list is one of the declaration's synthetic
        CALLs binds that CALL, as C3's binds its RHS (a declarator's NAME and PARAMS ship in
        pairs, in order)."""
        node, calls = synthetic
        pairs = zip(self._m.children(node, Field.NAME), self._m.children(node, Field.PARAMS))
        for declared, held in pairs:
            if held in calls:
                self._bind(declared, self._m.ident(declared), "assign", held)

    # ── branches (§7.2, D6, L10, A25) ──

    def _branch(self, frame: _Branch, arms: Iterable[Sequence[int]]) -> list[_Work]:
        """The steps of alternatives, each from the pre-state in a delta of its own, then
        their join."""
        steps: list[_Work] = []
        for arm in arms:
            steps += [(_Pass._open, frame), *arm, (_Pass._close, frame)]
        steps.append((_Pass._join, frame))
        return steps

    def _open(self, frame: _Branch) -> None:
        """One delta; past MAX_BRANCH_DEPTH none: the writes are weak, the reads capped."""
        can = self._state.depth < MAX_BRANCH_DEPTH
        frame.opened.append(can)
        if can:
            self._state.push()
        else:
            self._over.add(frame.node)
            self._over_cap += 1

    def _end(self, frame: _Branch) -> _Layer | None:
        if frame.opened.pop():
            return self._state.pop()
        self._over_cap -= 1
        return None

    def _close(self, frame: _Branch) -> None:
        layer = self._end(frame)
        if layer is not None:
            frame.alternatives.append((layer,))

    def _join(self, frame: _Branch) -> None:
        """Join the closed alternatives — the pre-state among them when the branch may run
        none (an IF without an else, the arms, a loop body) — into the state."""
        if frame.alternatives:
            pre: list[tuple[_Layer, ...]] = [()] if frame.with_pre else []
            self._state.join([*frame.alternatives, *pre])
        frame.alternatives.clear()

    def _if(self, node: int) -> None:
        """§7.2 IF: the CONSEQ and each ALT are alternatives (an elif's TEST is read first);
        without an else the pre-state is one too. A TEST-less IF (an else, a Python loop or
        try ``else``) runs as it stands."""
        conseq = list(self._m.children(node, Field.CONSEQ))
        heads = self._heads(node)
        if not self._m.children(node, Field.TEST):
            self._later(heads + conseq)
            return
        arms, tests, closed = self._alternatives(node, conseq)
        self._later([*heads, *tests, *self._branch(_Branch(node, not closed), arms)])

    def _alternatives(
        self, node: int, conseq: list[int]
    ) -> tuple[list[Sequence[int]], list[int], bool]:
        """The bodies an IF chooses between, the elif TESTs, and whether an else closes it."""
        arms: list[Sequence[int]] = [conseq]
        tests: list[int] = []
        closed = False
        for alt in self._m.children(node, Field.ALT):
            body, heads = self._alternative(alt)
            arms.append(body)
            tests += heads
            closed = closed or not heads
        return arms, tests, closed

    def _alternative(self, alt: int) -> tuple[Sequence[int], list[int]]:
        """An elif (an IF with a TEST and no ALT of its own): its CONSEQ and its TEST; an
        else (an IF without a TEST): its CONSEQ; anything else (a nested if/else, a block, a
        statement): itself. An empty TEST list means the chain is closed."""
        if self._m.kind(alt) is not Kind.IF or self._m.children(alt, Field.ALT):
            return (alt,), []
        return self._m.children(alt, Field.CONSEQ), self._heads(alt)

    def _heads(self, node: int) -> list[int]:
        """An IF's parts read before it branches: its TEST (and a Go initialiser)."""
        return kids_outside(self._m, node, _BRANCH_FIELDS)

    def _other(self, node: int) -> None:
        """An OTHER: its parts run in order; L10, A25: its BLOCK children with Field NONE are
        switch/match arms — alternatives, each from the pre-state, joined with it."""
        arms, parts = _split(self._m.children(node), self._is_arm)
        steps: list[_Work] = [*parts]
        if arms:
            steps += self._branch(_Branch(node, True), ((arm,) for arm in arms))
        self._later(steps)

    def _is_arm(self, node: int) -> bool:
        return self._m.kind(node) is Kind.BLOCK and self._m.field(node) is Field.NONE

    def _try(self, node: int) -> None:
        """§7.2 TRY: the body in a delta; each handler from the body's state in a delta over
        it; ``join(Δb, Δh…)``; then the finally."""
        body, catches, finals = self._try_parts(node)
        frame = _Branch(node, False)
        steps: list[_Work] = [(_Pass._open, frame), *body]
        for catch in catches:
            steps += [(_Pass._open, frame), (_Pass._catch, catch), (_Pass._close_handler, frame)]
        steps += [(_Pass._close_body, frame), (_Pass._join, frame)]
        self._later([*steps, *finals])

    def _try_parts(self, node: int) -> tuple[list[int], list[int], list[int]]:
        """The body (with Java's resources and Python's try ``else``), CATCHes, FINALLYs."""
        parts: dict[Kind, list[int]] = {Kind.CATCH: [], Kind.FINALLY: [], Kind.TRY: []}
        for kid in self._m.children(node):
            kind = self._m.kind(kid)
            parts[kind if kind in _HANDLERS else Kind.TRY].append(kid)
        return parts[Kind.TRY], parts[Kind.CATCH], parts[Kind.FINALLY]

    def _close_handler(self, frame: _Branch) -> None:
        layer = self._end(frame)
        if layer is not None:
            frame.handlers.append(layer)

    def _close_body(self, frame: _Branch) -> None:
        body = self._end(frame)
        if body is not None:
            frame.alternatives = [(body,), *((body, handler) for handler in frame.handlers)]

    def _catch(self, node: int) -> None:
        """A CATCH's parameter (under PARAMS or TARGET, or a PARAM child) binds ``catch``;
        the rest — the body, the exception types — runs."""
        holders, parts = _split(self._m.children(node), self._binds_catch)
        for leaf, _ in self._holders_leaves(holders):
            self._bind(leaf, self._m.ident(leaf), "catch", node)
        self._later(parts)

    def _binds_catch(self, node: int) -> bool:
        return self._m.field(node) in _CATCH_FIELDS or self._m.kind(node) is Kind.PARAM

    def _holders_leaves(self, holders: Iterable[int]) -> list[tuple[int, int]]:
        """The leaves of parameter holders: an ARGS's PARAMs, a PARAM, a bare NAME/pattern."""
        return [leaf for holder in holders for leaf in self._holder_leaves(holder)]

    def _holder_leaves(self, holder: int) -> list[tuple[int, int]]:
        if self._m.kind(holder) in _PARAM_HOLDERS:
            return [leaf for param in params_in(self._m, holder) for leaf in self._param_leaves(param)]
        return self._leaves((holder,))

    def _loop(self, node: int) -> None:
        """§7.2 LOOP: the head is read, the TARGET binds the iterable, the body runs as an
        alternative to the pre-state, twice (one extra pass: a Def at its end reaches a read
        at its start), then the tail (a Python loop ``else``).

        Inside an enclosing loop's SECOND pass the body runs once: the first pass already
        ran it twice from an entry state that differs only by Defs flowing through, and
        Defs are identities — so the reads see the same fixpoint, and a scope's nested loops
        cost O(nodes x loop depth), never 2^depth."""
        head, body, tail = self._loop_parts(node)
        once = self._loop_pass(_Branch(node, True), body)
        again = [] if self._single else [(_Pass._single_on, node), *once, (_Pass._single_off, node)]
        bind = (_Pass._bind_loop, node)
        self._later([*head, bind, *once, *again, *tail])

    def _loop_pass(self, frame: _Branch, body: Sequence[int]) -> list[_Work]:
        return [(_Pass._open, frame), *body, (_Pass._close, frame), (_Pass._join, frame)]

    def _loop_parts(self, node: int) -> tuple[list[int], list[int], list[int]]:
        """A LOOP's head (before its body; the TARGET left out), body and tail."""
        parts: tuple[list[int], list[int], list[int]] = ([], [], [])
        for kid in self._m.children(node):
            slot = _loop_slot(self._m.field(kid), bool(parts[1]))
            if slot >= 0:
                parts[slot].append(kid)
        return parts

    def _single_on(self, node: int) -> None:
        self._single += 1

    def _single_off(self, node: int) -> None:
        self._single -= 1

    def _bind_loop(self, node: int) -> None:
        self._bind_targets(node, "loop_target")

    def _with(self, node: int) -> None:
        """§7.2 WITH ``with e as x``: ``e`` is read, ``x`` binds it, then the body runs."""
        heads = kids_outside(self._m, node, _WITH_OWN)
        body = self._m.children(node, Field.BODY)
        self._later([*heads, (_Pass._bind_with, node), *body])

    def _bind_with(self, node: int) -> None:
        self._bind_targets(node, "with")

    def _bind_targets(self, node: int, kind: DefKind) -> None:
        """Every leaf under TARGET binds the node's first ITER."""
        iterable = first(self._m, node, Field.ITER)
        value = iterable if iterable >= 0 else None
        for leaf, _ in self._leaves(self._m.children(node, Field.TARGET)):
            self._bind(leaf, self._m.ident(leaf), kind, value)

    # ── global, imports, calls ──

    def _global(self, node: int) -> None:
        """A24: ``global x`` binds nothing; ``x`` is the MODULE's for the rest of the
        function, so a later write there is a MODULE Def (W13)."""
        if self._fn:
            self._globals.update(filter(None, map(self._m.ident, self._m.children(node))))

    def _import(self, node: int) -> None:
        """W6: the imported names bind (``import``); a nested IMPORT (a Go spec, a PHP
        clause) is its own."""
        kids = self._m.children(node)
        self._later(kids_of(self._m, node, Kind.IMPORT))
        names = self._imported(node, kids)
        for name in names:
            _IMPORTS[self._m.kind(name)](self, node, name)
        if not names and self._text_imports:
            self._import_text(node)

    def _imported(self, node: int, kids: Sequence[int]) -> list[int]:
        """The positional names an IMPORT binds (JS specifiers, ``from m import …``, Java);
        without any, its SOURCE names (Python ``import a.b``, Rust ``use``)."""
        sources = self._m.children(node, Field.SOURCE)
        return self._importable(kids, Field.NONE) or self._importable(sources, Field.SOURCE)

    def _importable(self, kids: Iterable[int], fld: Field) -> list[int]:
        return [kid for kid in kids if self._m.field(kid) is fld and self._m.kind(kid) in _IMPORTED]

    def _bind_import(self, imp: int, bound: int, symbol: int) -> None:
        """W6, R-H: ``bound`` binds the IMPORT ``imp``; the symbol is ``symbol``'s last
        segment's text (``_last_text``)."""
        self._bind(bound, self._m.ident(bound), "import", imp, self._last_text(symbol))

    def _import_pair(self, imp: int, pair: int) -> None:
        """W6, R-H: a PAIR binds its VALUE (the alias) — its KEY when it has none — and its
        KEY's last identifier is the symbol."""
        key = first(self._m, pair, Field.KEY)
        alias = first(self._m, pair, Field.VALUE)
        self._bind_import(imp, alias if alias >= 0 else self._bound_segment(self._m, key), key)

    def _import_member(self, imp: int, member: int) -> None:
        """A dotted name binds its first segment in Python (``import os.path`` binds
        ``os``), its last elsewhere; its last segment is the symbol (a NAME is both)."""
        self._bind_import(imp, self._bound_segment(self._m, member), member)

    def _import_text(self, imp: int) -> None:
        """A Go import spec binds its alias, else its own text (its path's last segment)."""
        alias = first(self._m, imp, Field.NAME)
        bound = alias if alias >= 0 else imp
        self._bind_import(imp, bound, bound)

    def _call(self, node: int) -> None:
        """A CALL's parts are read; then each name ``call_writes`` says it writes in place
        (R-J, R-W) keeps what it held and takes an ``aug`` Def whose value is the CALL. What
        it writes is a fact of the model alone, so it is asked here, and a CALL that writes
        nothing schedules no step."""
        written = self._call_writes(self._m, node) if self._call_writes is not None else ()
        if written:
            self._todo.append((_Pass._call_written, (node, written)))
        self._children(node)

    def _call_written(self, step: tuple[int, Iterable[int]]) -> None:
        call, written = step
        for target in written:
            name = self._m.ident(target)
            if name:
                self._augment(target, name, call)

    # ── the table ──

    def _table(self) -> ScopeTable:
        """The table over what the pass has run. ``on_demand``: the table keeps the pass (the
        pass keeps nothing of the table: no cycle outlives the build), and a later ``ensure``
        adds to the same Defs, reads, capped reads and parameter names — never a tally, a
        constructor or a prototype (``_up_front``)."""
        demand = None if self._up_front is None else self
        resolver = _Resolver(self._m, self._defs, self._reads, self._read_at, demand)
        resolver.publish(self._positions())
        tallies = {BRANCH_DEPTH: len(self._over)} if self._over else {}
        constructors = MappingProxyType(self._constructors)
        prototypes = frozenset(self._prototypes)
        params = self._param_names
        return ScopeTable(resolver, self._capped, constructors, tallies, prototypes, params)

    def _positions(self) -> Sequence[int]:
        """The Def ids in the order they take positions: document order when every scope has
        run (``build``), else the order they were made in (``on_demand``: each later scope's
        Defs follow)."""
        made = range(len(self._defs))
        return made if self._up_front is not None else sorted(made, key=self._document_key)

    def _document_key(self, index: int) -> tuple[int, str]:
        return self._defs[index][:2]  # (node, name)


# Each statement or expression kind's handler; every other kind's children run (§7.2).
STATEMENTS: Mapping[Kind, Callable[[_Pass, int], None]] = MappingProxyType({
    Kind.MODULE: _Pass._block,
    Kind.BLOCK: _Pass._block,
    Kind.IF: _Pass._if,
    Kind.LOOP: _Pass._loop,
    Kind.TRY: _Pass._try,
    Kind.CATCH: _Pass._catch,
    Kind.WITH: _Pass._with,
    Kind.OTHER: _Pass._other,
    Kind.ASSIGN: _Pass._assign,
    Kind.AUG_ASSIGN: _Pass._aug,
    Kind.FUNCTION: _Pass._function,
    Kind.IMPORT: _Pass._import,
    Kind.GLOBAL: _Pass._global,
    Kind.NAME: _Pass._name,
    Kind.MEMBER: _Pass._chain_read,
    Kind.SUBSCRIPT: _Pass._chain_read,
    Kind.CALL: _Pass._call,
    Kind.PARAM: _Pass._skip,
})
# A node's visit by its kind's int (``FileModel.kind_ids``): ``STATEMENTS``, else its children.
_VISITS: tuple[Callable[[_Pass, int], None], ...] = tuple(
    STATEMENTS.get(kind, _Pass._children) for kind in Kind
)
# How an assignment target of each kind binds (W6, W8, W11, R-K); any other is read.
_TARGETS: Mapping[Kind, Callable[[_Pass, int, int | None, DefKind], None]] = MappingProxyType({
    Kind.NAME: _Pass._bind_name,
    Kind.DESTRUCT: _Pass._bind_pattern,
    Kind.ARRAY: _Pass._bind_pattern,
    Kind.OBJECT: _Pass._bind_pattern,
    Kind.SPREAD: _Pass._bind_pattern,
    Kind.MEMBER: _Pass._bind_member_target,
    Kind.SUBSCRIPT: _Pass._bind_subscript_target,
})
# How an imported name of each kind binds (W6).
_IMPORTS: Mapping[Kind, Callable[[_Pass, int, int], None]] = MappingProxyType({
    Kind.NAME: _Pass._import_member,
    Kind.PAIR: _Pass._import_pair,
    Kind.MEMBER: _Pass._import_member,
})


class _Resolver:
    """A read's Defs (A22), resolved when first asked (``ScopeTable.resolve`` memoises them
    per node): the ones its scope's pass recorded and, when it may reach none of them, R-O's
    (W13) — every Def of its root name in each scope enclosing its function, the MODULE
    included (memoised per function and name). Only the reads a caller asks for are ever
    materialised. ``defs`` holds every Def published so far, by position (``publish``, which
    also indexes each one by its scope and name); an ``on_demand`` table's
    ``ensure`` first runs the scopes a read needs (its pass, ``demand``), then publishes what
    they made."""

    def __init__(
        self,
        model: FileModel,
        made: Sequence[_Binds],
        reads: Mapping[int, _Binding],
        read_at: Mapping[int, tuple[str, int]],
        demand: _Pass | None,
    ) -> None:
        self._model = model
        self._made = made  # the pass's Defs by id, as it makes them
        self.defs: list[Def] = []
        self._rank: list[int] = []  # each published Def's position, by its id
        self._reads = reads
        self._read_at = read_at
        self._demand = demand
        self._by_scope: dict[tuple[int, str], list[int]] = {}
        self._chains: dict[int, tuple[int, ...]] = {}
        self._free: dict[tuple[int, str], tuple[int, ...]] = {}

    def ensure(self, node: int) -> None:
        """``on_demand``: the scopes a read at ``node`` needs run, and the Defs they made are
        published; ``build`` ran every one."""
        if self._demand is not None and self._demand.ensure(node):
            self.publish(range(len(self._rank), len(self._made)))

    def publish(self, ids: Iterable[int]) -> None:
        """The Defs of ``ids``, in that order, take the next positions; each is indexed by
        scope and name (R-O)."""
        defs, rank = self.defs, self._rank
        rank.extend(repeat(0, len(self._made) - len(rank)))
        for index in ids:
            found = Def(*self._made[index], len(defs))
            rank[index] = found.position
            defs.append(found)
            self._by_scope.setdefault((found.scope, found.name), []).append(found.position)

    def resolved(self, node: int) -> tuple[Def, ...]:
        ids = self._recorded(node)
        if ids is None:
            return ()
        if _UNBOUND in ids:  # a path that may reach no Def of its own scope: R-O's too
            return self._ranked(ids, self._enclosing(*self._read_at[node]))
        if len(ids) == 1:  # one Def of the read's own scope
            return (self.defs[self._rank[next(iter(ids))]],)
        return self._ranked(ids, ())

    def _recorded(self, node: int) -> _Binding | None:
        """What the pass recorded at ``node`` (``-1`` reads nothing), its scopes run first."""
        if node < 0:
            return None
        self.ensure(node)
        return self._reads.get(node)

    def _ranked(self, ids: _Binding, enclosing: tuple[int, ...]) -> tuple[Def, ...]:
        """The Defs of the bound ``ids`` and of the ``enclosing`` positions, in document order."""
        positions = set(map(self._rank.__getitem__, ids - _FREE))
        positions.update(enclosing)
        return tuple(sorted(map(self.defs.__getitem__, positions), key=_DOCUMENT_ORDER))

    def _enclosing(self, name: str, fn: int) -> tuple[int, ...]:
        return cached(self._free, (fn, name.partition(".")[0]), self._in_scopes)

    def _in_scopes(self, key: tuple[int, str]) -> tuple[int, ...]:
        """The positions of the Defs of the name ``key[1]`` in the scopes enclosing the
        function ``key[0]``'s."""
        fn, name = key
        found = (self._by_scope.get((scope, name), ()) for scope in self._scopes(fn))
        return tuple(position for positions in found for position in positions)

    def _scopes(self, fn: int) -> tuple[int, ...]:
        """The scopes enclosing ``fn``'s, innermost first; none around the MODULE."""
        return cached(self._chains, fn, self._outward)

    def _outward(self, fn: int) -> tuple[int, ...]:
        return () if fn == 0 else (*_enclosers(self._model, fn), 0)


# ── the table (A22) ──────────────────────────────────────────────────────────


class ScopeTable:
    """One file's def-use (§7, A22), built by ``build`` and immutable after.

    ``defs`` is every Def in document order; ``resolve(node)`` the Defs reaching the read at
    ``node`` (W8's scope read; ``()`` for a node that reads nothing, or a path never bound) -
    a read is materialised as Defs only when asked, never as a ``Use`` list (A22's API is
    ``defs`` and ``resolve``); ``depth_capped(node)`` whether the read is ``unknown(depth)`` (a
    branch past MAX_BRANCH_DEPTH, or a path truncated to two segments); ``constructors`` maps
    each C++ declaration R-X confirmed as a stack-constructor call (C2) to its arguments, the
    bare type NAMEs of its parameters; ``prototypes`` the synthetic CALLs R-X did not keep
    (A36): local prototypes, no call site; ``tallies`` the per-file
    cap counts (``branch_depth``) the flow analysis carries (A28 (3)); ``param_names(param)``
    the names a PARAM binds (W7, A26).

    An ``on_demand`` table answers every one of these as ``build``'s does; its ``defs`` are
    the Defs of the scopes run so far, each at its ``position``."""

    __slots__ = (
        "_capped", "_ensure", "_params", "_reads", "_resolved", "constructors", "defs",
        "prototypes", "tallies",
    )

    def __init__(
        self,
        resolver: _Resolver,
        capped: Container[int],
        constructors: Mapping[int, tuple[int, ...]],
        tallies: Mapping[str, int],
        prototypes: frozenset[int],
        params: Mapping[int, tuple[str, ...]],
    ) -> None:
        self.defs: Sequence[Def] = resolver.defs
        self.constructors = constructors
        self.prototypes = prototypes
        self.tallies: Mapping[str, int] = MappingProxyType(dict(tallies))
        self._resolved = resolver.resolved  # bound once: ``resolve`` is the hottest read
        self._reads: dict[int, tuple[Def, ...]] = {}  # each read's Defs, once resolved
        self._capped = capped
        self._ensure = resolver.ensure
        self._params = params  # the pass's own: an on-demand table's grows as its scopes run

    @classmethod
    def build(
        cls,
        model: FileModel,
        *,
        state_factory: StateFactory = dict,
        call_writes: CallWrites | None = None,
    ) -> ScopeTable:
        """The scope pass over ``model`` (§7.2). ``state_factory`` builds every State dict —
        the base of each scope and each delta — and nothing else; ``call_writes`` (the flow
        pass's R-J and R-W) names the NAMEs a CALL writes in place."""
        return _Pass(model, state_factory, call_writes).run()

    @classmethod
    def on_demand(cls, model: FileModel, *, call_writes: CallWrites | None = None) -> ScopeTable:
        """``build``'s table with each function scope run when first needed (module
        docstring, ``_up_front``): what the flow pass reads (§8.7)."""
        return _Pass(model, dict, call_writes, _up_front(model)).run()

    def resolve(self, node: int) -> tuple[Def, ...]:
        """The Defs reaching the read at ``node``, in document order (A22), memoised (the
        flow pass's hottest read: ``cached`` inlined, no answer is None)."""
        found = self._reads.get(node)
        return found if found is not None else cached(self._reads, node, self._resolved)

    def depth_capped(self, node: int) -> bool:
        """The read at ``node`` is ``unknown(depth)`` (§7.1, §7.2, §8.7); a read resolved
        already has had its scopes run."""
        if node not in self._reads:
            self._ensure(node)
        return node in self._capped

    def param_names(self, param: int) -> tuple[str, ...]:
        """The names the PARAM ``param`` binds (W7, A26: several for a pattern), in document
        order; none for a node that is no bound parameter."""
        self._ensure(param)
        return self._params.get(param, ())


def _up_front(model: FileModel) -> frozenset[int]:
    """The functions ``on_demand`` runs before any question: each whose pass can leave a fact
    outside its own scope (a row of ``_UP_FRONT``), and each enclosing one (a pass meets a
    function only while its encloser's runs)."""
    held = (_holding(model, select(model), floor) for select, floor in _UP_FRONT)
    return frozenset(chain.from_iterable(held))


def _branches(model: FileModel) -> list[int]:
    """Every ``_BRANCHING`` node: a branch past ``MAX_BRANCH_DEPTH`` needs that many above it or
    at it in one scope's pass, which visits only nodes of its function's subtree."""
    return [*chain.from_iterable(map(model.nodes, _BRANCHING))]


def _global_statements(model: FileModel) -> Sequence[int]:
    return model.nodes(Kind.GLOBAL)


def _declarations(model: FileModel) -> list[int]:
    """C2, A36: a vexing-parse profile's declarations whose declarator is a function
    declarator — an ASSIGN with PARAMS, what ``_assign`` hands ``_declarator``, the one writer
    of R-X's constructors and prototypes; none elsewhere (C ships no synthetic CALL, and R-X
    is C++'s)."""
    if not PROFILES[model.language].scope_rules.vexing_parse:
        return []
    return [node for node in model.nodes(Kind.ASSIGN) if first(model, node, Field.PARAMS) >= 0]


# What puts a function up front (``_up_front``): at least ``floor`` of the nodes ``select``
# picks in its subtree, nested functions' included. A branch past the cap (``tallies``, per
# file, A28 (3)); a ``global`` write (a MODULE Def, A24); an R-X declaration (``Calls`` reads
# the constructors and prototypes up front, C2, A36).
_UP_FRONT: tuple[tuple[Callable[[FileModel], Sequence[int]], int], ...] = (
    (_branches, MAX_BRANCH_DEPTH),
    (_global_statements, 1),
    (_declarations, 1),
)


def _holding(model: FileModel, nodes: Sequence[int], floor: int) -> list[int]:
    """The functions holding ``floor`` or more of ``nodes``, nested functions' counted (so each
    encloser is one too)."""
    if len(nodes) < floor:  # no function holds more than the whole file
        return []
    counts = _subtree_counts(model, nodes)
    return [fn for fn, count in counts.items() if count >= floor]


def _subtree_counts(model: FileModel, nodes: Iterable[int]) -> Counter[int]:
    """Each function's ``nodes`` with its nested functions' — one count per node, then each
    function's total added to its encloser's — the MODULE's own (``-1``) left out."""
    held = Counter(map(model.function_of, nodes))
    for fn in reversed(model.functions()):  # document order reversed: inner ones first
        held[model.function_of(fn)] += held[fn]
    del held[-1]  # a Counter's del of a missing key is no error
    return held


# ── decorators (W7, A22) ─────────────────────────────────────────────────────


def decorators(model: FileModel, fn: int) -> tuple[int, ...]:
    """W7: ``fn``'s DECORATOR children and the run of DECORATORs right before it among its
    siblings (Python's ``decorated_definition`` is transparent, W1), in document order —
    never one a statement separates from it, never a nested DECORATOR, never its class's; none
    in a file with no DECORATOR at all (one probe of the kind index)."""
    if not model.nodes(Kind.DECORATOR):
        return ()
    return tuple(sorted((*_preceding_decorators(model, fn), *kids_of(model, fn, Kind.DECORATOR))))


def _preceding_decorators(model: FileModel, fn: int) -> list[int]:
    parent = model.parent(fn)
    siblings = model.children(parent) if parent >= 0 else ()
    k = bisect_right(siblings, fn) - 1
    run: list[int] = []
    while k > 0 and model.kind(siblings[k - 1]) is Kind.DECORATOR:
        k -= 1
        run.append(siblings[k])
    return run
