"""Parameters and source calls as the flow pass reads them (feature 0102, LLD §8.2 PARAM row,
§8.4 R-A ... R-E, R-T, R-U; W4, W7, W9, C4/A23, A28 (1), A47 D23-d).

A parameter's BASE origins — the ones it has when its function is analysed on its own, not
under a summary binding (§8.4) — come from the structural rules, each one O(1) set probes:

* a request word in its name (``SOURCE_WORDS["request"]``; R-E for a destructured leaf);
* R-A: a callback registered through ``HANDLER_REGISTRATION_WORDS`` — a parameter hitting
  ``CALLBACK_PAYLOAD_WORDS`` is ``external(network)`` and nothing else (R-A wins, A28 (1));
* R-C: a route handler (registered, route-decorated, or whose first non-receiver parameter is
  request-named) makes every parameter outside ``RESPONSE_WORDS`` ``external(request)``;
* R-D: decorator and default-call words against ``PARAM_ANNOTATION_WORDS``, type-annotation
  words against ``TYPE_ANNOTATION_WORDS`` (W4) — ``external(upload)`` for an upload word;
* R-T: a ``PARAM_HINTS`` combination of its words — ``external(param_hint)`` (D23) — for a
  parameter of an ENTRY function of the file only (A47 D23-d, ``_Entries``: in JavaScript /
  TypeScript an exported one, in every language a public top-level one no same-file call
  site resolves to), with no server-context condition;
* C4 (a flow fact, A23): ``main``'s second parameter in C/C++ — ``external(argv)``.

R-B (an iteration callback's element parameter takes its receiver's origins) needs an origin,
so ``_origins`` evaluates the receiver ``iteration_receiver`` names. ``source_role`` is the
model-only half of L6: R-U's accessor on a request-ish receiver parameter (tested first, W9),
then a reading function by its glued key (``SOURCE_CALL_KEYS``, W9 (a)).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from itertools import chain
from typing import TYPE_CHECKING

from shared.ast._nodes import (
    cached,
    chain_root,
    first,
    is_kind,
    methods_of,
    named,
    pair_part,
    params_in,
    preorder,
    segment,
    top_statement,
)
from shared.ast._records import Origins, external, only
from shared.ast.kinds import Field, Kind
from shared.ast.profile import PROFILES
from shared.ast.roles import (
    ACCESSOR_RECEIVER_WORDS,
    ACCESSOR_WORDS,
    ACCUMULATOR_KEYS,
    CALLBACK_PAYLOAD_WORDS,
    CONTAINER_WORDS,
    HANDLER_REGISTRATION_WORDS,
    ITERATION_WORDS,
    NAMED_REQUEST_WORDS,
    NAMED_TYPE_WORDS,
    NO_WORDS,
    PARAM_ANNOTATION_WORDS,
    PARAM_HINTS,
    RECEIVER_PARAM_WORDS,
    RESPONSE_OBJECT_WORDS,
    RESPONSE_WORDS,
    ROUTE_WORDS,
    SOURCE_CALL_KEYS,
    UPLOAD_WORDS,
    chain_names,
    glue,
    hits,
    identifier_text,
    last_identifier,
    named_by,
    word_set,
)
from shared.ast.roles._words import invert
from shared.ast.scope import decorators

if TYPE_CHECKING:
    from shared.ast._calls import Calls
    from shared.ast.model import FileModel
    from shared.ast.scope import Def, ScopeTable

__all__ = ["Params"]

# A44 (1) (b): ``name`` names a request on its own - a word, or its glued form, of the request
# words that are no container word (``req``, ``request``, ``searchParams``); a CONTAINER_WORDS
# word does so only in handler context (``Params.request_named``), and a container TYPE word
# from a qualified type path (``Params._qualified_container``) or in handler context.
_names_request = partial(named_by, lexicon=NAMED_REQUEST_WORDS)
# R-T: each word's PARAM_HINTS combinations, so a name's words probe only the hints they could
# complete (no combination is empty: each holds a word of any name it is a subset of).
_HINTS_OF_WORD = invert({hint: hint for hint in PARAM_HINTS})


def _hint_named(name: str) -> bool:
    """R-T: ``name``'s words complete a PARAM_HINTS combination."""
    found = word_set((name,))
    return any(hint <= found for word in found for hint in _HINTS_OF_WORD.get(word, ()))


@dataclass(frozen=True, slots=True)
class _Handler:
    """What a FUNCTION's shape makes of its parameters (§8.4): R-A's registration, R-C's
    route, and R-B's iteration call with the position of the parameter taking the element."""

    registered: bool = False
    route: bool = False
    iteration: int = -1
    element: int = 0


_PLAIN = _Handler()
_ROUTE = _Handler(route=True)
_UNANNOTATED = (NO_WORDS, NO_WORDS)
_NO_NAMES: tuple[str, ...] = ()


@dataclass(slots=True)
class _Facts:
    """One memo per parameter fact, each keyed by the FUNCTION or PARAM it is about (§8.7)."""

    positional: dict[int, tuple[int, ...]] = field(default_factory=dict)
    slots: dict[int, tuple[int, ...]] = field(default_factory=dict)
    handler: dict[int, _Handler] = field(default_factory=dict)
    context: dict[int, bool] = field(default_factory=dict)  # A44 (1) (b): handler context
    annotations: dict[int, tuple[frozenset[str], frozenset[str]]] = field(default_factory=dict)


class Params:
    """One file's parameter facts, memoised per Def and per FUNCTION."""

    def __init__(self, model: FileModel, scope: ScopeTable, calls: Calls) -> None:
        self._m = model
        self._scope = scope
        self._calls = calls
        self._facts = _Facts()
        profile = PROFILES[model.language]  # a model is of a validated language
        self._main = profile.main_argv  # C4
        self._receiver_list = profile.receiver_list  # A3 (Go)
        self._entries: frozenset[int] | None = None  # A47 D23-d: built on first use

    # ── a function's parameters ──

    def positional(self, fn: int) -> tuple[int, ...]:
        """``fn``'s PARAM nodes in order, from the ARGS under Field PARAMS (A3) — a Go method's
        receiver list left out — each a bare-NAME parameter itself (``x => ...``)."""
        return cached(self._facts.positional, fn, self._param_nodes)

    def _param_nodes(self, fn: int) -> tuple[int, ...]:
        return tuple(param for holder in self._holders(fn) for param in params_in(self._m, holder))

    def _holders(self, fn: int) -> Sequence[int]:
        """What ``fn`` holds under Field PARAMS, a Go method's receiver list left out (A3)."""
        holders = self._m.children(fn, Field.PARAMS)
        return holders[1:] if self._receiver_list and len(holders) > 1 else holders

    def slots(self, fn: int) -> tuple[int, ...]:
        """``fn``'s positional slots, memoised: its parameters without a leading receiver
        (R-C's ``self`` / ``cls``), the ones a call's arguments bind (§8.4)."""
        return cached(self._facts.slots, fn, self._slots)

    def _slots(self, fn: int) -> tuple[int, ...]:
        return self.positional(fn)[self.receivers(fn) :]

    def receivers(self, fn: int) -> int:
        """How many leading parameters are receivers (Python ``self`` / ``cls``): 0 or 1."""
        leading = self._leading_names(self.positional(fn))
        return int(bool(leading) and leading[0] in RECEIVER_PARAM_WORDS)

    def _leading_names(self, params: Sequence[int]) -> tuple[str, ...]:
        """The names the first of ``params`` binds (W7, A26: the scope table's ``param_names``,
        in document order); none without a parameter."""
        return self._scope.param_names(params[0]) if params else _NO_NAMES

    # ── the shape of a function (R-A, R-B, R-C) ──

    def handler(self, fn: int) -> _Handler:
        """R-A / R-B / R-C of ``fn``, memoised."""
        return cached(self._facts.handler, fn, self._shape)

    def _shape(self, fn: int) -> _Handler:
        call = self._enclosing_call(fn)
        key = self._call_key(call)
        if key in HANDLER_REGISTRATION_WORDS:
            return _Handler(registered=True, route=True)
        if key in ITERATION_WORDS:
            return _Handler(iteration=call, element=int(key in ACCUMULATOR_KEYS))
        return _ROUTE if self._routed(fn) else _PLAIN

    def _call_key(self, call: int) -> str:
        """``call``'s glued key; ``""`` for none (``-1``)."""
        return self._calls.key(call) if call >= 0 else ""

    def _enclosing_call(self, fn: int) -> int:
        """The CALL ``fn`` is a positional argument of, else ``-1``."""
        holder = self._m.parent(fn)
        call = self._m.parent(holder) if holder >= 0 else -1
        if not is_kind(self._m, call, Kind.CALL):
            return -1
        return call if fn in self._calls.args(call) else -1

    def _routed(self, fn: int) -> bool:
        """R-C: a route-word decorator, or a first non-receiver parameter named a request by a
        word that is no container word (A44 (1) (b): a leading ``params`` routes nothing)."""
        decorated = (n for d in decorators(self._m, fn) for n in self._decorator_names(d))
        return hits(decorated, ROUTE_WORDS) or any(map(_names_request, self._leading_names(self.slots(fn))))

    def _decorator_names(self, decorator: int) -> list[str]:
        return [n for kid in self._m.children(decorator) for n in chain_names(self._m, kid)]

    # ── base origins of a parameter Def ──

    def origins(self, d: Def) -> Origins:
        """The base origins the structural rules give the parameter Def ``d`` (empty when none
        applies: the caller then answers R-B's receiver, else ``unknown(param)``)."""
        handler = self.handler(d.scope)
        if handler.registered and hits((d.name,), CALLBACK_PAYLOAD_WORDS):
            return only("network")  # R-A wins (A28 (1))
        roles = (*self._named(d, handler), *self._annotated(d), *self._hinted(d), *self._argv(d))
        return frozenset(external(role) for role in roles)

    def _named(self, d: Def, handler: _Handler) -> Iterator[str]:
        """A request-named parameter (R-E for a pattern leaf; ``request_named``); R-C's route
        parameters."""
        if self.request_named(d):
            yield "request"
        if handler.route and not hits((d.name,), RESPONSE_WORDS):
            yield "request"

    def request_named(self, d: Def) -> bool:
        """A44 (1) (b): ``d``'s name names a request — by a word that is no container word (or
        its glued form: ``searchParams``), or by a ``CONTAINER_WORDS`` word in a function in
        handler context (``_in_handler``)."""
        if _names_request(d.name):
            return True
        return hits((d.name,), CONTAINER_WORDS) and self._in_context(d.scope)

    def _in_context(self, fn: int) -> bool:
        """``_in_handler`` of ``fn``, memoised per function."""
        return cached(self._facts.context, fn, self._in_handler)

    def _in_handler(self, fn: int) -> bool:
        """A44 (1) (b): R-A's registration or R-C's route (``handler``), a function named by a
        ``ROUTE_WORDS`` word whole (``export function GET``), or a response-object parameter
        beside it (``({ params }, res, next) => ...``)."""
        if self.handler(fn).route or glue(named(self._m, fn)) in ROUTE_WORDS:
            return True
        return hits(self._param_names(fn), RESPONSE_OBJECT_WORDS)

    def _param_names(self, fn: int) -> Iterator[str]:
        """The names ``fn``'s parameters bind (W7, A26), in order."""
        return chain.from_iterable(map(self._scope.param_names, self.positional(fn)))

    def _annotated(self, d: Def) -> Iterator[str]:
        """R-D (W4): decorator / default-call words, then type words (``_typed_request``)."""
        marks, types = self.annotation_words(d.value)
        if marks & PARAM_ANNOTATION_WORDS or self._typed_request(d, types):
            yield "upload" if (marks | types) & UPLOAD_WORDS else "request"

    def _typed_request(self, d: Def, types: frozenset[str]) -> bool:
        """W4's type words name a request (A44 (1) (b)): a ``TYPE_ANNOTATION_WORDS`` word that is
        no container word; a container word of a qualified type path, an extractor type
        (``web::Query<T>``); a container word of a bare name — an unqualified type, or in
        TypeScript an inline object type's member name (``opts: { payload: string }``) — only
        in handler context. A decorator or default-call mark needs no context."""
        if types & NAMED_TYPE_WORDS:
            return True
        if types.isdisjoint(CONTAINER_WORDS):
            return False
        return self._qualified_container(d.value) or self._in_context(d.scope)

    def _qualified_container(self, param: int | None) -> bool:
        """A MEMBER type annotation of ``param`` (a qualified type path) holds a container word."""
        kids = self._m.children(param) if param is not None else ()
        paths = filter(self._is_type_path, kids)
        return hits(chain.from_iterable(map(self._names_under, paths)), CONTAINER_WORDS)

    def _is_type_path(self, node: int) -> bool:
        return self._m.kind(node) is Kind.MEMBER and self._is_type(node)

    def _hinted(self, d: Def) -> Iterator[str]:
        """R-T (D23): a PARAM_HINTS combination of the name's words, for a parameter of an
        ENTRY function of the file only (A47 D23-d, ``entries``); elsewhere the hint yields
        nothing, so the parameter is ``unknown(param)`` (or R-B's receiver)."""
        if _hint_named(d.name) and d.scope in self.entries():
            yield "param_hint"

    def entries(self) -> frozenset[int]:
        """A47 D23-d: the file's ENTRY functions (``_Entries``), read once per file, on the
        first hinted parameter's ask (a None sentinel, as ``Calls.reaching_sinks``)."""
        if self._entries is None:
            self._entries = _Entries(self._m, self._scope, self._calls).read()
        return self._entries

    def _argv(self, d: Def) -> Iterator[str]:
        """C4: the entry function's argv PARAM, by position (P6)."""
        if self._main is not None and self._is_argv(d, *self._main):
            yield "argv"

    def _is_argv(self, d: Def, name: str, position: int) -> bool:
        held = self.positional(d.scope)[position : position + 1]
        return held == (d.value,) and named(self._m, d.scope) == name

    def annotation_words(self, param: int | None) -> tuple[frozenset[str], frozenset[str]]:
        """A PARAM's words, memoised: (decorator and default-call words, type words)."""
        if param is None or self._m.kind(param) is not Kind.PARAM:
            return _UNANNOTATED
        return cached(self._facts.annotations, param, self._read_annotations)

    def _read_annotations(self, param: int) -> tuple[frozenset[str], frozenset[str]]:
        kids = self._m.children(param)  # a mark is a DECORATOR or CALL, a type a NAME or MEMBER
        if not kids:
            return _UNANNOTATED  # a bare identifier: no word of either
        marks, types = self._names_where(kids, self._is_mark), self._names_where(kids, self._is_type)
        return word_set(marks), word_set(types)

    def _names_where(self, kids: Sequence[int], test: Callable[[int], bool]) -> list[str]:
        """The NAME identifiers under each of ``kids`` that ``test`` holds for, in order."""
        return [name for kid in kids if test(kid) for name in self._names_under(kid)]

    def _is_mark(self, node: int) -> bool:
        """A decorator, or a default-value CALL (R-D)."""
        kind = self._m.kind(node)
        return kind is Kind.DECORATOR or (kind is Kind.CALL and self._m.field(node) is Field.VALUE)

    def _is_type(self, node: int) -> bool:
        return self._m.field(node) is Field.ANNOTATION and self._m.kind(node) in (Kind.NAME, Kind.MEMBER)

    def _names_under(self, node: int) -> list[str]:
        """The NAME identifiers of a small annotation subtree (at most MAX_TEST_NODES nodes)."""
        return [name for current in preorder(self._m, node) for name in self._symbolised(current)]

    def _symbolised(self, node: int) -> Sequence[str]:
        """A NAME's text and, when it is an import binding, its symbol (R-H: ``File(...)``)."""
        if self._m.kind(node) is not Kind.NAME:
            return ()
        text = self._m.ident(node) or ""
        symbol = self._calls.symbol_of(node)
        return (text, symbol) if symbol else (text,)

    # ── R-B, R-U ──

    def iteration_receiver(self, d: Def) -> int:
        """R-B: the receiver whose origins the element PARAM of an iteration callback takes
        (PARAM 0; PARAM 1 for an accumulator such as ``reduce``), else ``-1``."""
        handler = self.handler(d.scope)
        params = self.positional(d.scope)
        element = params[handler.element] if handler.element < len(params) else -1
        if handler.iteration < 0 or element != d.value:
            return -1
        return self._calls.receiver(handler.iteration)

    def source_role(self, call: int) -> str | None:
        """L6's model-only source reads: R-U's accessor (``request``, tested first, W9), else
        a reading function by its glued key (``SOURCE_CALL_KEYS``)."""
        key = self._calls.key(call)
        if key in ACCESSOR_WORDS and self._accessor(call):
            return "request"
        return SOURCE_CALL_KEYS.get(key)

    def _accessor(self, call: int) -> bool:
        """R-U: the receiver resolves — itself or as a MEMBER chain's root (W9 (d)) — to a
        request-named parameter, one whose annotation words meet ``ACCESSOR_RECEIVER_WORDS``,
        or one of an R-C handler."""
        _, root = chain_root(self._m, self._calls.receiver(call))
        found = self._scope.resolve(root) if root >= 0 else ()
        return any(self._accessor_param(d) for d in found if d.kind == "param")

    def _accessor_param(self, d: Def) -> bool:
        marks, types = self.annotation_words(d.value)
        receiving = not (marks | types).isdisjoint(ACCESSOR_RECEIVER_WORDS)
        return receiving or self.request_named(d) or self.handler(d.scope).route


# ── A47 D23-d: the ENTRY functions of a file ─────────────────────────────────


class _Entries:
    """One file's ENTRY functions (A47 D23-d), read once: ``Params.entries`` keeps the set.

    An entry is a function an outside caller can reach: where the language exports
    (``LanguageProfile.export_chains``: JavaScript / TypeScript) an EXPORTED one
    (``_exported``), and in every language a PUBLIC top-level named one
    (``LanguageProfile.public_name``; ``function_of == -1``, so a method of a top-level class
    too) that no same-file call site resolves to (``_uncalled``). One pass over the file's
    functions, its EXPORT nodes and its ASSIGNs, and one read of the local-call edges
    (``Calls.called``, memoised there); an exported name reads its Defs and the top-level
    classes of its name, indexed once."""

    def __init__(self, model: FileModel, scope: ScopeTable, calls: Calls) -> None:
        self._m = model
        self._scope = scope
        self._calls = calls
        self._profile = PROFILES[model.language]  # a model is of a validated language
        self._classes: dict[str, list[int]] | None = None  # built on first use

    def read(self) -> frozenset[int]:
        return frozenset(chain(self._exported(), self._uncalled()))

    # ── public, top-level and uncalled (every language) ──

    def _uncalled(self) -> Iterator[int]:
        """The public top-level named FUNCTIONs that no ``Calls.local`` call site reaches
        (``Calls.called``); a reference (``items.forEach(f)``) is no call site."""
        called = self._calls.called()
        return (fn for fn in self._m.functions() if fn not in called and self._public(fn))

    def _public(self, fn: int) -> bool:
        """``fn`` is top-level and its declared name is public (``public_name``; an anonymous
        one has none)."""
        return self._top(fn) and self._profile.public_name(self._declared_name(fn))

    def _top(self, node: int) -> bool:
        """``node`` is in no FUNCTION (module level)."""
        return self._m.function_of(node) == -1

    def _declared_name(self, fn: int) -> str:
        """``fn``'s declared name: its NAME's last identifier (W3), so a C++ out-of-line method
        (``Store::readEntry``) is named as the same method defined in its class."""
        return identifier_text(self._m, last_identifier(self._m, first(self._m, fn, Field.NAME)))

    # ── exported (JavaScript / TypeScript) ──

    def _exported(self) -> Iterator[int]:
        """The top-level functions an ``export`` statement holds (``_held``), and the ones each
        value an ``export`` lists (``export { f }``, ``export default f``) or a CommonJS export
        assigns names (``_value_fns``)."""
        if not self._profile.export_chains:
            return iter(())
        listed = chain.from_iterable(map(self._m.children, self._m.nodes(Kind.EXPORT)))
        values = chain(listed, self._commonjs_values())
        held = filter(self._held, self._m.functions())
        return chain(held, chain.from_iterable(map(self._value_fns, values)))

    def _held(self, fn: int) -> bool:
        """``fn`` is top-level and its module-level statement is an ``export`` (``export
        function``, ``export default function``, ``export const f = () => ...``, an ``export
        class``'s methods)."""
        return self._top(fn) and is_kind(self._m, top_statement(self._m, fn), Kind.EXPORT)

    def _commonjs_values(self) -> Iterator[int]:
        """The value of each top-level ASSIGN to ``exports.x`` or ``module.exports[.x]``."""
        assigns = filter(self._commonjs, self._m.nodes(Kind.ASSIGN))
        return chain.from_iterable(self._m.children(a, Field.RHS) for a in assigns)

    def _commonjs(self, assign: int) -> bool:
        """A top-level ASSIGN whose target is a chain from CommonJS's export object: its root,
        or its root and next segment, is one of the profile's ``export_chains``."""
        if not self._top(assign):
            return False
        links, root = chain_root(self._m, first(self._m, assign, Field.LHS))
        head = (self._m.ident(root), segment(self._m, links[-1])) if links else ()
        return not self._profile.export_chains.isdisjoint((head[:1], head))

    def _value_fns(self, value: int) -> Iterable[int]:
        """The FUNCTIONs an exported value names (``_named_fns``); for an OBJECT, the ones its
        members name — one level, no deeper (``{ read }``, ``{ read: readEntry }``, a method)."""
        if not is_kind(self._m, value, Kind.OBJECT):
            return self._named_fns(value)
        members = map(self._member_value, self._m.children(value))
        return chain.from_iterable(map(self._named_fns, members))

    def _member_value(self, member: int) -> int:
        """An OBJECT member's value: a PAIR's VALUE, else the member itself."""
        return pair_part(self._m, member, Field.VALUE)

    def _named_fns(self, value: int) -> Iterable[int]:
        """A FUNCTION itself, a CLASS's methods, a NAME's bound function or class
        (``_bound``)."""
        if is_kind(self._m, value, Kind.NAME):
            return chain.from_iterable(map(self._fns_of, self._bound(value)))
        return self._fns_of(value)

    def _bound(self, name: int) -> list[int]:
        """What the NAME ``name`` binds: its Defs' values, then the file's top-level CLASS
        declarations of its name (A47 (5)(a), (6)(b): a class declaration makes no scope Def,
        and none is added; a Def holding no function or class, ``X = register(X)``, does not
        hide the class declared as ``X``)."""
        defs = self._scope.resolve(name)
        declared = self._declared().get(self._m.ident(name) or "", ())
        return [*(d.value for d in defs if d.value is not None), *declared]

    def _fns_of(self, value: int) -> Sequence[int]:
        """A FUNCTION itself, a CLASS's methods, else none."""
        if is_kind(self._m, value, Kind.CLASS):
            return methods_of(self._m, value)
        return (value,) if is_kind(self._m, value, Kind.FUNCTION) else ()

    def _declared(self) -> Mapping[str, list[int]]:
        """The file's top-level CLASSes by declared name, indexed on first use."""
        if self._classes is None:
            self._classes = self._top_classes()
        return self._classes

    def _top_classes(self) -> dict[str, list[int]]:
        """Each named top-level CLASS (``function_of == -1``) under its name, in order."""
        found: dict[str, list[int]] = {}
        for cls in filter(self._top, self._m.nodes(Kind.CLASS)):
            found.setdefault(named(self._m, cls), []).append(cls)
        found.pop("", None)  # an anonymous class expression declares no name
        return found
