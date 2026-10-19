"""Parameters and source calls as the flow pass reads them (feature 0102, LLD §8.2 PARAM row,
§8.4 R-A ... R-E, R-T, R-U; W4, W7, W9, C4/A23, A28 (1)).

A parameter's BASE origins — the ones it has when its function is analysed on its own, not
under a summary binding (§8.4) — come from the structural rules, each one O(1) set probes:

* a request word in its name (``SOURCE_WORDS["request"]``; R-E for a destructured leaf);
* R-A: a callback registered through ``HANDLER_REGISTRATION_WORDS`` — a parameter hitting
  ``CALLBACK_PAYLOAD_WORDS`` is ``external(network)`` and nothing else (R-A wins, A28 (1));
* R-C: a route handler (registered, route-decorated, or whose first non-receiver parameter is
  request-named) makes every parameter outside ``RESPONSE_WORDS`` ``external(request)``;
* R-D: decorator and default-call words against ``PARAM_ANNOTATION_WORDS``, type-annotation
  words against ``TYPE_ANNOTATION_WORDS`` (W4) — ``external(upload)`` for an upload word;
* R-T: a ``PARAM_HINTS`` combination of its words — ``external(param_hint)`` (D23);
* C4 (a flow fact, A23): ``main``'s second parameter in C/C++ — ``external(argv)``.

R-B (an iteration callback's element parameter takes its receiver's origins) needs an origin,
so ``_origins`` evaluates the receiver ``iteration_receiver`` names. ``source_role`` is the
model-only half of L6: R-U's accessor on a request-ish receiver parameter (tested first, W9),
then a reading function by its glued key (``SOURCE_CALL_KEYS``, W9 (a)).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from itertools import chain
from typing import TYPE_CHECKING

from shared.ast._nodes import cached, chain_root, is_kind, named, params_in, preorder
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
    NO_WORDS,
    PARAM_ANNOTATION_WORDS,
    PARAM_HINTS,
    RECEIVER_PARAM_WORDS,
    RESPONSE_OBJECT_WORDS,
    RESPONSE_WORDS,
    ROUTE_WORDS,
    SOURCE_CALL_KEYS,
    SOURCE_WORDS,
    TYPE_ANNOTATION_WORDS,
    UPLOAD_WORDS,
    chain_names,
    glue,
    hits,
    word_set,
)
from shared.ast.roles._words import invert
from shared.ast.scope import decorators

if TYPE_CHECKING:
    from shared.ast._calls import Calls
    from shared.ast.model import FileModel
    from shared.ast.scope import Def, ScopeTable

__all__ = ["Params"]

_REQUEST = SOURCE_WORDS["request"]
# A44 (1) (b): the request words that name a request on their own; a CONTAINER_WORDS word does
# so only in handler context (``Params.request_named``).
_NAMED_REQUEST = _REQUEST - CONTAINER_WORDS
# R-T: each word's PARAM_HINTS combinations, so a name's words probe only the hints they could
# complete (no combination is empty: each holds a word of any name it is a subset of).
_HINTS_OF_WORD = invert({hint: hint for hint in PARAM_HINTS})


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
        return hits((d.name,), CONTAINER_WORDS) and cached(self._facts.context, d.scope, self._in_handler)

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
        """R-D (W4): decorator / default-call words, then type words."""
        marks, types = self.annotation_words(d.value)
        if marks & PARAM_ANNOTATION_WORDS or types & TYPE_ANNOTATION_WORDS:
            yield "upload" if (marks | types) & UPLOAD_WORDS else "request"

    def _hinted(self, d: Def) -> Iterator[str]:
        """R-T (D23): a PARAM_HINTS combination of the name's words."""
        found = word_set((d.name,))
        if any(hint <= found for word in found for hint in _HINTS_OF_WORD.get(word, ())):
            yield "param_hint"

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


def _names_request(name: str) -> bool:
    """A44 (1) (b): ``name`` names a request on its own — a word, or its glued form, of the
    request words that are no container word (``req``, ``request``, ``searchParams``)."""
    return hits((name,), _NAMED_REQUEST) or glue(name) in _NAMED_REQUEST
