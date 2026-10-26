"""Call sites as the flow pass reads them (feature 0102, LLD §8.2, §8.4, §8.5; L1-L3, L7-L9, W3,
W5, W6, W10, W11, W14, W15 (a), R5, R7, R9, R10, C2/R-X).

A call site is a CALL, or a C++ declaration the scope pass confirmed as a stack-constructor
call (R-X, ``ScopeTable.constructors``): its callee is the declared type and its arguments the
bare type names. A synthetic CALL the scope pass left a local prototype (A36,
``ScopeTable.prototypes``) is none. ``Calls`` answers, per site and memoised, the MODEL-ONLY facts the flow pass
needs — never an origin, so every answer is the same in every summary context:

* the callee's last identifier and its glued key (L1 (a)), keyed by the imported SYMBOL when
  the callee NAME is an import binding (R-H, W6); the builtin a PAIR key or a single key names
  (W5: pair first, then single — two O(1) probes);
* the local FUNCTION a callee resolves to (a bound NAME, R-G, or ``this.m``/``self.m``, R-F):
  a local def wins over every lexicon (§8.4);
* the sink arguments of each family (§8.5): the builtin positions (L9, P4, W5 ``when``), the
  path defaults (R10's two-path keys, W14's one-argument writes), the request union (W10, L8,
  R-V) and the command program position with R-M's interpreter + flag (L3, W15 (a), L7);
* the command parameter heuristic's three facts of a command sink argument (D25, A42 (1),
  A43 (1)), read off the same command row: whether the sink shells it (``shell_arg``), whether
  it is built (``built``) and whether it is the whole command of a profile builtin
  (``builtin_program``).

The source half of L6 (R-U, ``SOURCE_CALL_KEYS``, the accessor shape) is ``_params`` and
``_origins``'s: a sink here is a sink unless a source read pre-empts it there. ``call_writes``
is the R-J / R-W hook the scope pass calls while it is still building, so it reads the model
alone (no R-H symbol). Nothing here imports ``tree_sitter`` (D1).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from itertools import chain, filterfalse
from operator import attrgetter
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

from shared.ast._nodes import (
    ancestors,
    cached,
    first,
    is_kind,
    kids_of,
    member_object,
    named,
    of_kind,
    parsed_buffer,
)
from shared.ast._validate import OTHER_LITERAL_CLASS
from shared.ast.kinds import Field, Kind
from shared.ast.limits import MAX_ARG_NAMES, MAX_CHAIN
from shared.ast.profile import PROFILES
from shared.ast.profiles import EMPTY_MAP, FAMILIES, Builtin, Positions
from shared.ast.roles import (
    BROWSER_REQUEST_KEYS,
    BUILDER_ARG_KEYS,
    BUILTIN_KEYS,
    COLLECTION_WORDS,
    COMMAND_BUILDER_WORDS,
    COMMAND_RECEIVER_WORDS,
    COMMAND_STRONG,
    COMMAND_WEAK,
    DATA_STORE_WORDS,
    EXACT_NON_STRONG,
    FLAG_LITERALS,
    GENERIC_REQUEST_VERBS,
    MERGE_WORDS,
    NO_WORDS,
    OUTPUT_PARAM_WORDS,
    PATH_KWARGS,
    PATH_SYNC_TWINS,
    PROCESS_WORDS,
    REGEX_WORDS,
    REQUEST_API_WORDS,
    REQUEST_CARRIER_WORDS,
    REQUEST_SINK_NO_POSITIONAL,
    REQUEST_TERMINAL_WORDS,
    SHELL_INTERPRETERS,
    SHELL_KWARG,
    SHELL_PREFIXES,
    SINK_KEYS,
    SINK_WORDS,
    TWO_PATH_SINKS,
    URL_KWARGS,
    URL_SHAPE_WORDS,
    WRITE_SINKS,
    callee_text,
    chain_names,
    command_lead,
    glue,
    hits,
    identifier_text,
    last_identifier,
    named_by,
    path_sink_key,
    receiver,
    sync_twin,
    word_set,
    words,
)
from shared.ast.scope import binds_whole_module, import_call

if TYPE_CHECKING:
    from shared.ast.model import FileModel
    from shared.ast.scope import Def, ScopeTable

__all__ = ["FAMILIES", "Calls", "call_writes"]  # FAMILIES: v1's three (§8.3), ``profiles``'

# The empty answers, each one shared object (``EMPTY_MAP`` for a site with no keyword argument,
# no sink or no method): every answer is memoised per site, so a fresh empty one each time
# would be kept once per call.
_NONE: tuple[int, ...] = ()
# R-F: the receiver NAMEs a method call through the enclosing class is made on (syntax, not
# lexicon: `this.m()`, `self.m()`, `cls.m()`).
_SELF_RECEIVERS = frozenset({"this", "self", "cls"})
# W11 / R-W: the UNARY operator tokens that take a reference to a NAME (Go `&x`, Rust `&mut x`).
_REFERENCES = frozenset({"&", "*"})
# R-L: the template-shell callee (`$\`...\``), tested on the raw NAME: gluing would erase it.
_TEMPLATE_SHELL = "$"
_STRONG_PREFIXES = tuple(sorted(COMMAND_STRONG))
# A44 (1) (a): a URL-shaped argument. A LITERAL or TEMPLATE carrying a scheme separator in its
# head (a scheme is short: `https://`, `${proto}://`), or the last identifier of a
# NAME / MEMBER (else of its first operand: `&q.url`, `BASE_URL + p`) with a URL word.
_SCHEME = "://"
# The head of a literal read for it (and, A44 (1) (c), for an import call's module path).
_LITERAL_HEAD = 64
_TEXTUAL = frozenset({Kind.LITERAL, Kind.TEMPLATE})
_NAMED_VALUES = frozenset({Kind.NAME, Kind.MEMBER})
# A44 (1) (a): the literal collections a receiver's Def may bind (an object / dict, an array).
_LITERAL_COLLECTIONS = frozenset({Kind.OBJECT, Kind.ARRAY})
# D25 (b): the kinds of a BUILT command argument — string construction by syntax (a BINOP,
# a TEMPLATE), never a key table.
_BUILT = frozenset({Kind.BINOP, Kind.TEMPLATE})
# The ``_of_function`` group of the local calls (no family is named so).
_LOCAL_CALLS = "local calls"
_LITERAL_TRUE = "true"
# What a site's glued key must be for the site to be any sink (§8.5), derived once from the
# roles tables: a word-sink key (path, request, R-V's terminal, command), or any key a builtin's
# PAIR can end in. ``builtin`` probes ``glue(qualifier) + key`` first (W5, ``_pair``), so every
# proper suffix of a builtin key is one (the whole key is a ``SINK_KEYS`` entry). ``""`` is a
# key-less callee: R-L's ``$`` glues to it (an import-aliased ``$`` is ``_dollar``'s). A strong
# prefix (R-N) is the one other way in. One probe rejects most call sites before any of their
# sink rows is read.
_SINK_SIDE = frozenset().union(
    SINK_KEYS,
    REQUEST_TERMINAL_WORDS,
    ("",),
    (key[i:] for key in BUILTIN_KEYS for i in range(1, len(key))),
    PATH_SYNC_TWINS,  # A44 (1) (e): ``path_sink_key``'s twins
)


# ── the scope pass's R-J / R-W hook (model only) ─────────────────────────────


def _reference_name(model: FileModel, arg: int) -> int:
    """W11: the NAME an argument takes a reference to (UNARY ``&`` / ``*`` over a NAME)."""
    if model.kind(arg) is not Kind.UNARY or model.ident(arg) not in _REFERENCES:
        return -1
    return _leading_name(model, model.children(arg))


def _first_child(model: FileModel, node: int) -> int:
    """``node``'s first child, ``-1`` for a leaf."""
    kids = model.children(node)
    return kids[0] if kids else -1


# A44 (1) (c): an identifier carrying a ``REGEX_WORDS`` concept, by a word or glued (``RegExp``
# -> ``regexp``).
_regex_name = partial(named_by, lexicon=REGEX_WORDS)


def _leading_name(model: FileModel, nodes: Sequence[int]) -> int:
    """The first of ``nodes`` when it is a NAME, else ``-1`` (also for no node)."""
    return nodes[0] if nodes and model.kind(nodes[0]) is Kind.NAME else -1


def _merged(model: FileModel, call: int) -> list[int]:
    """R-J: a merge call's arg 0, when it is a NAME."""
    head = _leading_name(model, model.args(call))
    return [head] if head >= 0 else []


def _referenced(model: FileModel, call: int) -> list[int]:
    """R-W: the NAMEs the call's reference arguments point at."""
    return [n for n in (_reference_name(model, a) for a in model.args(call)) if n >= 0]


def call_writes(model: FileModel, call: int) -> list[int]:
    """The NAMEs ``call`` writes in place (§7.2's ``call_writes``): R-J's merge target, R-W's
    output parameters (A28 (7): only in a profile with ``reference_args``, Go and Rust). The
    scope pass is still building when it asks, so the callee is read by the identifier the
    model ships (no R-H symbol)."""
    key = glue(callee_text(model, call))
    if key in MERGE_WORDS:
        return _merged(model, call)
    if key in OUTPUT_PARAM_WORDS and PROFILES[model.language].reference_args:
        return _referenced(model, call)
    return []


# ── small model reads ────────────────────────────────────────────────────────


def _unique(nodes: Iterator[int] | Sequence[int]) -> tuple[int, ...]:
    """``nodes`` in order, each once (a request argument may be named twice)."""
    return tuple(dict.fromkeys(nodes))


def _by_family(found: Iterable[tuple[str, tuple[int, ...]]]) -> Mapping[str, tuple[int, ...]]:
    """A site's sink arguments by family, a family with none left out (``EMPTY_MAP``: no sink)."""
    sinks = {family: args for family, args in found if args}
    return MappingProxyType(sinks) if sinks else EMPTY_MAP


def _select(args: Sequence[int], positions: Positions) -> tuple[int, ...]:
    """L9/W5: the arguments at ``positions`` (``"all"``: every positional argument)."""
    if positions == "all":
        return tuple(args)
    return tuple(args[i] for i in positions if i < len(args))


class _Shape(NamedTuple):
    """A call site's shape: its callee; the CALL its callee NAME is bound to by a partial
    application (§8.4; ``-1``: none); its receiver; its callee's last identifier as role tests
    read it (R-H) and that identifier's glued key (L1 (a))."""

    callee: int
    bound: int
    receiver: int
    ident: str
    key: str


@dataclass(slots=True)
class _Facts:
    """One memo per model-only fact of the call sites, each keyed by node (§8.7)."""

    args: dict[int, Sequence[int]] = field(default_factory=dict)
    kwargs: dict[int, Mapping[str, int]] = field(default_factory=dict)
    shape: dict[int, _Shape] = field(default_factory=dict)
    chain: dict[int, frozenset[str]] = field(default_factory=dict)
    local: dict[int, int] = field(default_factory=dict)
    methods: dict[int, Mapping[str, int]] = field(default_factory=dict)
    sinks: dict[int, Mapping[str, tuple[int, ...]]] = field(default_factory=dict)
    # The profile builtin a site names, None for none (``Calls.builtin``).
    builtins: dict[int, Builtin | None] = field(default_factory=dict)
    # A command site's arguments after an R-M interpreter + flag (``Calls._shelled``).
    shelled: dict[int, Sequence[int]] = field(default_factory=dict)
    # A site list's sites by nearest FUNCTION, keyed by family (``_LOCAL_CALLS``: the local
    # calls), made when a summary first asks for one function's (the base reads the whole list).
    grouped: dict[str, dict[int, list[int]]] = field(default_factory=dict)


class Calls:
    """The model-only facts of one file's call sites, each memoised per node (§8.7: O(1)
    amortised per call)."""

    def __init__(self, model: FileModel, scope: ScopeTable) -> None:
        profile = PROFILES[model.language]  # a model is of a validated language
        self._m = model
        self._scope = scope
        self._builtins: Mapping[str, Builtin] = profile.builtin_sinks
        self._browser = profile.browser_capable
        self.constructors = scope.constructors
        self._facts = _Facts()
        # A Def is named by the text of a node outside every CALLEE (``_resolve``).
        self._bindable = model.texts_outside(Field.CALLEE)
        self._keywords = bool(model.nodes(Kind.KWARG))  # no KWARG, no call has a keyword
        for site, names in self.constructors.items():
            self._declared(site, names)
        calls = filterfalse(scope.prototypes.__contains__, model.calls())  # A36
        self.sites: tuple[int, ...] = tuple(sorted(chain(calls, self.constructors)))
        self._reaching: frozenset[int] | None = None  # built on first use
        self._parsed: str | bytes | None = None  # the parsed buffer, built on first use
        self._sinks_by_family: dict[str, list[int]] | None = None  # built on first use
        self._locals: tuple[int, ...] | None = None  # built on first use

    def _declared(self, site: int, names: Sequence[int]) -> None:
        """C2 (R-X): a declaration's call shape, known up front — its declared type is the
        callee and the bare type NAMEs the scope pass confirmed are its arguments; it has no
        keyword argument, receiver, partial application or local callee."""
        facts = self._facts
        declared = first(self._m, site, Field.ANNOTATION)
        facts.shape[site] = self._made(declared, -1, -1, declared)
        facts.args[site] = names
        facts.kwargs[site] = EMPTY_MAP
        facts.local[site] = -1

    def local_calls(self, fn: int | None) -> Sequence[int]:
        """The call sites whose callee is a local FUNCTION (``local``), in document order:
        every one (``fn`` None), else those whose nearest FUNCTION is ``fn`` (``-1``: module
        level)."""
        return self._of_function(_LOCAL_CALLS, self._local_sites(), fn)

    def _local_sites(self) -> tuple[int, ...]:
        """Every call site of a local FUNCTION, in document order: one pass over the sites."""
        if self._locals is None:
            self._locals = tuple(site for site in self.sites if self.local(site) >= 0)
        return self._locals

    def family_sites(self, family: str, fn: int | None) -> Sequence[int]:
        """The call sites that are ``family`` sinks, keyed as ``local_calls`` keys them."""
        return self._of_function(family, self._sink_sites().get(family, ()), fn)

    def _sink_sites(self) -> Mapping[str, list[int]]:
        """Each family's sink sites, in document order: every site classified once, in one
        pass (``_by_family`` leaves out a family a site is no sink of)."""
        if self._sinks_by_family is None:
            self._sinks_by_family = self._classified()
        return self._sinks_by_family

    def _classified(self) -> dict[str, list[int]]:
        found: dict[str, list[int]] = {}
        for site in self.sites:
            for family in cached(self._facts.sinks, site, self._sinks):
                found.setdefault(family, []).append(site)
        return found

    def _of_function(self, group: str, sites: Sequence[int], fn: int | None) -> Sequence[int]:
        """``sites`` (the ``group`` list) whole for ``fn`` None, else those whose nearest
        FUNCTION is ``fn``, the list grouped once on its first such ask."""
        if fn is None:
            return sites
        return cached(self._facts.grouped, group, lambda _: self._grouped(sites)).get(fn, ())

    def _grouped(self, sites: Iterable[int]) -> dict[int, list[int]]:
        """``sites`` in document order, each under its nearest FUNCTION (``-1``: module
        level)."""
        found: dict[int, list[int]] = {}
        for site in sites:
            found.setdefault(self._m.function_of(site), []).append(site)
        return found

    # ── the shape of a site (an R-X declaration's is ``_declared``) ──

    def _shape(self, site: int) -> _Shape:
        """The site's shape, made once (``_shaped``): every site's key is read, and with it
        its callee, partial application and receiver, so they are made together. The most read
        memo of the flow pass, so ``cached`` is inlined (no shape is None)."""
        found = self._facts.shape.get(site)
        return found if found is not None else cached(self._facts.shape, site, self._shaped)

    def _shaped(self, site: int) -> _Shape:
        """A CALL's callee and its partial application first (§8.4): the bound call's first
        argument, when there is one, is the head the key and the receiver are read from."""
        callee = self._m.callee(site)
        bound = self._bound(callee)
        if bound < 0:
            return self._made(callee, -1, receiver(self._m, site), callee)
        head = self._head(bound)
        return self._made(callee, bound, member_object(self._m, head), head)

    def _made(self, callee: int, bound: int, holder: int, head: int) -> _Shape:
        """The shape whose identifier is ``head``'s last one, an import's symbol (R-H)."""
        ident = identifier_text(self._m, last_identifier(self._m, head), self.symbol_of)
        return _Shape(callee, bound, holder, ident, glue(ident))

    def callee(self, site: int) -> int:
        """The callee: a CALL's CALLEE child; an R-X declaration's declared type (C2)."""
        return self._shape(site).callee

    def args(self, site: int) -> Sequence[int]:
        """The positional arguments (the first ``MAX_ARGS``); an R-X declaration's are the
        bare type NAMEs of its parameters (C2)."""
        return cached(self._facts.args, site, self._m.args)

    def kwargs(self, site: int) -> Mapping[str, int]:
        """The keyword arguments, name -> value node (none for an R-X declaration); a
        partial application's pre-bound ones first (§8.4)."""
        return cached(self._facts.kwargs, site, self._kwargs)

    def _kwargs(self, site: int) -> Mapping[str, int]:
        if not self._keywords:
            return EMPTY_MAP
        bound = self.bound(site)
        own = self._m.kwargs(site)
        merged = {**self._m.kwargs(bound), **own} if bound >= 0 else own
        return MappingProxyType(merged) if merged else EMPTY_MAP

    def receiver(self, site: int) -> int:
        """The receiver (``roles.receiver``); a partial application's, its bound callee's
        object (§8.4); ``-1`` for a bare call or a declaration."""
        return self._shape(site).receiver

    def _head(self, bound: int) -> int:
        """A partial application's bound callee: the first argument of the bound call."""
        return self._m.args(bound)[0]

    # ── partial application (§8.4) ──

    def bound(self, site: int) -> int:
        """§8.4 partial application: the CALL a callee NAME is bound to whose first argument
        names a sink (``go = partial(subprocess.run, shell=True)``), else ``-1``; the site then
        takes that sink's key and the call's pre-bound keyword arguments."""
        return self._shape(site).bound

    def _bound(self, callee: int) -> int:
        if not is_kind(self._m, callee, Kind.NAME):
            return -1
        values = map(attrgetter("value"), self._resolve(callee))
        return next((v for v in values if self._binds_a_sink(v)), -1)

    def _binds_a_sink(self, node: int | None) -> bool:
        """A CALL whose first argument's last identifier is a sink key (§8.4)."""
        if node is None or not is_kind(self._m, node, Kind.CALL) or not self._m.args(node):
            return False
        return self._sink_key(self._glued(last_identifier(self._m, self._head(node))))

    @staticmethod
    def _sink_key(key: str) -> bool:
        """§8.4: a key a partial application binds a sink by — a ``SINK_KEYS`` entry, or an
        R-N strong prefix (``_strong``)."""
        return key in SINK_KEYS or Calls._strong(key)

    def _glued(self, node: int) -> str:
        """The glued text of a NAME (``""`` for ``-1`` or a node with no text)."""
        return glue(identifier_text(self._m, node))

    def values(self, site: int) -> tuple[int, ...]:
        """Every argument value: the positional ones, then each keyword's (§8.2's ⋃ args)."""
        return (*self.args(site), *self.kwargs(site).values())

    def _resolve(self, node: int) -> Sequence[Def]:
        """The scope table's ``resolve``, short of a NAME no Def reaches (``_unbindable``): so a
        call site read only so (``res.send(x)``, ``str(x)``) never makes an on-demand table run
        its function's scope."""
        return () if self._unbindable(node) else self._scope.resolve(node)

    def _unbindable(self, node: int) -> bool:
        """A NAME that reaches no Def in any scope: a PROPERTY (W8: never a read, and no write
        records one there), or one whose text no Def carries — a Def is named by its own node's
        text, or by W8's OBJECT's, never by a CALLEE's."""
        m = self._m
        return m.kind(node) is Kind.NAME and (m.field(node) is Field.PROPERTY or m.ident(node) not in self._bindable)

    # ── the callee's key (L1 (a), W3, W5, W6) ──

    def symbol_of(self, node: int) -> str | None:
        """R-H: the symbol of the import binding a NAME read resolves to, else None."""
        defs = self._resolve(node)
        return next((d.symbol for d in defs if d.symbol), None) if defs else None

    def ident(self, site: int) -> str:
        """The callee's last identifier as role tests read it: the imported symbol for an
        import-bound callee NAME (R-H), else its own text; ``""`` for none."""
        return self._shape(site).ident

    def key(self, site: int) -> str:
        """The callee's glued key (L1 (a))."""
        return self._shape(site).key

    def _pair(self, site: int) -> str:
        """W5: ``glue(qualifier's last identifier) + key``, or ``""`` without a qualifier."""
        qualifier = self._m.ident(last_identifier(self._m, self.receiver(site)))
        return glue(qualifier) + self.key(site) if qualifier else ""

    def builtin(self, site: int) -> Builtin | None:
        """The profile builtin the site names: its PAIR key first, then its single key.
        Memoised per site: ``_sinks``, ``_program`` and ``builtin_program`` read the one answer."""
        return cached(self._facts.builtins, site, self._named_builtin)

    def _named_builtin(self, site: int) -> Builtin | None:
        return self._builtins.get(self._pair(site)) or self._builtins.get(self.key(site))

    def chain_words(self, node: int) -> frozenset[str]:
        """The words of ``node``'s chain identifiers (callee and receiver links, never its
        arguments; at most ``MAX_CHAIN`` identifiers): a carrier or receiver test reads them."""
        return cached(self._facts.chain, node, self._chain_words)

    def _chain_words(self, node: int) -> frozenset[str]:
        return word_set(chain_names(self._m, node))

    # ── a local def wins (§8.4; R-F, R-G) ──

    def local(self, site: int) -> int:
        """The local FUNCTION the callee resolves to, else ``-1``: a NAME bound by a
        ``function`` Def (R-G included), or ``this.m`` / ``self.m`` / ``cls.m`` (R-F)."""
        return cached(self._facts.local, site, self._local)

    def _local(self, site: int) -> int:
        callee = self.callee(site)
        if callee < 0:
            return -1
        bound = self._bound_function(callee)
        return bound if bound >= 0 else self._method(site)

    def _bound_function(self, callee: int) -> int:
        """R-G: the FUNCTION a ``function`` Def binds the callee NAME to."""
        if self._m.kind(callee) is not Kind.NAME:
            return -1
        defs = self._resolve(callee)
        return next((d.value for d in defs if self._function_def(d)), -1)  # type: ignore[misc]

    def _function_def(self, d: Def) -> bool:
        return d.kind == "function" and is_kind(self._m, d.value if d.value is not None else -1, Kind.FUNCTION)

    def _method(self, site: int) -> int:
        """R-F: a method of the enclosing CLASS called on ``this`` / ``self`` / ``cls``."""
        if self._glued(self.receiver(site)) not in _SELF_RECEIVERS:
            return -1
        methods = self._methods(self._enclosing_class(site))
        return methods.get(identifier_text(self._m, last_identifier(self._m, self.callee(site))), -1)

    def _enclosing_class(self, node: int) -> int:
        """The nearest CLASS ancestor (at most ``MAX_DEPTH`` up), else ``-1``."""
        return next((a for a in ancestors(self._m, node) if self._m.kind(a) is Kind.CLASS), -1)

    def _methods(self, cls: int) -> Mapping[str, int]:
        """A CLASS's methods by name, memoised per class (none outside a class)."""
        return cached(self._facts.methods, cls, self._class_methods) if cls >= 0 else EMPTY_MAP

    def _class_methods(self, cls: int) -> Mapping[str, int]:
        """Its BODY's FUNCTION children, by declared name."""
        fns = (f for body in self._m.children(cls, Field.BODY) for f in kids_of(self._m, body, Kind.FUNCTION))
        return MappingProxyType({named(self._m, f): f for f in fns})

    # ── which functions can hold a flow (§8.4) ──

    def reaching_sinks(self) -> frozenset[int]:
        """The FUNCTIONs holding a sink of any family, directly or through their own local
        calls (transitively): the only callees whose summaries can add a candidate. One pass
        over the call sites and one over the reverse local-call edges, memoised (a None
        sentinel, as ``Engine._returns``: an attribute set outside ``__init__``, as
        ``cached_property`` sets one, would make every attribute read of the object slower)."""
        if self._reaching is None:
            self._reaching = self._reached()
        return self._reaching

    def _reached(self) -> frozenset[int]:
        """Module-level code (``function_of == -1``) is no FUNCTION: a sink there reaches no
        callee, and a call to no local FUNCTION (``local == -1``) is no edge."""
        callers = self._callers()
        found = {self._m.function_of(site) for sites in self._sink_sites().values() for site in sites}
        work = list(found)
        while work:
            fresh = callers.get(work.pop(), set()) - found
            found |= fresh
            work.extend(fresh)
        found.discard(-1)
        return frozenset(found)

    def _callers(self) -> dict[int, set[int]]:
        """The reverse local-call edges: each local FUNCTION's calling FUNCTIONs (``-1`` for
        module level)."""
        callers: dict[int, set[int]] = {}
        for site in self._local_sites():
            callers.setdefault(self.local(site), set()).add(self._m.function_of(site))
        return callers

    # ── sinks (§8.5) ──

    def sink_args(self, site: int, family: str) -> tuple[int, ...]:
        """The site's ``family`` sink arguments (§8.5), empty when it is no such sink. A
        local def is no sink; a builtin's family set replaces the word classification (an
        EMPTY set is no sink at all, P4/R5)."""
        return cached(self._facts.sinks, site, self._sinks).get(family, _NONE)

    def _sinks(self, site: int) -> Mapping[str, tuple[int, ...]]:
        if not self._sink_side(site) or self.local(site) >= 0:
            return EMPTY_MAP
        builtin = self.builtin(site)
        return _by_family(self._builtin_sinks(site, builtin) if builtin else self._word_sinks(site))

    def _sink_side(self, site: int) -> bool:
        """What every sink row needs (``_SINK_SIDE``): a sink-side key or a strong prefix, or
        an import-aliased R-L ``$`` callee (read last: the set holds every other ``$``)."""
        key = self.key(site)
        return key in _SINK_SIDE or key.startswith(_STRONG_PREFIXES) or self._dollar(site)

    def _dollar(self, site: int) -> bool:
        """R-L: the callee NAME is ``$``, tested on the raw NAME (gluing would erase it)."""
        return self._m.ident(self.callee(site)) == _TEMPLATE_SHELL

    def _builtin_sinks(self, site: int, builtin: Builtin) -> Iterator[tuple[str, tuple[int, ...]]]:
        """W5, L9: a builtin's positions per family, only when its ``when`` holds."""
        if not self._when(site, builtin.when):
            return
        for family in builtin.families:
            yield family, self._builtin_args(site, builtin, family)

    def _builtin_args(self, site: int, builtin: Builtin, family: str) -> tuple[int, ...]:
        """The command row's program position with what R-M and ``shell=True`` add (§8.5),
        else the family's positions (L9)."""
        if family == "command":
            return self._command_args(site)
        return _select(self.args(site), builtin.args_for(family))

    def _when(self, site: int, when: tuple[int, str] | None) -> bool:
        """W5: the argument at the position is a NAME whose glued text is the key."""
        if when is None:
            return True
        position, key = when
        held = self.args(site)[position : position + 1]
        return any(is_kind(self._m, n, Kind.NAME) and self._glued(n) == key for n in held)

    def _word_sinks(self, site: int) -> Iterator[tuple[str, tuple[int, ...]]]:
        """Each family's word-classified sink arguments (§8.5), in ``FAMILIES`` order."""
        return ((family, _WORD_ROWS[family](self, site)) for family in FAMILIES)

    # ── path (§8.5; L9, W14, R10) ──

    def _path_args(self, site: int) -> tuple[int, ...]:
        """A path sink key, a synchronous twin's by its stem (A44 (1) (e)): its arguments."""
        key = path_sink_key(self.key(site))
        if not key:
            return _NONE
        args = self.args(site)
        if key in TWO_PATH_SINKS:
            return tuple(args)  # R10
        return self._path_default(site, key, args)

    def _path_default(self, site: int, key: str, args: Sequence[int]) -> tuple[int, ...]:
        """A one-path sink's argument 0 and its path keyword arguments (L9's default); none
        for a write-style key called with one positional argument (W14: it is the data)."""
        if key in WRITE_SINKS and len(args) == 1:
            return _NONE
        return _unique(chain(args[:1], self._named(site, PATH_KWARGS)))

    def _named(self, site: int, names: frozenset[str]) -> Iterator[int]:
        return (value for name, value in self.kwargs(site).items() if glue(name) in names)

    # ── request (§8.5; L8, W10, R-V) ──

    def _request_args(self, site: int) -> tuple[int, ...]:
        key = self.key(site)
        carrier = self._carrier(site, key)
        if not self._request_sink(site, key, carrier):
            return _NONE
        carried = self._carried(site, key) if carrier else ()
        return _unique(chain(self._url_positional(site, key), self._url_named(site), carried))

    def _request_sink(self, site: int, key: str, carrier: bool) -> bool:
        """A request word or an R-V carrier (§8.5), on a receiver like an HTTP client
        (``_client_like``, A44 (1) (a))."""
        return (carrier or self._request_word(key)) and self._client_like(site, key)

    def _url_named(self, site: int) -> Iterator[int]:
        """W10: the values of the KWARGs and OBJECT-literal PAIRs named like a URL."""
        return chain(self._named(site, URL_KWARGS), self._url_pairs(site))

    # ── HTTP-client evidence (A44 (1) (a)) ──

    def _client_like(self, site: int, key: str) -> bool:
        """A receiver that is no collection construction (one hop: ``_collection_value``), and
        for a generic verb HTTP-client evidence (``_client_evidence``): an in-memory map, set
        or literal is no HTTP client."""
        if self._receiver_is(site, self._collection_value):
            return False
        return key not in GENERIC_REQUEST_VERBS or self._client_evidence(site, key)

    def _client_evidence(self, site: int, key: str) -> bool:
        """No receiver (a module's own function counts as none), a request API concept in the
        receiver chain, or a URL-shaped argument."""
        api = self._receiver_meets
        return self._free_call(site) or api(site, REQUEST_API_WORDS) or self._url_shaped(site, key)

    def _free_call(self, site: int) -> bool:
        """A bare call, or one on a NAME a whole-module import binds (``import requests``:
        ``scope.binds_whole_module``)."""
        holder = self.receiver(site)
        return holder < 0 or any(binds_whole_module(self._m, d) for d in self._arg_defs(holder))

    def _url_shaped(self, site: int, key: str) -> bool:
        """A KWARG or PAIR named like a URL, or a positional URL argument that is URL-shaped
        (``_url_value``: a scheme, or URL words)."""
        named = next(self._url_named(site), -1) >= 0
        return named or any(map(self._url_value, self._url_positional(site, key)))

    def _url_value(self, node: int) -> bool:
        """A LITERAL or TEMPLATE carrying ``://`` (``_scheme``); else the last identifier of
        ``node`` — or of its first operand (``&q.url``, ``BASE_URL + p``) — has a
        ``URL_SHAPE_WORDS`` word."""
        if self._m.kind(node) in _TEXTUAL:
            return self._scheme(node)
        operand = node if self._m.kind(node) in _NAMED_VALUES else _first_child(self._m, node)
        return hits((identifier_text(self._m, last_identifier(self._m, operand)),), URL_SHAPE_WORDS)

    def _scheme(self, node: int) -> bool:
        """The literal's head (``_literal_head``) holds ``://``."""
        return _SCHEME in self._literal_head(node)

    def _literal_head(self, node: int) -> str:
        """The first ``_LITERAL_HEAD`` bytes of a literal's source, read from the parsed buffer:
        a string's value never ships in the model (D16), so its few leading bytes are read
        where it stands and kept nowhere (a scheme, a module path)."""
        start, end = self._m.span(node)
        head = self._buffer()[start : min(end, start + _LITERAL_HEAD)]
        return head if isinstance(head, str) else head.decode("utf-8", "replace")

    def _buffer(self) -> str | bytes:
        """The parsed buffer (``parsed_buffer``), made on the first ask."""
        if self._parsed is None:
            self._parsed = parsed_buffer(self._m.nl_lines.text)
        return self._parsed

    def _collection_value(self, node: int) -> bool:
        """An OBJECT or ARRAY literal, or a CALL whose callee's last word is a
        ``COLLECTION_WORDS`` concept (``new Map()``, ``new WeakSet()``, ``dict()``)."""
        kind = self._m.kind(node)
        if kind is not Kind.CALL:
            return kind in _LITERAL_COLLECTIONS
        found = words(callee_text(self._m, node))
        return bool(found) and found[-1] in COLLECTION_WORDS

    def _url_positional(self, site: int, key: str) -> tuple[int, ...]:
        """A request sink's argument 0, none for a key that takes no positional URL."""
        return _NONE if key in REQUEST_SINK_NO_POSITIONAL else tuple(self.args(site)[:1])

    def _request_word(self, key: str) -> bool:
        """A request sink word; the bare ``open`` only in a browser-capable profile (L8)."""
        return key in SINK_WORDS["request"] and (key not in BROWSER_REQUEST_KEYS or self._browser)

    def _carrier(self, site: int, key: str) -> bool:
        """R-V: a request terminal on a receiver whose chain words meet the carriers."""
        return key in REQUEST_TERMINAL_WORDS and self._receiver_meets(site, REQUEST_CARRIER_WORDS)

    def _carried(self, site: int, key: str) -> tuple[int, ...]:
        """R-V's receiver, and for a no-positional key every positional argument that is a
        carrier itself or a NAME whose reaching Defs' RHS chains are (W10)."""
        args = self.args(site) if key in REQUEST_SINK_NO_POSITIONAL else ()
        return (self.receiver(site), *(a for a in args if self._carries(a)))

    def _carries(self, arg: int) -> bool:
        """W10: a carrier chain itself, or a NAME whose reaching Defs' RHS chains are."""
        return self._one_hop(arg, self._carrier_chain)

    def _one_hop(self, arg: int, test: Callable[[int], bool]) -> bool:
        """``test`` holds of the argument itself, or of a reaching Def's value of a NAME
        argument (``_arg_defs``): one hop, never deeper (W10; D25 (b)'s ``built``)."""
        return test(arg) or any(test(d.value) for d in self._arg_defs(arg) if d.value is not None)

    def _arg_defs(self, arg: int) -> Sequence[Def]:
        """W10: the Defs reaching a NAME argument (at most ``MAX_ARG_NAMES``); none for any
        other argument."""
        return self._resolve(arg)[:MAX_ARG_NAMES] if self._m.kind(arg) is Kind.NAME else ()

    def _carrier_chain(self, node: int) -> bool:
        return not self.chain_words(node).isdisjoint(REQUEST_CARRIER_WORDS)

    # ── the receiver's evidence (R-V, A44 (1) (a), (c)) ──

    def _receiver_words(self, site: int) -> frozenset[str]:
        """The receiver's chain words (``chain_words``, memoised); none for a bare call."""
        holder = self.receiver(site)
        return self.chain_words(holder) if holder >= 0 else NO_WORDS

    def _receiver_meets(self, site: int, lexicon: frozenset[str]) -> bool:
        """The receiver's chain words meet ``lexicon``: never for a bare call."""
        return not self._receiver_words(site).isdisjoint(lexicon)

    def _receiver_is(self, site: int, test: Callable[[int], bool]) -> bool:
        """``test`` holds of the receiver, or of a reaching Def's value of a NAME receiver
        (``_one_hop``): never for a bare call."""
        holder = self.receiver(site)
        return holder >= 0 and self._one_hop(holder, test)

    def _url_pairs(self, site: int) -> Iterator[int]:
        """W10: the values of the OBJECT-literal PAIRs named like a URL, in any argument."""
        objects = of_kind(self._m, self.args(site), Kind.OBJECT)
        return (v for o in objects for v in self._url_values(o))

    def _url_values(self, obj: int) -> list[int]:
        pairs = (p for p in kids_of(self._m, obj, Kind.PAIR) if self._glued(first(self._m, p, Field.KEY)) in URL_KWARGS)
        return [first(self._m, p, Field.VALUE) for p in pairs]

    # ── command (§8.5; L2, L3, L7, R-L, R-M, R-N, W15 (a)) ──

    def _command_sink(self, site: int) -> bool:
        """R-L (``$`` with a TEMPLATE); else, on a receiver that is no regex and no data store
        (A44 (1) (c)), R-N (``_strong_sink``) or a weak key with a strengthener."""
        if self._template_shell(site):
            return True
        return self._keyed_command(site) and not self._not_a_process(site)

    def _keyed_command(self, site: int) -> bool:
        return self._strong_sink(site) or (self.key(site) in COMMAND_WEAK and self._strengthened(site))

    def _strong_sink(self, site: int) -> bool:
        """R-N under L2 (``_strong``), narrowed by A44 (1) (c): an exact ``COMMAND_STRONG``
        key or a single-word identifier, else leading words gluing to a strong key exactly
        with process evidence (``_process_evidence``)."""
        if not Calls._strong(self.key(site)):
            return False
        return self._single_word(site) or (command_lead(self.ident(site)) and self._process_evidence(site))

    def _single_word(self, site: int) -> bool:
        """An exact ``COMMAND_STRONG`` key (``checkoutput``) or its synchronous twin (``execsync``,
        (e)'s suffix reading), or an identifier of one word (``execa``)."""
        exact = bool(sync_twin(self.key(site), COMMAND_STRONG))
        return exact or len(words(self.ident(site))) <= 1

    def _process_evidence(self, site: int) -> bool:
        """A44 (1) (c): a ``PROCESS_WORDS`` concept in the callee's own words, its receiver
        chain or the module its import binding names (``import { execSync } from
        "child_process"``)."""
        own, module = words(self.ident(site)), self._module_words(self.callee(site))
        return not PROCESS_WORDS.isdisjoint(chain(own, self._receiver_words(site), module))

    def _module_words(self, node: int) -> Iterator[str]:
        """The words of the module text of each import Def ``node`` resolves to (a MEMBER by its
        base, as ``ScopeTable.resolve`` reads a chain): at most ``MAX_ARG_NAMES`` Defs."""
        defs = self._resolve(node)[:MAX_ARG_NAMES] if node >= 0 else ()
        return chain.from_iterable(map(self._import_words, defs))

    def _import_words(self, d: Def) -> tuple[str, ...]:
        """The words of the module a Def binds from: an IMPORT's text (W3: the last segment of
        a string module path), or an import call's module literal (``require("node:x")``)."""
        if d.value is None:
            return ()
        if d.kind == "import":
            return words(self._m.ident(d.value) or "")
        return self._required_words(d.value)

    def _required_words(self, value: int) -> tuple[str, ...]:
        """W6's import call (``scope.import_call``): the words of its module literal's head
        (``_literal_head``); none for any other value."""
        if not import_call(self._m, value):
            return ()
        module = next(iter(self._m.args(value)), -1)
        return words(self._literal_head(module)) if is_kind(self._m, module, Kind.LITERAL) else ()

    def _not_a_process(self, site: int) -> bool:
        """A44 (1) (c): the receiver is a regex — a regex literal, or a NAME one of whose
        reaching Defs binds one or a regex construction — or its chain words carry a
        data-store concept (``db.exec(sql)``)."""
        return self._receiver_meets(site, DATA_STORE_WORDS) or self._receiver_is(site, self._regex)

    def _regex(self, node: int) -> bool:
        """A regex literal (R3's catch-all literal class, ``OTHER_LITERAL_CLASS``), or a CALL
        whose callee chain carries a ``REGEX_WORDS`` concept, by a word or glued (``new
        RegExp(...)``, ``re.compile``)."""
        kind = self._m.kind(node)
        if kind is Kind.LITERAL:
            return self._m.literal(node).kind == OTHER_LITERAL_CLASS
        return kind is Kind.CALL and any(map(_regex_name, chain_names(self._m, node)))

    def _command_word_args(self, site: int) -> tuple[int, ...]:
        """A word-classified command sink's arguments (§8.5): from the program at position 0
        (``_program``: the site names no builtin)."""
        return self._command_args(site) if self._command_sink(site) else _NONE

    def _template_shell(self, site: int) -> bool:
        """R-L: the callee NAME ``$`` with a TEMPLATE argument — a tagged template ships its
        TEMPLATE as the call's ARGS itself, whose substitutions are then the arguments."""
        if not self._dollar(site):
            return False
        held = (*self._m.children(site, Field.ARGS), *self.args(site))
        return any(self._m.kind(a) is Kind.TEMPLATE for a in held)

    @staticmethod
    def _strong(key: str) -> bool:
        """R-N under L2: a COMMAND_STRONG prefix, and no exact weak or non-command key."""
        return bool(key) and key.startswith(_STRONG_PREFIXES) and key not in EXACT_NON_STRONG

    def _strengthened(self, site: int) -> bool:
        """A KWARG ``shell`` literally true, or a receiver chain naming a command receiver."""
        return self._receiver_meets(site, COMMAND_RECEIVER_WORDS) or self._shell_true(site)

    def _shell_true(self, site: int) -> bool:
        value = self.kwargs(site).get(SHELL_KWARG, -1)
        return value >= 0 and self._m.literal(value).value == _LITERAL_TRUE

    def _command_args(self, site: int) -> tuple[int, ...]:
        """The program position (``_program``; unless an ARRAY literal) and every element after
        an R-M interpreter + flag of the argument sequence (L3, L7) — the interpreter literal
        itself then carries nothing and is left out; every positional argument with a literal
        ``shell=True`` or a ``shell``/``system`` key."""
        head = self._program_arg(site)
        if head < 0:
            return _NONE
        shelled = self._shelled(site)
        positioned = () if shelled or self._m.kind(head) is Kind.ARRAY else (head,)
        return _unique(chain(positioned, shelled, self._everything(site)))

    def _shelled(self, site: int) -> Sequence[int]:
        """L3, L7 (R-M): the elements after an interpreter + flag of the argument sequence from
        the program position (``_program``) on — the positional arguments, then the builder
        chain's, each ARRAY literal flattened once (W15 (a)) — else none. Memoised per site:
        the sink arguments and ``shell_arg`` read the one answer."""
        return cached(self._facts.shelled, site, self._after_program)

    def _after_program(self, site: int) -> Sequence[int]:
        sequence = [*self._flat(self.args(site)[self._program(site) :]), *self._builder_args(site)]
        return self._after_flag(sequence)

    def _program(self, site: int) -> int:
        """The command row's program position: a builtin's (W5), else argument 0 — the row
        ``_sinks`` dispatches to (``_builtin_args``, ``_command_word_args``)."""
        builtin = self.builtin(site)
        return builtin.program if builtin else 0

    def _program_arg(self, site: int) -> int:
        """The argument at the command row's program position (``_program``), ``-1`` when the
        call has none there."""
        args = self.args(site)
        program = self._program(site)
        return args[program] if program < len(args) else -1

    # ── the command parameter heuristic's facts (D25, A42 (1); §8.5) ──

    def shell_arg(self, site: int, arg: int) -> bool:
        """D25 (b)'s shell half: the command sink ``site`` interprets ``arg`` through a shell
        by the command row's existing tables — every positional argument under a literal
        ``shell=True``, a ``shell``/``system`` key or an R-L template, or ``arg`` after an R-M
        interpreter + flag (L3)."""
        return self._shell_all(site) or arg in self._shelled(site)

    def built(self, arg: int) -> bool:
        """D25 (b)'s built half: ``arg`` is a BINOP or TEMPLATE, or a NAME one of whose reaching
        Defs' value is — one hop, never deeper (``_one_hop``)."""
        return self._one_hop(arg, self._built_node)

    def _built_node(self, node: int) -> bool:
        return self._m.kind(node) in _BUILT

    def builtin_program(self, site: int, arg: int) -> bool:
        """D25 (b)'s builtin half (A43 (1)): ``arg`` is the whole command of a profile builtin
        process API — the site names a command ``Builtin`` of the profile's own table (§6.3:
        Java ``new ProcessBuilder(cmd)``, Rust ``Command::new(cmd)``, C ``posix_spawn``) and
        ``arg`` sits at its program position (``_program_arg``). The table decides; no key is
        named here."""
        builtin = self.builtin(site)
        return builtin is not None and "command" in builtin.families and self._program_arg(site) == arg

    def _flat(self, nodes: Sequence[int]) -> Iterator[int]:
        """W15 (a): ``nodes`` with each ARRAY literal flattened once."""
        for node in nodes:
            yield from (self._m.children(node, Field.NONE) if self._m.kind(node) is Kind.ARRAY else (node,))

    def _builder_args(self, site: int) -> Iterator[int]:
        """W15 (a): the ``.arg`` / ``.args`` arguments of the builder chain above ``site``, in
        chain order (each ARRAY literal flattened once), at most ``MAX_CHAIN`` links."""
        for link in self._builder_links(site):
            if self.key(link) in BUILDER_ARG_KEYS:
                yield from self._flat(self.args(link))

    def _builder_links(self, site: int) -> Iterator[int]:
        """The CALLs of the builder chain above ``site``, in chain order: each next link
        while its key is a ``COMMAND_BUILDER_WORDS`` one, at most ``MAX_CHAIN`` of them."""
        current = site
        for _ in range(MAX_CHAIN):
            current = self._next_link(current)
            if current < 0 or self.key(current) not in COMMAND_BUILDER_WORDS:
                return
            yield current

    def _next_link(self, call: int) -> int:
        """The CALL a builder chain continues to from ``call`` (``call.next(...)``), else -1."""
        parent = self._m.parent(call)
        if parent < 0 or self._m.field(call) is not Field.OBJECT:
            return -1
        return parent if self._m.kind(parent) is Kind.CALL else self._called(parent)

    def _called(self, member: int) -> int:
        """The CALL whose CALLEE is the MEMBER ``member`` (``x.next`` in ``x.next(...)``)."""
        callee_of = self._m.kind(member) is Kind.MEMBER and self._m.field(member) is Field.CALLEE
        return self._m.parent(member) if callee_of else -1

    def _after_flag(self, sequence: Sequence[int]) -> Sequence[int]:
        """L3 (R-M): every element after the first FLAG_LITERALS literal, when the program
        (the sequence's first element) is a SHELL_INTERPRETERS literal; else none."""
        if not sequence or not self._literal_in(sequence[0], SHELL_INTERPRETERS):
            return _NONE
        return tuple(sequence[self._flag_end(sequence) :])

    def _flag_end(self, sequence: Sequence[int]) -> int:
        """One past the first ``FLAG_LITERALS`` literal after the program (past the end when
        there is none)."""
        flags = (i for i, n in enumerate(sequence[1:], 1) if self._literal_in(n, FLAG_LITERALS))
        return next(flags, len(sequence)) + 1

    def _literal_in(self, node: int, values: frozenset[str]) -> bool:
        return self._m.kind(node) is Kind.LITERAL and (self._m.ident(node) or "").lower() in values

    def _everything(self, site: int) -> Sequence[int]:
        """§8.5: every positional argument under ``shell=True`` or a shell/system key, and
        every substitution of an R-L template."""
        return self.args(site) if self._shell_all(site) else _NONE

    def _shell_all(self, site: int) -> bool:
        """§8.5: the site interprets every positional argument through a shell — a literal
        ``shell=True``, a ``shell``/``system`` key, or an R-L template."""
        every = self._shell_true(site) or self.key(site).startswith(SHELL_PREFIXES)
        return every or self._template_shell(site)


# A family's word-classified sink row (§8.5): the rows ``_word_sinks`` reads, one per family.
_WORD_ROWS: Mapping[str, Callable[[Calls, int], tuple[int, ...]]] = MappingProxyType({
    "path": Calls._path_args,
    "request": Calls._request_args,
    "command": Calls._command_word_args,
})
