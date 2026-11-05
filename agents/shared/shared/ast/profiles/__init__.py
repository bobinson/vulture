"""The row types every language table is written in (feature 0102, LLD §6.3, D19).

A language profile is DATA: a ``NODE_MAP`` from grammar node types to ``Capture`` rows,
the scope rules, and the language's own builtins. The per-language modules of this package
(``js_ts``, ``python``, ``go``, ``java``, ``rust``, ``php``, ``c``, ``cpp``) hold nothing
but tables built from the types below; ``shared.ast.profile`` assembles them into
``PROFILES`` and generates each tree-sitter query from its table (``build_query``).

The types live here, not in ``shared.ast.profile``, so the dependency runs one way: the
tables import their schema, and ``profile`` imports the tables. Nothing here imports
``tree_sitter`` (D1): only the spawned worker parses.

Dispositions (W1): a type a table maps ships as its Capture; a ``(parent type, type)`` key
applies to a direct child of that parent and wins over the plain key; a ``kind=None``
Capture is TRANSPARENT with its own field map; every unlisted type is transparent; a type in
``LanguageProfile.pruned`` is dropped with its subtree.

The rows several grammars spell the same way (``IF_ROW``, ``CALL_FA``, ``LOOP_BODY`` ...), the
family sets and the shared builtins (``EVERY_ARG_PATH``, ``NO_FAMILY``) are defined once here
(D19); each table keeps its own grammar keys and refers to them. Only ``ERROR`` exists in every
grammar, so the tables share rows, never keys.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from operator import attrgetter
from pathlib import PurePath
from types import MappingProxyType
from typing import Any, Literal

from shared.ast.kinds import Field, Kind

__all__ = [
    "ALL_FAMILIES",
    "ASSIGN_LR",
    "ASSIGN_NV",
    "AUG_ASSIGN_LR",
    "CALL_FA",
    "CLASS_ROW",
    "COMMAND",
    "EMPTY_MAP",
    "EVERY_ARG_PATH",
    "FAMILIES",
    "FUNCTION_ROW",
    "IF_ROW",
    "LAMBDA_ROW",
    "LOOP_BODY",
    "NO_FAMILY",
    "PAIR_KV",
    "PATH",
    "REQUEST",
    "TRY_BODY",
    "TYPE_ARGUMENTS",
    "Builtin",
    "CallShape",
    "Capture",
    "LanguageProfile",
    "NodeKey",
    "Positions",
    "ScopeRules",
    "Subscript",
    "cap",
    "frozen",
    "pair",
    "rows",
]

# A grammar node type, or a (parent type, type) pair that applies to a direct child (W1).
type NodeKey = str | tuple[str, str]
# Argument positions of a builtin sink: every argument, or the listed ones (L9, P4, W5).
type Positions = Literal["all"] | tuple[int, ...]
# How a CALL's callee chain is formed (§6.3): a ``function`` child, or ``object`` + ``name``
# children (Java/PHP method calls). Scoped paths (Rust/PHP ``A::b``) are compound MEMBERs (W3).
type CallShape = Literal["function", "object_name"]

# The three families a profile's consumers may own (§6.3), one set each; ``FAMILIES`` is all
# three in the LLD's order, the order a flow build meets its calls in (A38).
PATH: frozenset[str] = frozenset({"path"})
REQUEST: frozenset[str] = frozenset({"request"})
COMMAND: frozenset[str] = frozenset({"command"})
FAMILIES: tuple[str, ...] = (*PATH, *REQUEST, *COMMAND)
ALL_FAMILIES: frozenset[str] = frozenset(FAMILIES)

# The one empty read-only table every default field shares (and the flow pass's empty answers).
EMPTY_MAP: Mapping[Any, Any] = MappingProxyType({})
# W1: a generic call's type arguments, pruned so the callee ends in its own name.
TYPE_ARGUMENTS: frozenset[str] = frozenset({"type_arguments"})


def frozen[K, V](table: Mapping[K, V]) -> Mapping[K, V]:
    """A read-only view of a table: a profile's rows never change after import."""
    return MappingProxyType(dict(table))


@dataclass(frozen=True, slots=True)
class Subscript:
    """The parameter a vexing parse reads as a subscripted name (A36, C2, R-X: the C++
    ``std::ifstream in(argv[1]);``), in the grammar's names, each written by the language's
    table: a ``param`` node holding just a type name under ``object`` and, under
    ``declarator``, an ``array`` node that holds its ``index`` and no declarator of its own
    (``argv[]`` and ``argv[1][2]`` are none). ``build_query`` emits the shape, so a grammar
    lacking any of it fails D19's compile."""

    param: str
    array: str
    object: str
    declarator: str
    index: str


@dataclass(frozen=True, slots=True)
class Capture:
    """One ``NODE_MAP`` row (LLD §6.3).

    ``kind`` is what the node ships as; ``None`` makes it TRANSPARENT while its own
    ``fields`` still name the Field its children inherit (W1: C/C++ ``function_declarator``).
    ``fields`` maps a grammar field name to a Field. ``positional`` maps a NAMED-child index
    to a Field for the grammars that give a child no field (Rust ``index_expression`` and
    ``macro_invocation``, PHP ``subscript_expression`` and ``foreach_statement``).

    ``callee_from`` makes the row a synthetic CALL whose callee the grammar puts elsewhere
    (C3, A28 (9): the C++ stack constructor ``std::ifstream in(p.c_str())``): the worker ships
    the node as a CALL whose CALLEE is a copy of the name chain (a NAME or MEMBER) the
    enclosing shipped node holds under that Field — the declaration's type, its ANNOTATION —
    and whose ARGS container is the node itself. Where the enclosing node holds no name chain
    there (``int n(f(x))``: a primitive type ships nothing) the node is transparent. None for
    every other row.

    ``subscript`` narrows a ``callee_from`` row to a node holding ONE parameter of that shape
    (A36): only then is the node the synthetic CALL, its one argument the parameter shipped
    as SUBSCRIPT(NAME, INDEX); any other node ships as the row's own ``kind``.
    """

    kind: Kind | None
    fields: Mapping[str, Field] = EMPTY_MAP
    positional: Mapping[int, Field] = EMPTY_MAP
    callee_from: Field | None = None
    subscript: Subscript | None = None


@dataclass(frozen=True, slots=True)
class Builtin:
    """A language's own builtin sink (LLD §6.3; L9, P4, W5, R5, R7, R9).

    ``families`` REPLACES the word classification of the callee; an EMPTY set makes the
    callee no sink at all (C ``read``/``write``, P4/R5). ``<family>_args`` names the argument
    positions that reach that family's sink, ``"all"`` or a tuple, default ``(0,)``. ``when``
    = ``(position, glued NAME key)``: a sink only when that argument is a NAME whose glued
    text is the key (PHP ``curl_setopt`` with ``CURLOPT_URL``). ``qualifier`` is a PAIR key's
    glued qualifier (W5, written by ``pair``), empty for a single key: the pair is never
    contiguous in source text (``Paths.get``), so the §9.1 prefilter searches for its qualifier.
    """

    families: frozenset[str]
    path_args: Positions = (0,)
    request_args: Positions = (0,)
    command_args: Positions = (0,)
    when: tuple[int, str] | None = None
    qualifier: str = ""

    def __post_init__(self) -> None:
        """``command_args`` names ONE position, the program (§8.5 command row): a profile can
        state nothing the command row would silently read otherwise."""
        if self.command_args == "all" or len(self.command_args) != 1:
            raise ValueError(f"Builtin.command_args is one program position, not {self.command_args!r}")

    def args_for(self, family: str) -> Positions:
        """The positions whose arguments reach ``family``'s sink (``<family>_args``)."""
        return _ARGS_FOR[family](self)

    @property
    def program(self) -> int:
        """The command row's program position (§8.5): a later argument reaches the sink only
        after an R-M interpreter + flag (L3, L7)."""
        return self.command_args[0]  # type: ignore[index]


# A family -> the Builtin field holding its argument positions (an unknown family: KeyError).
_ARGS_FOR: Mapping[str, Callable[[Builtin], Positions]] = MappingProxyType({
    "path": attrgetter("path_args"),
    "request": attrgetter("request_args"),
    "command": attrgetter("command_args"),
})


# L9/W5/R9/R10: a builtin that takes a path on EVERY argument (Java's File constructors,
# Python's os.replace, PHP's copy).
EVERY_ARG_PATH = Builtin(PATH, path_args="all")
# P4/R5: a language global that only shadows a sink word - its EMPTY family set makes the
# callee no sink at all (C's fd and buffer calls, Go's predeclared ``append`` / ``copy``,
# A47 (2) (i)): the one entry every such key shares.
NO_FAMILY = Builtin(frozenset())


@dataclass(frozen=True, slots=True)
class ScopeRules:
    """How bindings are scoped (LLD §6.3, §7.2). ``"*"`` in a keyword set means every
    binding form; R-O's closure reads are not a profile choice.

    The v1 scope pass reads ``functions_hoist`` and the three binding facts below it. The
    first six fields describe the language as §6.3 states it; the v1 pass, one §7.2 pass for
    every language, reads none of them (reserved for the SKILLS.md known gaps)."""

    block_scoped: frozenset[str] = frozenset()
    function_scoped: frozenset[str] = frozenset()
    functions_hoist: bool = True
    module_is_scope: bool = True
    comprehension_scope: bool = False
    global_statement: bool = False
    shadowing_rebinds: bool = False
    # W6: a dotted import binds its FIRST segment (Python `import os.path` binds `os`); else
    # its last (Java `import a.b.File` binds `File`).
    import_binds_first: bool = False
    # W3: an import spec with no name carries its path's last segment as its text (Go).
    import_spec_text: bool = False
    # C2 (R-X): a declaration may parse a stack constructor as a function prototype (C++).
    vexing_parse: bool = False


def cap(kind: Kind | None, positional: Mapping[int, Field] = EMPTY_MAP, **fields: Field) -> Capture:
    """A row: ``cap(Kind.CALL, function=Field.CALLEE, arguments=Field.ARGS)``."""
    return Capture(kind, MappingProxyType(fields), MappingProxyType(dict(positional)))


def pair(qualifier: str, callee: str, builtin: Builtin) -> dict[str, Builtin]:
    """W5: a glued PAIR builtin, ``glue(qualifier) + glue(callee)`` (``pair("paths", "get", ...)``
    is Java ``Paths.get``), carrying its qualifier: the one place a pair's parts are written."""
    return {qualifier + callee: replace(builtin, qualifier=qualifier)}


def rows(row: Capture, *node_types: NodeKey) -> dict[NodeKey, Capture]:
    """The same row for several node types (one table line of LLD §6.3)."""
    return dict.fromkeys(node_types, row)


# ── the rows several grammars spell the same way (D19) ───────────────────────
LOOP_BODY = cap(Kind.LOOP, body=Field.BODY)
IF_ROW = cap(Kind.IF, condition=Field.TEST, consequence=Field.CONSEQ, alternative=Field.ALT)
CALL_FA = cap(Kind.CALL, function=Field.CALLEE, arguments=Field.ARGS)
FUNCTION_ROW = cap(Kind.FUNCTION, name=Field.NAME, parameters=Field.PARAMS, body=Field.BODY)
LAMBDA_ROW = cap(Kind.FUNCTION, parameters=Field.PARAMS, body=Field.BODY)
CLASS_ROW = cap(Kind.CLASS, name=Field.NAME, body=Field.BODY)
ASSIGN_LR = cap(Kind.ASSIGN, left=Field.LHS, right=Field.RHS)
ASSIGN_NV = cap(Kind.ASSIGN, name=Field.LHS, value=Field.RHS)
AUG_ASSIGN_LR = cap(Kind.AUG_ASSIGN, left=Field.LHS, right=Field.RHS)
PAIR_KV = cap(Kind.PAIR, key=Field.KEY, value=Field.VALUE)
TRY_BODY = cap(Kind.TRY, body=Field.BODY)


@dataclass(frozen=True, slots=True)
class LanguageProfile:
    """One v1 language (LLD §6.3), keyed by its ``shared.language`` name (D19).

    ``builtin_sinks`` keys are glued (L1 (a)): one glued identifier, or a glued PAIR
    ``glue(qualifier) + glue(callee)`` probed before the single key (W5). ``builtin_sources``
    maps the language's own superglobals to their role. ``synthetic_calls`` maps a grammar
    type that is a call in disguise to its glued synthetic callee key (``""``: the callee is
    the node's own CALLEE field); the worker ships a keyed type as a CALL whose CALLEE is a
    NAME carrying the key and whose ARGS container is the node, its children the positional
    arguments (A42 (2)), so the type also needs its ``node_map`` row for D19's grammar check.
    ``arm_types`` are the switch/match arm types (L10).
    ``owned_families`` limits what the AST tier owns on the language (D-H: no SSRF on C/C++).
    ``disabled_until`` is the grammar version §6.4 holds the profile back until: while it is
    set, ``profile_for`` answers no profile, so every file of the language is regex-owned.
    ``grammar_variants`` maps a lower-case file suffix to the entry point of
    ``grammar_module`` that parses it instead of ``grammar_attr`` (§6.3: ``.tsx`` is parsed
    with ``language_tsx``); the ``node_map`` holds for every variant.

    The flow pass's language facts (§6.4: a language is one file under ``profiles/``):
    ``block_value`` - a function body's last expression is its value (Rust, no ``return``);
    ``receiver_list`` - a method's receiver list is its first PARAMS holder, before its
    parameters (Go, A3); ``reference_args`` - an argument can take a reference (``&x``) a
    call writes through (R-W, A28 (7): Go and Rust); ``main_argv`` - the entry function's
    name and its argv PARAM's position (C4: C and C++); ``export_chains`` - the chain heads
    whose assignment exports a value (CommonJS ``exports.x``, ``module.exports[.x]``): a
    language with any also exports by an ``export`` statement, and either makes a function an
    ENTRY (A47 D23-d: JavaScript and TypeScript);
    ``public_name`` - whether a top-level declared name is public, so an outside caller can
    reach it (A47 D23-d: Python no leading ``_``, Go an upper-case initial; elsewhere any
    name, ``bool``: an anonymous function has none).
    """

    language: str
    grammar_module: str
    grammar_attr: str
    node_map: Mapping[NodeKey, Capture]
    scope_rules: ScopeRules
    call_shape: CallShape = "function"
    browser_capable: bool = False
    builtin_sources: Mapping[str, str] = EMPTY_MAP
    builtin_sinks: Mapping[str, Builtin] = EMPTY_MAP
    synthetic_calls: Mapping[str, str] = EMPTY_MAP
    owned_families: frozenset[str] = ALL_FAMILIES
    arm_types: frozenset[str] = frozenset()
    disabled_until: str | None = None
    pruned: frozenset[str] = frozenset()
    grammar_variants: Mapping[str, str] = EMPTY_MAP
    block_value: bool = False
    receiver_list: bool = False
    reference_args: bool = False
    main_argv: tuple[str, int] | None = None
    export_chains: frozenset[tuple[str, ...]] = frozenset()
    public_name: Callable[[str], bool] = bool

    def grammar_for(self, path: str | PurePath) -> str:
        """The grammar entry point that parses ``path``: its suffix's variant, else the
        profile's own (one O(1) probe)."""
        return self.grammar_variants.get(PurePath(path).suffix.lower(), self.grammar_attr)

    @property
    def grammar_attrs(self) -> tuple[str, ...]:
        """Every entry point the profile parses with: its own, then each variant."""
        return (self.grammar_attr, *self.grammar_variants.values())
