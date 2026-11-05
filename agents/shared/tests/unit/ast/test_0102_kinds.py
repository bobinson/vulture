"""Feature 0102 (D4, D19, LLD §6.1-§6.3): the closed kind and field sets, and the
language profiles as tables from which every tree-sitter query is generated.

The parse worker ships a node only through a profile's ``NODE_MAP``: a grammar
type the table maps ships as its ``Capture``; a type the table does not list is
TRANSPARENT (its shipped descendants are re-parented and inherit the Field of
the outermost transparent ancestor); a ``PRUNED`` type is dropped with its
subtree; an unmapped node under a field mapped to ARGS or PARAMS ships as the
ARGS container (W1). Because the disposition is read from the table alone,
these tests check the tables against the INSTALLED grammars — every node type
and field name exists, the generated query compiles — so a grammar bump that
renames a node or a field fails here, not as a silent loss of coverage.

The test process may import ``tree_sitter``; the library's parent-side modules
never do (``test_profile_tables_load_no_parser``, D1).

Profile builtins (L1 (a), L9, W5, P4, R5, R7, R9) are pinned as table facts:
a ``builtin_sinks`` entry is read through ``families`` (its family set; empty
means "no sink"), ``path_args`` / ``request_args`` (``"all"`` or a tuple of
argument positions, default ``(0,)``) and ``when`` (``None`` or
``(position, glued NAME key)``).
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import tree_sitter

import shared.ast
from shared.ast import profile as profile_module
from shared.ast.kinds import Field, Kind
from shared.ast.model import owns_lang
from shared.ast.profile import (
    GRAMMAR_PROFILES,
    PROFILES,
    Capture,
    LanguageProfile,
    build_query,
    profile_for,
)
from shared.language import detect_language
from tests.support.fresh_import import loaded_after_import
from tests.unit.ast._support import GRAMMARS, LANGUAGES, TSX_GRAMMAR, grammar, profile_grammar

# ── The closed sets (LLD §6.1) ───────────────────────────────────────────────

KIND_NAMES = frozenset(
    "MODULE FUNCTION CLASS PARAM BLOCK IF LOOP TRY CATCH FINALLY WITH RETURN THROW JUMP"
    " ASSIGN AUG_ASSIGN CALL MEMBER SUBSCRIPT NAME LITERAL TEMPLATE BINOP UNARY TERNARY"
    " AWAIT SPREAD DESTRUCT IMPORT EXPORT DECORATOR ARGS KWARG OBJECT ARRAY PAIR YIELD"
    " GLOBAL COMPREHENSION ERROR OTHER".split()
)
FIELD_NAMES = frozenset(
    "CALLEE ARGS LHS RHS NAME VALUE BODY TEST CONSEQ ALT PARAMS OBJECT PROPERTY INDEX"
    " TARGET ITER SOURCE KEY HANDLER ANNOTATION NONE".split()
)

# ── The nine v1 profiles (D-D, D-H): LANGUAGES and their GRAMMARS (LLD §6.3), in _support ──

PROFILE_ATTRIBUTES = (
    "language", "grammar_module", "grammar_attr", "node_map", "scope_rules", "call_shape",
    "browser_capable", "builtin_sources", "builtin_sinks", "synthetic_calls",
    "owned_families", "arm_types", "disabled_until", "pruned",
)
ALL_FAMILIES = frozenset({"path", "request", "command"})
OWNED_FAMILIES = {name: ALL_FAMILIES for name in LANGUAGES} | {
    "c": frozenset({"path", "command"}),  # D-H: SSRF stays regex-owned on C/C++
    "cpp": frozenset({"path", "command"}),
}

# L10: the switch/match/case arm types, shipped as BLOCK {CONSEQ}.
ARMS: dict[str, frozenset[str]] = {
    "javascript": frozenset({"switch_case", "switch_default"}),
    "typescript": frozenset({"switch_case", "switch_default"}),
    "python": frozenset({"case_clause"}),
    "go": frozenset({"expression_case", "type_case", "communication_case", "default_case"}),
    "java": frozenset({"switch_block_statement_group", "switch_rule"}),
    "rust": frozenset({"match_arm"}),
    "php": frozenset({
        "case_statement", "default_statement",
        "match_conditional_expression", "match_default_expression",
    }),
    "c": frozenset({"case_statement"}),
    "cpp": frozenset({"case_statement"}),
}
# L10 / §6.3: the switch and match nodes the tables list as OTHER (the arms' owners).
SWITCHES = (
    ("javascript", "switch_statement"), ("typescript", "switch_statement"),
    ("python", "match_statement"), ("go", "expression_switch_statement"),
    ("go", "select_statement"), ("java", "switch_expression"), ("rust", "match_expression"),
    ("php", "match_expression"), ("c", "switch_statement"), ("cpp", "switch_statement"),
)

# W1 + the §6.3 "transparent" cells + C4: unlisted wrappers, never shipped and
# never pruned (pruning would drop the expressions and declarators inside them).
TRANSPARENT = (
    ("javascript", "parenthesized_expression"),
    ("typescript", "as_expression"), ("typescript", "satisfies_expression"),
    ("typescript", "non_null_expression"),
    ("python", "decorated_definition"), ("python", "type"),
    ("python", "parenthesized_expression"), ("python", "expression_list"),
    ("go", "statement_list"), ("go", "expression_list"), ("go", "pointer_type"),
    ("go", "slice_type"), ("go", "map_type"), ("go", "generic_type"),
    ("go", "parenthesized_expression"),
    ("java", "modifiers"), ("java", "generic_type"), ("java", "cast_expression"),
    ("java", "parenthesized_expression"), ("java", "local_variable_declaration"),
    ("rust", "match_block"), ("rust", "generic_type"), ("rust", "try_expression"),
    ("rust", "parenthesized_expression"),
    ("php", "argument"), ("php", "named_type"), ("php", "parenthesized_expression"),
    ("php", "text_interpolation"),
    ("c", "pointer_declarator"), ("c", "array_declarator"), ("c", "cast_expression"),
    ("c", "parenthesized_expression"),
    ("cpp", "pointer_declarator"), ("cpp", "array_declarator"),
    ("cpp", "reference_declarator"), ("cpp", "subscript_argument_list"),
    ("cpp", "template_declaration"),
)
# W3: scoped / qualified names ship as a text-less MEMBER chain.
COMPOUND_NAMES = (
    ("rust", "scoped_identifier"), ("rust", "scoped_type_identifier"),
    ("java", "scoped_identifier"), ("java", "scoped_type_identifier"),
    ("cpp", "qualified_identifier"), ("php", "qualified_name"), ("php", "namespace_name"),
    ("python", "dotted_name"), ("go", "qualified_type"),
)
# W3: type names ship as NAME (where the analysis reads them).
TYPE_NAMES = (
    ("go", "type_identifier"), ("java", "type_identifier"), ("rust", "type_identifier"),
    ("c", "type_identifier"), ("cpp", "type_identifier"), ("cpp", "namespace_identifier"),
)
# §6.3: grammar nodes that are calls in disguise.
SYNTHETIC_CALLS = (
    ("php", "include_expression"), ("php", "include_once_expression"),
    ("php", "require_expression"), ("php", "require_once_expression"),
    ("php", "shell_command_expression"), ("rust", "macro_invocation"),
)

# Row tables: (parent type, type) -> the Kind the row ships as. Parent "" names
# a type outside every parent-keyed row, so the lookup falls to the plain key.
# JS and TS share their plain rows (W6). Their parameter rows differ with the
# grammar: tree-sitter-javascript puts identifiers and patterns DIRECTLY under
# ``formal_parameters``; tree-sitter-typescript wraps each in a
# ``required_parameter``/``optional_parameter`` (a direct JS-style row is an
# impossible pattern there, and the TS wrappers do not exist in JS).
JS_TS_PLAIN_ROWS: dict[tuple[str, str], Kind | None] = {
    ("variable_declarator", "object_pattern"): Kind.DESTRUCT,  # W6
    ("variable_declarator", "array_pattern"): Kind.DESTRUCT,
    ("object_pattern", "rest_pattern"): Kind.SPREAD,
    ("member_expression", "identifier"): Kind.NAME,
    ("", "pair_pattern"): Kind.PAIR,
    ("", "import_specifier"): Kind.PAIR,
}
JS_TS_PLAIN_FIELDS: dict[tuple[str, str], dict[str, Field]] = {
    ("", "pair_pattern"): {"key": Field.KEY, "value": Field.VALUE},
    ("", "import_specifier"): {"name": Field.KEY, "alias": Field.VALUE},  # W6
}
_JS_PARAMS = ("identifier", "object_pattern", "array_pattern", "rest_pattern", "assignment_pattern")
JS_PARAM_ROWS: dict[tuple[str, str], Kind | None] = {
    ("formal_parameters", t): Kind.PARAM for t in _JS_PARAMS  # W1: direct children only
}
JS_PARAM_FIELDS = {("formal_parameters", "assignment_pattern"): {"left": Field.NAME, "right": Field.VALUE}}
# W7 also names ``decorator`` for these rows, but DECORATOR is a Kind, not one of the
# 21 Fields (§6.1), so which Field the decorator child carries is left to the table.
_TS_PARAM_FIELDS = {"pattern": Field.NAME, "type": Field.ANNOTATION, "value": Field.VALUE}
TS_PARAM_ROWS: dict[tuple[str, str], Kind | None] = {
    ("formal_parameters", "required_parameter"): Kind.PARAM,  # W7
    ("formal_parameters", "optional_parameter"): Kind.PARAM,
}
TS_PARAM_FIELDS = {key: _TS_PARAM_FIELDS for key in TS_PARAM_ROWS}
_PY_PATTERNS = ("pattern_list", "tuple_pattern", "list_pattern")
PY_ROWS: dict[tuple[str, str], Kind | None] = {
    ("parameters", "identifier"): Kind.PARAM,
    ("parameters", "list_splat_pattern"): Kind.PARAM,
    ("parameters", "default_parameter"): Kind.PARAM,
    ("parameters", "typed_default_parameter"): Kind.PARAM,
    ("parameters", "typed_parameter"): Kind.PARAM,
    **{("", t): Kind.DESTRUCT for t in _PY_PATTERNS},
    **{(t, "list_splat_pattern"): Kind.SPREAD for t in _PY_PATTERNS},  # W6: `a, *rest = x`
    ("call", "identifier"): Kind.NAME,
    ("", "aliased_import"): Kind.PAIR,
}
PY_FIELDS: dict[tuple[str, str], dict[str, Field]] = {
    ("parameters", "default_parameter"): {"name": Field.NAME, "value": Field.VALUE},  # W7
    ("parameters", "typed_default_parameter"): {
        "name": Field.NAME, "type": Field.ANNOTATION, "value": Field.VALUE,
    },
    ("parameters", "typed_parameter"): {"type": Field.ANNOTATION},
    ("", "aliased_import"): {"name": Field.KEY, "alias": Field.VALUE},  # W6
}
# W1/C4: function_declarator is transparent WITH its own field map.
C_DECLARATOR_ROWS: dict[tuple[str, str], Kind | None] = {("", "function_declarator"): None}
C_DECLARATOR_FIELDS = {
    ("", "function_declarator"): {"declarator": Field.NAME, "parameters": Field.PARAMS},
}
# W15 (e): tree-sitter-cpp names the subscript fields argument / indices.
CPP_SUBSCRIPT_ROWS: dict[tuple[str, str], Kind | None] = {("", "subscript_expression"): Kind.SUBSCRIPT}
CPP_SUBSCRIPT_FIELDS = {
    ("", "subscript_expression"): {"argument": Field.OBJECT, "indices": Field.INDEX},
}
ROW_TABLES = {
    "javascript-patterns": ("javascript", JS_TS_PLAIN_ROWS, JS_TS_PLAIN_FIELDS),
    "typescript-patterns": ("typescript", JS_TS_PLAIN_ROWS, JS_TS_PLAIN_FIELDS),
    "javascript-parameters": ("javascript", JS_PARAM_ROWS, JS_PARAM_FIELDS),
    "typescript-parameters": ("typescript", TS_PARAM_ROWS, TS_PARAM_FIELDS),
    "python-parameters-patterns-imports": ("python", PY_ROWS, PY_FIELDS),
    "c-function-declarator": ("c", C_DECLARATOR_ROWS, C_DECLARATOR_FIELDS),
    "cpp-function-declarator": ("cpp", C_DECLARATOR_ROWS, C_DECLARATOR_FIELDS),
    "cpp-subscript": ("cpp", CPP_SUBSCRIPT_ROWS, CPP_SUBSCRIPT_FIELDS),
}

GLUED_KEY = re.compile(r"^[a-z0-9]{2,32}$")  # L1 (a): lowercase, no "_" or "$"; §9.1 entry shape
CAPTURE_NAME = re.compile(r"@([\w.]+)")

# ── Helpers ──────────────────────────────────────────────────────────────────


def _pair_ids(pairs: tuple[tuple[str, str], ...]) -> list[str]:
    """``language-node_type`` test ids for a table of pairs."""
    return [f"{language}-{node_type}" for language, node_type in pairs]


def _profile(language: str) -> LanguageProfile:
    """``PROFILES[language]``, failing the test (not collection) when absent."""
    assert language in PROFILES, f"no {language} profile in {sorted(PROFILES)}"
    return PROFILES[language]


def _node_types(key: str | tuple[str, str]) -> tuple[str, ...]:
    """Both members of a ``(parent type, type)`` key, or the one plain type."""
    return key if isinstance(key, tuple) else (key,)


def _entries_for(p: LanguageProfile, node_type: str) -> list[Capture]:
    """Every Capture keyed by ``node_type``, plain or under a parent (W1)."""
    return [cap for key, cap in p.node_map.items() if _node_types(key)[-1] == node_type]


def _kinds_for(p: LanguageProfile, node_type: str) -> set[Kind | None]:
    """The kinds ``node_type`` can ship as in profile ``p``."""
    return {cap.kind for cap in _entries_for(p, node_type)}


def _kinds_by_type(p: LanguageProfile, node_types: Iterable[str]) -> dict[str, set[Kind | None]]:
    """Node type -> the kinds it can ship as."""
    return {node_type: _kinds_for(p, node_type) for node_type in node_types}


def _capture_under(p: LanguageProfile, parent_type: str, node_type: str) -> Capture | None:
    """W1: a ``(parent, type)`` key wins for a direct child; else the plain key."""
    pair = p.node_map.get((parent_type, node_type))
    return pair if pair is not None else p.node_map.get(node_type)


def _row_kinds(p: LanguageProfile, rows: Iterable[tuple[str, str]]) -> dict[tuple[str, str], Kind | None]:
    """(parent, type) -> the kind the profile ships that child as."""
    return {row: getattr(_capture_under(p, *row), "kind", None) for row in rows}


def _maps_fields(p: LanguageProfile, row: tuple[str, str], expected: Mapping[str, Field]) -> bool:
    """The row's Capture maps at least the ``expected`` grammar fields."""
    actual = dict(getattr(_capture_under(p, *row), "fields", {}))
    return actual.items() >= dict(expected).items()


def _field_gaps(
    p: LanguageProfile, table: Mapping[tuple[str, str], Mapping[str, Field]]
) -> dict[tuple[str, str], object]:
    """Row -> the field map it actually has, for every row missing an expected field."""
    return {
        row: dict(getattr(_capture_under(p, *row), "fields", {}))
        for row, expected in table.items()
        if not _maps_fields(p, row, expected)
    }


def _is_transparent(p: LanguageProfile, node_type: str) -> bool:
    """Not shipped (no kind-bearing entry) and not pruned (W1 rule 4)."""
    return _kinds_for(p, node_type) <= {None} and node_type not in p.pruned


def _has_node(lang: tree_sitter.Language, node_type: str) -> bool:
    """The installed grammar knows ``node_type`` as a named node."""
    return lang.id_for_node_kind(node_type, True) is not None


def _missing_nodes(lang: tree_sitter.Language, node_types: Iterable[str]) -> list[str]:
    """The node types the grammar does not know."""
    return [node_type for node_type in node_types if not _has_node(lang, node_type)]


def _unknown_types(p: LanguageProfile, lang: tree_sitter.Language) -> list[str]:
    """Every node type of a ``node_map`` key (both pair members) ``lang`` lacks."""
    return _missing_nodes(lang, [t for key in p.node_map for t in _node_types(key)])


def _unknown_fields(p: LanguageProfile, lang: tree_sitter.Language) -> list[tuple[object, str]]:
    """(key, field) for every mapped grammar field ``lang`` does not define."""
    return [
        (key, name)
        for key, cap in p.node_map.items()
        for name in cap.fields
        if lang.field_id_for_name(name) is None
    ]


def _is_well_formed_key(key: object) -> bool:
    """A type, or a ``(parent type, type)`` pair of strings."""
    types = _node_types(key) if isinstance(key, (str, tuple)) else ()
    return len(types) in (1, 2) and all(isinstance(t, str) for t in types)


def _is_field_map(fields: Mapping[object, object]) -> bool:
    """Grammar field name -> Field."""
    return all(isinstance(k, str) and isinstance(v, Field) for k, v in fields.items())


def _is_capture(cap: object) -> bool:
    """A Capture whose kind is a Kind or None and whose fields are a field map."""
    if not isinstance(cap, Capture):
        return False
    return (cap.kind is None or isinstance(cap.kind, Kind)) and _is_field_map(cap.fields)


def _malformed_rows(p: LanguageProfile) -> list[object]:
    """Every ``node_map`` key whose key or Capture is malformed."""
    return [key for key, cap in p.node_map.items() if not (_is_well_formed_key(key) and _is_capture(cap))]


def _missing_attributes(p: LanguageProfile) -> list[str]:
    """The ``LanguageProfile`` attributes ``p`` lacks."""
    return [attr for attr in PROFILE_ATTRIBUTES if not hasattr(p, attr)]


def _capture_names(query: tree_sitter.Query) -> set[str]:
    """The distinct capture names of a compiled query."""
    return {query.capture_name(i) for i in range(query.capture_count)}


def _shipped_kinds(p: LanguageProfile) -> list[Kind]:
    """The kind of every row that ships a node (``kind=None`` rows excluded)."""
    return [cap.kind for cap in p.node_map.values() if cap.kind is not None]


def _is_kind_or_kind_field(name: str) -> bool:
    """A capture name of the form ``kind`` or ``kind.field``."""
    kind, _, fld = name.partition(".")
    return kind.upper() in Kind.__members__ and (not fld or fld.upper() in Field.__members__)


def _builtin(p: LanguageProfile, key: str) -> Any:
    """One ``builtin_sinks`` entry, failing with the keys the profile has."""
    assert key in p.builtin_sinks, f"{p.language}: no builtin {key!r} in {sorted(p.builtin_sinks)}"
    return p.builtin_sinks[key]


def _position_tuple(value: object) -> bool:
    """A non-empty tuple of argument positions."""
    return isinstance(value, tuple) and len(value) > 0 and all(_is_position(i) for i in value)


def _is_positions(value: object) -> bool:
    """``"all"`` or a non-empty tuple of argument positions (L9, P4)."""
    return value == "all" or _position_tuple(value)


def _is_position(value: object) -> bool:
    """A non-negative ``int`` argument position (never a bool)."""
    return type(value) is int and value >= 0


def _is_condition(when: object) -> bool:
    """``None`` or ``(position, glued NAME key)`` (W5)."""
    if when is None:
        return True
    return isinstance(when, tuple) and len(when) == 2 and _is_glued_position_key(when)


def _is_glued_position_key(when: tuple[object, object]) -> bool:
    """The two members of a ``when``: an argument position and a glued key."""
    return _is_position(when[0]) and isinstance(when[1], str) and bool(GLUED_KEY.match(when[1]))


def _is_builtin(entry: Any) -> bool:
    """A family set within the three families, positions and a condition."""
    positions = _is_positions(entry.path_args) and _is_positions(entry.request_args)
    return set(entry.families) <= ALL_FAMILIES and positions and _is_condition(entry.when)


def _malformed_builtins(p: LanguageProfile) -> list[str]:
    """The builtin keys whose entry is malformed."""
    return [key for key, entry in p.builtin_sinks.items() if not _is_builtin(entry)]


def _families_and_positions(entry: Any) -> tuple[frozenset[str], object]:
    """An entry's family set and its path positions, for one comparison."""
    return frozenset(entry.families), entry.path_args


def _captures(query_text: str, language: str, source: bytes) -> dict[str, list[bytes]]:
    """Capture name -> captured node texts, for ``query_text`` over ``source``."""
    lang = profile_grammar(_profile(language))
    tree = tree_sitter.Parser(lang).parse(source)
    found = tree_sitter.QueryCursor(tree_sitter.Query(lang, query_text)).captures(tree.root_node)
    return {name: [node.text for node in nodes] for name, nodes in found.items()}


# ── The W1 disposition, read from the table alone ────────────────────────────
#
# A reference walk of one parse tree that applies W1's rules using nothing but
# the profile's tables: the (parent, type) key wins; a kind-bearing Capture
# ships; an unmapped node under an ARGS/PARAMS field is the ARGS container; a
# PRUNED type drops its subtree; anything else is transparent, its children
# inheriting the field the outermost transparent ancestor was captured under
# (or the transparent entry's own field map). Only named children ship.


@dataclass(slots=True)
class _Shipped:
    """One shipped node: its grammar type, Kind, Field and shipped children."""

    type: str
    kind: Kind
    field: Field
    children: list[_Shipped] = field(default_factory=list)


_CONTAINER_FIELDS = (Field.ARGS, Field.PARAMS)


def _resolve(p: LanguageProfile, node_type: str, parent_type: str, fld: Field) -> Capture:
    """The Capture a node ships as; ``Capture(None)`` means transparent."""
    cap = _capture_under(p, parent_type, node_type)
    if cap is None and fld in _CONTAINER_FIELDS:
        return Capture(Kind.ARGS)
    return cap if cap is not None else Capture(None)


def _child_field(
    fields: Mapping[str, Field], node: tree_sitter.Node, i: int, inherited: Field
) -> Field:
    """The Field child ``i`` of ``node`` is shipped under."""
    own = fields.get(node.field_name_for_child(i) or "")
    return inherited if own is None else own


def _ship_children(
    p: LanguageProfile,
    node: tree_sitter.Node,
    fields: Mapping[str, Field],
    inherited: Field,
    out: list[_Shipped],
) -> None:
    """Ship every named child of ``node`` into ``out``."""
    for i, child in enumerate(node.children):
        if child.is_named:
            _ship(p, child, node.type, _child_field(fields, node, i, inherited), out)


def _ship(
    p: LanguageProfile, node: tree_sitter.Node, parent_type: str, fld: Field, out: list[_Shipped]
) -> None:
    """Append ``node``'s shipped form — or, when transparent, its shipped descendants."""
    if node.type in p.pruned:
        return
    cap = _resolve(p, node.type, parent_type, fld)
    if cap.kind is None:
        _ship_children(p, node, cap.fields, fld, out)
        return
    shipped = _Shipped(node.type, cap.kind, fld)
    out.append(shipped)
    _ship_children(p, node, cap.fields, Field.NONE, shipped.children)


def _shipped_tree(language: str, source: bytes) -> _Shipped:
    """The shipped skeleton of ``source`` under the ``language`` profile."""
    p = _profile(language)
    out: list[_Shipped] = []
    _ship(p, tree_sitter.Parser(profile_grammar(p)).parse(source).root_node, "", Field.NONE, out)
    assert [s.kind for s in out] == [Kind.MODULE], [(s.type, s.kind) for s in out]
    return out[0]


def _walk(node: _Shipped) -> Iterator[_Shipped]:
    """Every shipped node under ``node``, document order."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _shipped_types(root: _Shipped) -> set[str]:
    """The grammar types of every shipped node."""
    return {node.type for node in _walk(root)}


def _first(root: _Shipped, kind: Kind) -> _Shipped:
    """The first shipped node of ``kind``."""
    found = next((n for n in _walk(root) if n.kind is kind), None)
    assert found is not None, f"no {kind.name} in {[(n.type, n.kind.name) for n in _walk(root)]}"
    return found


def _child(node: _Shipped, fld: Field) -> _Shipped:
    """The shipped child of ``node`` under ``fld``."""
    found = next((c for c in node.children if c.field is fld), None)
    assert found is not None, f"{node.type}: no {fld.name} child in {node.children}"
    return found


def _head(node: _Shipped) -> tuple[str, Kind, list[tuple[str, Kind]]]:
    """A node's type and kind with its children's, for one comparison."""
    return node.type, node.kind, [(c.type, c.kind) for c in node.children]


def _disposition_expression_statement_everywhere() -> None:
    """``expression_statement`` exists in every grammar and is transparent in
    EVERY profile (W1: Java, Rust and PHP no longer map it to OTHER)."""
    found = {p.language: (_has_node(profile_grammar(p), "expression_statement"),
                          _is_transparent(p, "expression_statement")) for p in PROFILES.values()}
    assert found == dict.fromkeys(LANGUAGES, (True, True)), found


def _disposition_python_exit_call() -> None:
    """``if x:\\n    abort(1)``: the CONSEQ is a BLOCK whose first child is the
    CALL (the ``expression_statement`` between them is transparent) — the shape
    W2's ``exits`` reads for a Python exit-call consequence."""
    conseq = _child(_first(_shipped_tree("python", b"if x:\n    abort(1)\n"), Kind.IF), Field.CONSEQ)
    assert _head(conseq)[1:] == (Kind.BLOCK, [("call", Kind.CALL)]), _head(conseq)


def _disposition_go_block() -> None:
    """A Go ``block``'s statements are its DIRECT BLOCK children: the grammar's
    ``statement_list`` wrapper is transparent."""
    root = _shipped_tree("go", b"package m\n\nfunc f() {\n\ta := 1\n\tg(a)\n}\n")
    body = _child(_first(root, Kind.FUNCTION), Field.BODY)
    expected = ("block", Kind.BLOCK, [("short_var_declaration", Kind.ASSIGN), ("call_expression", Kind.CALL)])
    assert _head(body) == expected, _head(body)
    assert "statement_list" not in _shipped_types(root)


def _disposition_js_patterns() -> None:
    """``const {a} = x``: the LHS is DESTRUCT; ``function f({a})``: the same
    ``object_pattern`` is a PARAM, because the ``(formal_parameters, type)``
    key wins for a direct child of ``formal_parameters``."""
    root = _shipped_tree("javascript", b"const {a} = x;\nfunction f({a}) {}\n")
    lhs = _child(_first(root, Kind.ASSIGN), Field.LHS)
    params = _child(_first(root, Kind.FUNCTION), Field.PARAMS)
    assert (lhs.type, lhs.kind) == ("object_pattern", Kind.DESTRUCT), lhs
    assert _head(params)[1:] == (Kind.ARGS, [("object_pattern", Kind.PARAM)]), _head(params)


def _disposition_php_argument() -> None:
    """``f($x)``: the call's arg 0 is the expression itself, not the grammar's
    ``argument`` wrapper — ``arguments`` is the ARGS container and ``argument``
    is transparent, so argument positions never shift."""
    root = _shipped_tree("php", b"<?php\nf($x);\n")
    args = _child(_first(root, Kind.CALL), Field.ARGS)
    assert _head(args)[1:] == (Kind.ARGS, [("variable_name", Kind.NAME)]), _head(args)
    assert "argument" not in _shipped_types(root)


DISPOSITION_CASES: dict[str, Callable[[], None]] = {
    "expression-statement-transparent": _disposition_expression_statement_everywhere,
    "python-exit-call-consequence": _disposition_python_exit_call,
    "go-block-statements": _disposition_go_block,
    "js-destruct-vs-param": _disposition_js_patterns,
    "php-argument-wrapper": _disposition_php_argument,
}


# ── Kinds and fields ─────────────────────────────────────────────────────────


def test_closed_sets() -> None:
    """41 kinds, 21 fields; OTHER is the largest kind (the passthrough, D4)."""
    assert len(Kind) == 41 and len(Field) == 21 and Kind.OTHER == max(Kind)


def test_kind_and_field_names_are_the_lld_sets() -> None:
    """The member names are exactly LLD §6.1's."""
    assert set(Kind.__members__) == KIND_NAMES, set(Kind.__members__) ^ KIND_NAMES
    assert set(Field.__members__) == FIELD_NAMES, set(Field.__members__) ^ FIELD_NAMES


@pytest.mark.parametrize("enum", [Kind, Field], ids=["Kind", "Field"])
def test_members_are_distinct_ints(enum: type[Kind] | type[Field]) -> None:
    """Each member is a distinct int: the worker ships ``kind[]``/``field[]`` as
    parallel int arrays and the validator range-checks them (§6.2)."""
    values = {int(member) for member in enum if isinstance(member, int)}
    assert len(values) == len(enum), list(enum)


def test_model_schema_is_two() -> None:
    """The worker document is ``schema=2`` (§6.2; A28 (9) bumped it for the C3 synthetic
    CALL), part of the cache key (D5)."""
    assert shared.ast.MODEL_SCHEMA == 2


# ── Profile structure ────────────────────────────────────────────────────────


def test_profiles_are_the_nine_v1_languages() -> None:
    """One profile per v1 language, keyed by its ``shared.language`` name (D19)."""
    assert {name: p.language for name, p in PROFILES.items()} == {name: name for name in LANGUAGES}


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_language_profile_carries_every_table(p: LanguageProfile) -> None:
    """Every profile exposes the full ``LanguageProfile`` surface (LLD §5, §6.3, W1)."""
    assert _missing_attributes(p) == []


@pytest.mark.parametrize("language", LANGUAGES)
def test_profile_names_its_installed_grammar(language: str) -> None:
    """Each profile names the grammar wheel and entry point §6.3 gives it, and
    that grammar loads under the installed tree-sitter core."""
    p = _profile(language)
    assert (p.grammar_module, p.grammar_attr) == GRAMMARS[language]
    assert isinstance(profile_grammar(p), tree_sitter.Language)


def test_capture_is_a_frozen_slotted_row() -> None:
    """``Capture`` is an immutable table row (§6.3): frozen, slotted, empty field
    map by default, and ``kind=None`` admitted (W1: transparent with fields)."""
    row = Capture(Kind.NAME)
    transparent = Capture(None, MappingProxyType({"declarator": Field.NAME}))
    assert dataclasses.is_dataclass(Capture) and "__slots__" in vars(Capture)
    assert (row.kind, dict(row.fields), transparent.kind) == (Kind.NAME, {}, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        row.kind = Kind.CALL  # type: ignore[misc]


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_node_map_rows_are_well_formed(p: LanguageProfile) -> None:
    """Keys are a type or a ``(parent type, type)`` pair; values are Captures
    whose kind is a Kind or None and whose field map is grammar name -> Field."""
    assert _malformed_rows(p) == []


# ── The tables against the installed grammars (LLD §6.3, D19) ───────────────


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_node_map_types_and_fields_exist(p: LanguageProfile) -> None:
    """Every node type — both members of a ``(parent, type)`` key (W1) — and
    every field name a profile maps exists in its installed grammar."""
    lang = profile_grammar(p)
    assert _unknown_types(p, lang) == [], p.language
    assert _unknown_fields(p, lang) == [], p.language


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_generated_query_compiles(p: LanguageProfile) -> None:
    """``build_query`` emits one pattern per entry, captured as its kind, and the
    result compiles against the grammar.

    ``Query.capture_count`` counts DISTINCT capture names, and many entries share
    one (every NAME row captures ``@name``), so the per-entry claim is made on
    ``pattern_count``; every kind a row ships as must appear as a capture name.
    A ``kind=None`` row (transparent with fields, W1) needs no capture of its own.
    """
    query = tree_sitter.Query(profile_grammar(p), build_query(p.node_map))
    shipped = _shipped_kinds(p)
    assert query.pattern_count >= len(shipped), (query.pattern_count, len(shipped))
    assert {kind.name.lower() for kind in shipped} <= _capture_names(query)


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_every_capture_name_is_kind_or_kind_field(p: LanguageProfile) -> None:
    """Capture names are ``kind`` or ``kind.field`` — the worker's only vocabulary."""
    names = CAPTURE_NAME.findall(build_query(p.node_map))
    assert [name for name in names if not _is_kind_or_kind_field(name)] == []


def test_javascript_and_typescript_share_their_plain_rows() -> None:
    """JS and TS share one table (§6.3): every plain JavaScript row is a
    TypeScript row with the same Capture. Only the ``(parent, type)`` parameter
    rows differ, because the two grammars shape ``formal_parameters`` differently
    (``JS_PARAM_ROWS`` / ``TS_PARAM_ROWS``)."""
    js, ts = _profile("javascript"), _profile("typescript")
    plain = {key: cap for key, cap in js.node_map.items() if isinstance(key, str)}
    assert plain.items() <= dict(ts.node_map).items()


def test_tsx_grammar_knows_the_typescript_map() -> None:
    """The typescript table also holds for ``language_tsx``, the grammar a
    ``.tsx``/``.jsx`` file is parsed with: every type exists, the query compiles."""
    ts, tsx = _profile("typescript"), grammar(*TSX_GRAMMAR)
    assert _unknown_types(ts, tsx) == []
    tree_sitter.Query(tsx, build_query(ts.node_map))


@pytest.mark.parametrize(
    ("path", "language", "attr"),
    [
        ("x/component.tsx", "typescript", TSX_GRAMMAR[1]),
        ("x/COMPONENT.TSX", "typescript", TSX_GRAMMAR[1]),
        ("x/cast.ts", "typescript", GRAMMARS["typescript"][1]),
        ("x/a.mts", "typescript", GRAMMARS["typescript"][1]),
        ("x/view.jsx", "javascript", GRAMMARS["javascript"][1]),
        ("x/a.py", "python", GRAMMARS["python"][1]),
    ],
)
def test_grammar_entry_point_follows_the_suffix(path: str, language: str, attr: str) -> None:
    """§6.3: ``.tsx`` is parsed with ``language_tsx``; ``.ts`` keeps ``language_typescript``
    (angle-bracket casts) and ``.jsx`` the javascript grammar, which parses JSX. The choice is
    the profile's own ``grammar_variants`` — no extension table beside ``shared.language``."""
    profile = profile_for(path)
    assert (getattr(profile, "language", None), profile and profile.grammar_for(path)) == (language, attr)


def test_only_typescript_has_a_grammar_variant() -> None:
    """Every profile but typescript parses with its one entry point; typescript's only
    variant is ``.tsx`` -> ``language_tsx`` (§6.3)."""
    variants = {name: dict(p.grammar_variants) for name, p in PROFILES.items() if p.grammar_variants}
    assert variants == {"typescript": {".tsx": TSX_GRAMMAR[1]}}


def _entry_points() -> set[tuple[str, str]]:
    """(language, entry point) for every entry point a profile lists."""
    return {(name, attr) for name, p in PROFILES.items() for attr in p.grammar_attrs}


def _assert_entry_point_row(name: str, attr: str, variant: LanguageProfile) -> None:
    """One ``GRAMMAR_PROFILES`` row: the ``name`` profile with ``grammar_attr`` ``attr`` and
    the same table, its query compiling against that entry point's grammar."""
    base = PROFILES[name]
    assert (variant.grammar_attr, variant.node_map, variant.pruned) == (attr, base.node_map, base.pruned)
    lang = grammar(variant.grammar_module, attr)
    assert _unknown_types(variant, lang) == [], (name, attr)
    tree_sitter.Query(lang, build_query(variant.node_map))


def test_grammar_profiles_hold_every_entry_point_with_the_same_table() -> None:
    """``GRAMMAR_PROFILES`` has one row per (language, entry point) a profile lists; each row
    is its profile with that ``grammar_attr`` and the same table, and its query compiles
    against that entry point's grammar."""
    expected = _entry_points()
    assert set(GRAMMAR_PROFILES) == expected
    for (name, attr), variant in GRAMMAR_PROFILES.items():
        _assert_entry_point_row(name, attr, variant)


# ── build_query's emitted shape (LLD §6.3) ───────────────────────────────────


def test_build_query_names_captures_kind_and_kind_field() -> None:
    """``(call_expression function: (_) @call.callee arguments: (_) @call.args) @call``."""
    fields = MappingProxyType({"function": Field.CALLEE, "arguments": Field.ARGS})
    found = _captures(build_query({"call_expression": Capture(Kind.CALL, fields)}), "javascript", b"f(x);\n")
    assert found == {"call": [b"f(x)"], "call.callee": [b"f"], "call.args": [b"(x)"]}, found


def test_build_query_matches_nodes_missing_optional_fields() -> None:
    """A mapped field is optional: an ``if`` with no ``else`` still ships as IF.
    A pattern that required every mapped field would silently drop it."""
    fields = {"condition": Field.TEST, "consequence": Field.CONSEQ, "alternative": Field.ALT}
    rows = {"if_statement": Capture(Kind.IF, MappingProxyType(fields))}
    found = _captures(build_query(rows), "javascript", b"if (a) b();\n")
    assert {name: found.get(name) for name in ("if", "if.conseq", "if.alt")} == {
        "if": [b"if (a) b();"], "if.conseq": [b"b();"], "if.alt": None,
    }, found


def test_parent_keyed_row_captures_only_direct_children() -> None:
    """A ``(formal_parameters, identifier)`` row captures a parameter, never an
    identifier elsewhere (W1); the plain row still sees every identifier."""
    rows = {("formal_parameters", "identifier"): Capture(Kind.PARAM), "identifier": Capture(Kind.NAME)}
    found = _captures(build_query(rows), "javascript", b"function f(a) { b; }\n")
    assert (found.get("param"), b"b" in found.get("name", [])) == ([b"a"], True), found


# ── W1, W3, W6, W7, W11, W15 (e), C4: dispositions and rows ──────────────────


@pytest.mark.parametrize("case", sorted(DISPOSITION_CASES))
def test_node_disposition_is_mechanical(case: str) -> None:
    """Each grammar type's disposition follows from the profile table alone (D4, W1)."""
    DISPOSITION_CASES[case]()


@pytest.mark.parametrize(("language", "node_type"), TRANSPARENT, ids=_pair_ids(TRANSPARENT))
def test_listed_wrappers_are_transparent(language: str, node_type: str) -> None:
    """Unlisted wrappers ship nothing of their own and are not pruned (W1, C4)."""
    p = _profile(language)
    assert _has_node(profile_grammar(p), node_type), (language, node_type)
    assert _is_transparent(p, node_type), (language, node_type, _kinds_for(p, node_type))


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_pruned_types(p: LanguageProfile) -> None:
    """``type_arguments`` is PRUNED in every profile whose grammar has it, and
    every pruned name exists in the profile's grammar (W1)."""
    lang = profile_grammar(p)
    assert _missing_nodes(lang, p.pruned) == [], p.pruned
    assert not _has_node(lang, "type_arguments") or "type_arguments" in p.pruned, p.pruned


@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_declaration_keywords_ship_as_other(language: str) -> None:
    """JS/TS ``lexical_declaration``/``variable_declaration`` are OTHER (W1:
    they carry their ``let``/``const``/``var`` text for the scope rules)."""
    found = _kinds_by_type(_profile(language), ("lexical_declaration", "variable_declaration"))
    assert found == {"lexical_declaration": {Kind.OTHER}, "variable_declaration": {Kind.OTHER}}


@pytest.mark.parametrize(("language", "node_type"), COMPOUND_NAMES, ids=_pair_ids(COMPOUND_NAMES))
def test_compound_names_are_member(language: str, node_type: str) -> None:
    """Scoped/qualified names ship as a text-less MEMBER chain (W3)."""
    assert _kinds_for(_profile(language), node_type) == {Kind.MEMBER}


@pytest.mark.parametrize(("language", "node_type"), TYPE_NAMES, ids=_pair_ids(TYPE_NAMES))
def test_type_names_ship_as_name(language: str, node_type: str) -> None:
    """``type_identifier`` and C++ ``namespace_identifier`` are NAME rows (W3)."""
    assert Kind.NAME in _kinds_for(_profile(language), node_type)


@pytest.mark.parametrize(("language", "node_type"), SYNTHETIC_CALLS, ids=_pair_ids(SYNTHETIC_CALLS))
def test_calls_in_disguise_ship_as_call(language: str, node_type: str) -> None:
    """PHP include/require/backticks and Rust macros ship as CALL (§6.3)."""
    assert Kind.CALL in _kinds_for(_profile(language), node_type)


@pytest.mark.parametrize("table", sorted(ROW_TABLES))
def test_rows_ship_with_their_kinds_and_fields(table: str) -> None:
    """Table rows of W6 (patterns, imports), W7 (parameters), C4/W1
    (``function_declarator``: transparent with fields) and W15 (e) (C++
    subscript): each row ships as its kind and maps at least its fields."""
    language, rows, fields = ROW_TABLES[table]
    p = _profile(language)
    assert _row_kinds(p, rows) == rows
    assert _field_gaps(p, fields) == {}


def test_rust_reference_expression_is_unary() -> None:
    """W11: ``&x`` ships as UNARY so R-W's reference test is structural."""
    assert _kinds_for(_profile("rust"), "reference_expression") == {Kind.UNARY}


# ── L10: arms ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("language", LANGUAGES)
def test_arm_types(language: str) -> None:
    """Every profile's ``arm_types`` is exactly L10's list, each in the grammar."""
    p = _profile(language)
    assert set(p.arm_types) == ARMS[language], set(p.arm_types) ^ ARMS[language]
    assert _missing_nodes(profile_grammar(p), p.arm_types) == []


@pytest.mark.parametrize("language", LANGUAGES)
def test_arms_ship_as_block(language: str) -> None:
    """Each arm ships as a BLOCK (L10: the worker gives it field CONSEQ under its
    OTHER switch/match node), so §7.2 runs it as a conditional body."""
    arms = ARMS[language]
    assert _kinds_by_type(_profile(language), arms) == dict.fromkeys(arms, {Kind.BLOCK})


@pytest.mark.parametrize(("language", "node_type"), SWITCHES, ids=_pair_ids(SWITCHES))
def test_switch_and_match_nodes_stay_other(language: str, node_type: str) -> None:
    """The switch/match nodes that own the arms stay OTHER (L10, §6.3)."""
    assert _kinds_for(_profile(language), node_type) == {Kind.OTHER}


# ── Families and the browser gate ────────────────────────────────────────────


@pytest.mark.parametrize("language", LANGUAGES)
def test_owned_families(language: str) -> None:
    """All three families everywhere but C/C++, which own path + command (D-H)."""
    assert set(_profile(language).owned_families) == OWNED_FAMILIES[language]


@pytest.mark.parametrize("language", LANGUAGES)
def test_browser_capable_is_js_and_ts_only(language: str) -> None:
    """Only JS/TS carry the ``server_ctx`` browser gate (§6.3, L8)."""
    assert _profile(language).browser_capable is (language in {"javascript", "typescript"})


# ── Builtins (L1 (a), L9, W5, P4, R5, R7, R9) ────────────────────────────────


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_builtin_keys_are_glued(p: LanguageProfile) -> None:
    """Builtin keys are glued like every sink-side callee key (L1 (a), W5): one
    lowercase identifier or a glued pair, no ``_`` or ``$``."""
    assert [key for key in p.builtin_sinks if not GLUED_KEY.match(key)] == []


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_builtin_entries_are_well_formed(p: LanguageProfile) -> None:
    """A family set within the three families (possibly EMPTY: no sink, P4);
    positions ``"all"`` or a tuple of positions (L9, W5); ``when`` None or
    ``(position, glued NAME key)``."""
    assert _malformed_builtins(p) == []


@pytest.mark.parametrize("p", PROFILES.values(), ids=lambda p: p.language)
def test_ambiguous_single_keys_are_never_builtins(p: LanguageProfile) -> None:
    """W5: pairs are probed before single keys, so ``Path::new(x)``, ``map.get(k)``
    and ``Set.of(...)`` keep their word classification — no profile may make
    ``new``/``get``/``of`` a builtin. R9: ``replace`` is no sink anywhere (a
    string ``p.replace("..", "")`` passes through); ``pathnew`` is no pair."""
    assert {"new", "get", "of", "replace", "pathnew"} & set(p.builtin_sinks) == set()


def test_go_declares_only_its_predeclared_shadows() -> None:
    """§6.3 Go: the stdlib keys suffice for every sink, so the profile's only builtins are
    A47 (2) (i)'s predeclared slice builtins ``append`` and ``copy``, each with the EMPTY family
    set (R5's mechanism): never a path sink, whatever their arguments."""
    sinks = _profile("go").builtin_sinks
    assert {key: frozenset(sink.families) for key, sink in sinks.items()} == {
        "append": frozenset(), "copy": frozenset(),
    }


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("key", ["read", "fread", "fgets", "write", "fwrite"])
def test_c_buffer_and_fd_builtins_are_no_sinks(language: str, key: str) -> None:
    """P4/C5/R5: arg 0 of ``read``/``write`` is an fd and of ``fread``/``fgets``/
    ``fwrite`` a buffer — never a path. The EMPTY family set makes each no sink
    and overrides the generic ``read``/``write`` path words; C++ inherits it."""
    assert frozenset(_builtin(_profile(language), key).families) == frozenset()


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_c_openat_reports_on_its_path_argument_only(language: str) -> None:
    """L9/P4: ``openat(dirfd, path, flags)`` is a path sink on position 1 only."""
    entry = _builtin(_profile(language), "openat")
    assert _families_and_positions(entry) == (frozenset({"path"}), (1,))


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_c_posix_spawn_is_a_command_builtin(language: str) -> None:
    """§6.3 C: ``posix_spawn`` is a command sink by builtin (``posixspawn`` has
    no ``COMMAND_STRONG`` prefix); C++ takes C's command sinks."""
    assert frozenset(_builtin(_profile(language), "posixspawn").families) == frozenset({"command"})


@pytest.mark.parametrize("key", ["ifstream", "ofstream", "fstream"])
def test_cpp_stream_constructors_are_path_builtins(key: str) -> None:
    """§6.3 C++: the stream constructors are path sinks on arg 0 (the default)."""
    entry = _builtin(_profile("cpp"), key)
    assert _families_and_positions(entry) == (frozenset({"path"}), (0,))


@pytest.mark.parametrize(
    "key",
    [
        "file", "fileinputstream", "fileoutputstream", "filereader", "filewriter",
        "randomaccessfile", "pathsget", "pathof",
    ],
)
def test_java_file_builtins_take_every_argument(key: str) -> None:
    """L9/W5: the ``File*``/``RandomAccessFile`` constructors and the glued pairs
    ``Paths.get``/``Path.of`` are path sinks on EVERY argument, so
    ``new File(DOC_ROOT, name)`` reports on ``name``."""
    entry = _builtin(_profile("java"), key)
    assert _families_and_positions(entry) == (frozenset({"path"}), "all")


def test_python_os_replace_is_a_pair_key() -> None:
    """R9: ``os.replace(src, dst)`` is the builtin pair ``osreplace`` -> path on
    every argument; ``replace`` alone is no builtin (the ambiguous-keys test)."""
    entry = _builtin(_profile("python"), "osreplace")
    assert _families_and_positions(entry) == (frozenset({"path"}), "all")


def test_rust_command_new_is_a_pair_key() -> None:
    """W5: ``Command::new`` is the command root by the glued pair ``commandnew``;
    ``Path::new`` and every other ``X::new`` stay untouched."""
    assert frozenset(_builtin(_profile("rust"), "commandnew").families) == frozenset({"command"})


PHP_BUILTIN_FAMILIES: dict[str, set[str]] = {
    "filegetcontents": {"path", "request"},
    "fopen": {"path", "request"},
    "readfile": {"path"},
    "fileputcontents": {"path"},
    "copy": {"path"},
    "curlinit": {"request"},
    "curlsetopt": {"request"},
}


def test_php_builtin_families() -> None:
    """§6.3 PHP: the language's own file and ext/curl builtins (R7: ext/curl
    ships with PHP, so these are language builtins, not a library table)."""
    p = _profile("php")
    found = {key: set(_builtin(p, key).families) for key in PHP_BUILTIN_FAMILIES}
    assert found == PHP_BUILTIN_FAMILIES


def test_php_curl_setopt_is_conditional_and_positions_default_to_zero() -> None:
    """W5/R7: ``curl_setopt`` is a request sink on arg 2 only when arg 1 is the
    NAME ``CURLOPT_URL``; an entry that declares no positions takes ``(0,)``
    and no condition (P4)."""
    p = _profile("php")
    setopt, readfile, curlinit = (_builtin(p, key) for key in ("curlsetopt", "readfile", "curlinit"))
    assert (setopt.request_args, setopt.when) == ((2,), (1, "curlopturl"))
    assert (readfile.path_args, readfile.when, curlinit.request_args) == ((0,), None, (0,))


# ── profile_for (O1, D19) ────────────────────────────────────────────────────


def test_profile_for() -> None:
    """``.tsx`` -> typescript, ``.go`` -> go, ``.rb`` -> None (O1: Ruby
    is the unsupported language)."""
    found = [getattr(profile_for(path), "language", None) for path in ("x/a.tsx", "x/a.go", "x/a.rb")]
    assert found == ["typescript", "go", None]


@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("x/a.js", "javascript"), ("x/a.jsx", "javascript"), ("x/a.mjs", "javascript"),
        ("A.JS", "javascript"), ("x/a.ts", "typescript"), ("x/a.py", "python"),
        ("x/a.pyi", "python"), ("x/a.java", "java"), ("x/a.rs", "rust"), ("x/a.php", "php"),
        ("x/a.phtml", "php"), ("x/a.c", "c"), ("x/a.h", "c"), ("x/a.cpp", "cpp"),
        ("x/a.cc", "cpp"), ("x/a.hpp", "cpp"), (Path("x/a.go"), "go"), ("x/../a.py", "python"),
        ("x/a.kt", None), ("x/a.swift", None), ("x/a.cs", None), ("Gemfile", None),
        ("Dockerfile", None), ("README.md", None), ("", None), (".go", None), ("x/.tsx", None),
        ("a.go/", None), ("x/a.c ", None), ("x/a.py\x00.rb", None),
    ],
)
def test_profile_for_is_derived_from_detect_language(path: str | Path, language: str | None) -> None:
    """``profile_for`` is ``PROFILES.get(detect_language(path))`` — no second
    extension table (D19) — including for hostile and unsupported paths."""
    found = profile_for(path)
    assert found is PROFILES.get(detect_language(str(path)))
    assert getattr(found, "language", None) == language


def test_a_held_back_profile_is_no_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """§6.4: a profile ``disabled_until`` a grammar version is held back at the one decision
    point — ``profile_for`` answers no profile, so the language's files are ``unsupported``
    (regex-owned) and ``owns_lang`` is False — while every other language is untouched."""
    held = replace(PROFILES["go"], disabled_until="tree-sitter-go 0.26")
    monkeypatch.setattr(profile_module, "PROFILES", MappingProxyType({**PROFILES, "go": held}))
    observed = (profile_for("x/a.go"), owns_lang("x/a.go"), profile_for("x/a.py") is PROFILES["python"])
    assert observed == (None, False, True)


# ── D1: the tables never load a parser ───────────────────────────────────────


def test_profile_tables_load_no_parser() -> None:
    """A fresh ``import shared.ast.profile`` (every table, ``build_query``, the
    grammar versions) loads neither tree-sitter nor any grammar: only the spawned
    worker parses (D1)."""
    grammars = sorted({module for module, _ in GRAMMARS.values()})
    watch = ("tree_sitter", *grammars, "shared.validate", "shared.audit_runner")
    assert loaded_after_import("shared.ast.profile", watch) == []
