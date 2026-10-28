"""Go ``NODE_MAP`` (feature 0102, LLD §6.3; every name exists in tree-sitter-go 0.25.0).

``statement_list``, ``expression_list``, ``expression_statement``, ``pointer_type``,
``slice_type``, ``map_type``, ``generic_type`` and ``parenthesized_expression`` are unlisted,
hence transparent (W1): a block's statements and a ``:=``'s targets are direct children.
No TRY/CATCH: error values are ordinary names. The stdlib keys suffice for every sink
(``os.ReadFile``, ``exec.Command``, ``http.Get``; ``os.Open`` is a path sink only, L8), so the
only builtins are the predeclared slice builtins ``append`` and ``copy``, which shadow two path
sink words: ``NO_FAMILY`` makes them no sink at all (R5's mechanism, A47 (2) (i)), and W5's
single key reads them on any receiver.
"""

from __future__ import annotations

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    ASSIGN_LR,
    ASSIGN_NV,
    CALL_FA,
    FUNCTION_ROW,
    IF_ROW,
    LAMBDA_ROW,
    LOOP_BODY,
    NO_FAMILY,
    PAIR_KV,
    TYPE_ARGUMENTS,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    rows,
)

__all__ = ["GO"]

_ARMS = ("expression_case", "type_case", "communication_case", "default_case")
# A47 (2) (i): the predeclared slice builtins (module docstring).
_SHADOWS = ("append", "copy")

_NODE_MAP = {
    "source_file": cap(K.MODULE),
    "function_declaration": FUNCTION_ROW,
    "method_declaration": cap(
        K.FUNCTION, name=F.NAME, parameters=F.PARAMS, receiver=F.PARAMS, body=F.BODY
    ),
    "func_literal": LAMBDA_ROW,
    "parameter_list": cap(K.ARGS),
    **rows(cap(K.PARAM, name=F.NAME, type=F.ANNOTATION),
           "parameter_declaration", "variadic_parameter_declaration"),
    "block": cap(K.BLOCK),
    "if_statement": IF_ROW,
    "for_statement": LOOP_BODY,
    "range_clause": cap(None, left=F.TARGET, right=F.ITER),  # W1: fields of its LOOP
    "return_statement": cap(K.RETURN),
    **rows(cap(K.JUMP), "break_statement", "continue_statement"),
    # `+=` makes an assignment_statement an AUG_ASSIGN (the worker reads its operator).
    **rows(ASSIGN_LR, "short_var_declaration", "assignment_statement"),
    **rows(ASSIGN_NV, "var_spec", "const_spec"),
    "call_expression": CALL_FA,
    "selector_expression": cap(K.MEMBER, operand=F.OBJECT, field=F.PROPERTY),
    "index_expression": cap(K.SUBSCRIPT, operand=F.OBJECT, index=F.INDEX),
    **rows(cap(K.NAME), "identifier", "field_identifier", "package_identifier",
           "type_identifier"),
    "qualified_type": cap(K.MEMBER, package=F.OBJECT, name=F.PROPERTY),  # W3 compound
    **rows(cap(K.LITERAL), "interpreted_string_literal", "raw_string_literal", "int_literal",
           "float_literal", "imaginary_literal", "rune_literal", "true", "false", "nil",
           "iota"),
    "binary_expression": cap(K.BINOP),
    "unary_expression": cap(K.UNARY),
    **rows(cap(K.OBJECT), "composite_literal", "literal_value"),
    "keyed_element": PAIR_KV,
    "import_declaration": cap(K.IMPORT),
    # W3: `text` is the path's last segment (`net/http` -> `http`); `name` is an alias.
    "import_spec": cap(K.IMPORT, path=F.SOURCE, name=F.NAME),
    "type_declaration": cap(K.CLASS),
    **rows(cap(K.OTHER), "expression_switch_statement", "type_switch_statement",
           "select_statement", "defer_statement", "go_statement", "inc_statement",
           "dec_statement"),
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arms
    "ERROR": cap(K.ERROR),
}


def _public(name: str) -> bool:
    """A47 D23-d: Go exports a name by its upper-case initial."""
    return name[:1].isupper()


GO = LanguageProfile(
    language="go",
    grammar_module="tree_sitter_go",
    grammar_attr="language",
    node_map=frozen(_NODE_MAP),
    # `:=` and `var` are block-scoped; an import spec is its path's last segment (W3)
    scope_rules=ScopeRules(block_scoped=frozenset({"*"}), import_spec_text=True),
    builtin_sinks=frozen(dict.fromkeys(_SHADOWS, NO_FAMILY)),
    arm_types=frozenset(_ARMS),
    pruned=TYPE_ARGUMENTS,
    receiver_list=True,
    reference_args=True,
    public_name=_public,
)
