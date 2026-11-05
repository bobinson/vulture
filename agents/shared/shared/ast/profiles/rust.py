"""Rust ``NODE_MAP`` (feature 0102, LLD §6.3; tree-sitter-rust 0.24.2).

Method calls are ``call_expression`` whose ``function`` is a ``field_expression``.
``expression_statement``, ``match_block``, ``generic_type``, ``try_expression`` and
``parenthesized_expression`` are unlisted, hence transparent (W1). ``index_expression`` and
a macro's ``token_tree`` have no grammar field, so they are mapped by position.
"""

from __future__ import annotations

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    ASSIGN_LR,
    AUG_ASSIGN_LR,
    CALL_FA,
    COMMAND,
    FUNCTION_ROW,
    IF_ROW,
    LAMBDA_ROW,
    LOOP_BODY,
    TYPE_ARGUMENTS,
    Builtin,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    pair,
    rows,
)

__all__ = ["RUST"]

_ARMS = ("match_arm",)  # L10
_COMPOUND = cap(K.MEMBER, path=F.OBJECT, name=F.PROPERTY)  # W3: `fs::read_to_string`

_NODE_MAP = {
    "source_file": cap(K.MODULE),
    **rows(cap(K.CLASS), "impl_item", "struct_item"),
    "function_item": FUNCTION_ROW,
    "closure_expression": LAMBDA_ROW,
    **rows(cap(K.ARGS), "parameters", "closure_parameters"),
    "parameter": cap(K.PARAM, pattern=F.NAME, type=F.ANNOTATION),
    "self_parameter": cap(K.PARAM),
    ("closure_parameters", "identifier"): cap(K.PARAM),  # `|a| ...`: a bare-identifier PARAM
    **rows(cap(K.BLOCK), "block", "unsafe_block", "async_block"),
    "if_expression": IF_ROW,
    "let_condition": cap(K.ASSIGN, pattern=F.LHS, value=F.RHS),  # `if let P = v` binds P
    "for_expression": cap(K.LOOP, pattern=F.TARGET, value=F.ITER, body=F.BODY),
    **rows(LOOP_BODY, "while_expression", "loop_expression"),
    "match_expression": cap(K.OTHER),
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arm
    "return_expression": cap(K.RETURN),
    **rows(cap(K.JUMP), "break_expression", "continue_expression"),
    "let_declaration": cap(K.ASSIGN, pattern=F.LHS, value=F.RHS),
    "assignment_expression": ASSIGN_LR,
    "compound_assignment_expr": AUG_ASSIGN_LR,
    "call_expression": CALL_FA,
    # `token_tree` is a node kind, not a field: the macro's second named child is its ARGS.
    "macro_invocation": cap(K.CALL, {1: F.ARGS}, macro=F.CALLEE),
    "field_expression": cap(K.MEMBER, value=F.OBJECT, field=F.PROPERTY),
    "index_expression": cap(K.SUBSCRIPT, {0: F.OBJECT, 1: F.INDEX}),
    **rows(cap(K.NAME), "identifier", "field_identifier", "type_identifier", "self"),
    **rows(_COMPOUND, "scoped_identifier", "scoped_type_identifier"),
    **rows(cap(K.LITERAL), "string_literal", "raw_string_literal", "integer_literal",
           "float_literal", "boolean_literal", "char_literal"),
    "binary_expression": cap(K.BINOP),
    "unary_expression": cap(K.UNARY),
    "await_expression": cap(K.AWAIT),
    "reference_expression": cap(K.UNARY),  # W11: ships with token `&` (R-W's reference test)
    "struct_expression": cap(K.OBJECT),
    "field_initializer": cap(K.PAIR, field=F.KEY, value=F.VALUE),
    "shorthand_field_initializer": cap(K.PAIR),
    **rows(cap(K.ARRAY), "array_expression", "tuple_expression"),
    "use_declaration": cap(K.IMPORT, argument=F.SOURCE),  # W3: a compound MEMBER under SOURCE
    "attribute_item": cap(K.DECORATOR),
    "ERROR": cap(K.ERROR),
}

RUST = LanguageProfile(
    language="rust",
    grammar_module="tree_sitter_rust",
    grammar_attr="language",
    node_map=frozen(_NODE_MAP),
    scope_rules=ScopeRules(block_scoped=frozenset({"*"}), shadowing_rebinds=True),
    # W5: the glued pair `Command::new` is the command root (program = arg 0, L7);
    # `Path::new(x)` and every other `X::new` keep their word classification.
    builtin_sinks=frozen(pair("command", "new", Builtin(COMMAND))),
    synthetic_calls=frozen({"macro_invocation": ""}),
    arm_types=frozenset(_ARMS),
    pruned=TYPE_ARGUMENTS,
    block_value=True,
    reference_args=True,
)
