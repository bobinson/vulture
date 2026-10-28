"""Python ``NODE_MAP`` (feature 0102, LLD §6.3).

``decorated_definition``, ``type``, ``expression_statement``, ``parenthesized_expression``
and ``expression_list`` are unlisted, hence transparent (W1): a decorator precedes its
FUNCTION/CLASS as a sibling (W7) and a call's ``argument_list`` is the ARGS container.
"""

from __future__ import annotations

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    ASSIGN_LR,
    ASSIGN_NV,
    AUG_ASSIGN_LR,
    CALL_FA,
    CLASS_ROW,
    EVERY_ARG_PATH,
    FUNCTION_ROW,
    IF_ROW,
    LAMBDA_ROW,
    LOOP_BODY,
    PAIR_KV,
    TRY_BODY,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    pair,
    rows,
)

__all__ = ["PYTHON"]

_ARMS = ("case_clause",)  # L10

_PATTERNS = ("pattern_list", "tuple_pattern", "list_pattern")
_PARAMETERS = {
    "identifier": cap(K.PARAM),
    "list_splat_pattern": cap(K.PARAM),
    "dictionary_splat_pattern": cap(K.PARAM),
    "default_parameter": cap(K.PARAM, name=F.NAME, value=F.VALUE),  # W7
    "typed_default_parameter": cap(K.PARAM, name=F.NAME, type=F.ANNOTATION, value=F.VALUE),
    "typed_parameter": cap(K.PARAM, type=F.ANNOTATION),  # W7: its name is its first NAME
}

_NODE_MAP = {
    "module": cap(K.MODULE),
    "function_definition": FUNCTION_ROW,
    "lambda": LAMBDA_ROW,
    "class_definition": CLASS_ROW,
    "parameters": cap(K.ARGS),
    # W1: parameter rows apply to direct children of the parameter lists only.
    **{(owner, t): row for owner in ("parameters", "lambda_parameters")
       for t, row in _PARAMETERS.items()},
    "block": cap(K.BLOCK),
    # elif = a nested IF under ALT; else = an IF whose body is its CONSEQ.
    "if_statement": IF_ROW,
    "elif_clause": cap(K.IF, condition=F.TEST, consequence=F.CONSEQ),
    "else_clause": cap(K.IF, body=F.CONSEQ),
    "for_statement": cap(K.LOOP, left=F.TARGET, right=F.ITER, body=F.BODY),
    "while_statement": LOOP_BODY,
    "try_statement": TRY_BODY,
    "except_clause": cap(K.CATCH),
    "finally_clause": cap(K.FINALLY),
    "with_statement": cap(K.WITH, body=F.BODY),
    "with_item": cap(K.WITH, value=F.ITER),
    "as_pattern": cap(None, alias=F.TARGET),  # W1: `with e as x` / `except E as x`
    "return_statement": cap(K.RETURN),
    "raise_statement": cap(K.THROW),
    **rows(cap(K.JUMP), "continue_statement", "break_statement"),
    "assignment": ASSIGN_LR,
    "named_expression": ASSIGN_NV,
    "augmented_assignment": AUG_ASSIGN_LR,
    "call": CALL_FA,
    "keyword_argument": cap(K.KWARG, name=F.NAME, value=F.VALUE),
    "attribute": cap(K.MEMBER, object=F.OBJECT, attribute=F.PROPERTY),
    "subscript": cap(K.SUBSCRIPT, value=F.OBJECT, subscript=F.INDEX),
    "identifier": cap(K.NAME),
    **rows(cap(K.LITERAL), "string", "concatenated_string", "integer", "float", "true",
           "false", "none"),
    "interpolation": cap(K.TEMPLATE),  # M3: an f-string carries its parts
    **rows(cap(K.BINOP), "binary_operator", "boolean_operator", "comparison_operator"),
    **rows(cap(K.UNARY), "not_operator", "unary_operator"),
    "conditional_expression": cap(K.TERNARY),
    "await": cap(K.AWAIT),
    **rows(cap(K.SPREAD), "list_splat", "dictionary_splat"),
    "dictionary": cap(K.OBJECT),
    **rows(cap(K.ARRAY), "list", "tuple", "set"),
    "pair": PAIR_KV,
    **rows(cap(K.DESTRUCT), *_PATTERNS),
    **rows(cap(K.SPREAD), *((t, "list_splat_pattern") for t in _PATTERNS)),  # W6
    "import_statement": cap(K.IMPORT, name=F.SOURCE),
    "import_from_statement": cap(K.IMPORT, module_name=F.SOURCE),
    "aliased_import": cap(K.PAIR, name=F.KEY, alias=F.VALUE),  # W6
    "dotted_name": cap(K.MEMBER),  # W3: compound, no fields (last child -> PROPERTY)
    "decorator": cap(K.DECORATOR),
    **rows(cap(K.GLOBAL), "global_statement", "nonlocal_statement"),
    **rows(cap(K.COMPREHENSION), "list_comprehension", "set_comprehension",
           "dictionary_comprehension", "generator_expression"),
    "yield": cap(K.YIELD),
    **rows(cap(K.OTHER), "assert_statement", "delete_statement", "pass_statement",
           "match_statement", "print_statement", "exec_statement"),
    ("match_statement", "block"): cap(None),  # L10: arms sit directly under the match
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arm
    "ERROR": cap(K.ERROR),
}


def _public(name: str) -> bool:
    """A47 D23-d: a public Python name has no leading ``_`` (``_helper``, ``__init__`` are
    not)."""
    return bool(name) and not name.startswith("_")


PYTHON = LanguageProfile(
    language="python",
    grammar_module="tree_sitter_python",
    grammar_attr="language",
    node_map=frozen(_NODE_MAP),
    scope_rules=ScopeRules(
        function_scoped=frozenset({"*"}),
        functions_hoist=False,
        comprehension_scope=True,
        global_statement=True,
        import_binds_first=True,
    ),
    # R9: os.replace(src, dst) - both arguments are paths; `replace` alone is no sink.
    builtin_sinks=frozen(pair("os", "replace", EVERY_ARG_PATH)),
    arm_types=frozenset(_ARMS),
    public_name=_public,
)
