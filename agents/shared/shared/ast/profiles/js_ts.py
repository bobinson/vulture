"""JavaScript and TypeScript ``NODE_MAP`` (feature 0102, LLD §6.3).

The two languages share every plain row. Only the ``(formal_parameters, type)`` rows differ,
because the grammars shape parameters differently: tree-sitter-javascript puts identifiers
and patterns DIRECTLY under ``formal_parameters`` (W1), tree-sitter-typescript wraps each in
a ``required_parameter`` / ``optional_parameter`` (W7). TypeScript type nodes are not
listed, so they are transparent and ship no NAME (W4: TS R-D reads decorators and names).
A ``.tsx`` file is parsed with ``language_tsx`` (JSX), a ``.ts`` file with
``language_typescript`` (whose angle-bracket casts ``<T>x`` the tsx grammar reads as JSX).
``.jsx`` needs no variant: tree-sitter-javascript parses JSX.
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
    FUNCTION_ROW,
    IF_ROW,
    LOOP_BODY,
    PAIR_KV,
    TYPE_ARGUMENTS,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    rows,
)

__all__ = ["JAVASCRIPT", "TYPESCRIPT"]

_ARMS = ("switch_case", "switch_default")  # L10

_PLAIN = {
    "program": cap(K.MODULE),
    **rows(FUNCTION_ROW, "function_declaration", "function_expression", "method_definition",
           "generator_function", "generator_function_declaration"),
    "arrow_function": cap(K.FUNCTION, parameters=F.PARAMS, parameter=F.PARAMS, body=F.BODY),
    **rows(CLASS_ROW, "class_declaration", "class"),
    "formal_parameters": cap(K.ARGS),
    **rows(cap(K.BLOCK), "statement_block", "class_body"),
    "if_statement": IF_ROW,
    **rows(LOOP_BODY, "for_statement", "while_statement", "do_statement"),
    "for_in_statement": cap(K.LOOP, left=F.TARGET, right=F.ITER, body=F.BODY),
    "try_statement": cap(K.TRY, body=F.BODY, handler=F.HANDLER),
    "catch_clause": cap(K.CATCH, parameter=F.PARAMS, body=F.BODY),
    "finally_clause": cap(K.FINALLY, body=F.BODY),
    "return_statement": cap(K.RETURN),
    "throw_statement": cap(K.THROW),
    **rows(cap(K.JUMP), "continue_statement", "break_statement"),
    "variable_declarator": ASSIGN_NV,
    "assignment_expression": ASSIGN_LR,
    "augmented_assignment_expression": AUG_ASSIGN_LR,
    "call_expression": CALL_FA,
    "new_expression": cap(K.CALL, constructor=F.CALLEE, arguments=F.ARGS),
    "member_expression": cap(K.MEMBER, object=F.OBJECT, property=F.PROPERTY),
    "subscript_expression": cap(K.SUBSCRIPT, object=F.OBJECT, index=F.INDEX),
    **rows(cap(K.NAME), "identifier", "property_identifier", "shorthand_property_identifier",
           "shorthand_property_identifier_pattern", "this"),
    **rows(cap(K.LITERAL), "string", "number", "true", "false", "null", "undefined", "regex"),
    "template_string": cap(K.TEMPLATE),
    "binary_expression": cap(K.BINOP),
    "unary_expression": cap(K.UNARY),
    "ternary_expression": cap(K.TERNARY),
    "await_expression": cap(K.AWAIT),
    "spread_element": cap(K.SPREAD),
    "object": cap(K.OBJECT),
    "array": cap(K.ARRAY),
    **rows(PAIR_KV, "pair", "pair_pattern"),
    **rows(cap(K.DESTRUCT), "object_pattern", "array_pattern"),  # W6; PARAM under parameters
    "rest_pattern": cap(K.SPREAD),  # W6: a rest leaf binds the whole object
    "import_statement": cap(K.IMPORT, source=F.SOURCE),
    "import_specifier": cap(K.PAIR, name=F.KEY, alias=F.VALUE),  # W6: symbol -> local alias
    "export_statement": cap(K.EXPORT),
    "decorator": cap(K.DECORATOR),
    **rows(cap(K.OTHER), "switch_statement", "labeled_statement", "with_statement",
           "debugger_statement", "empty_statement"),
    # W1: OTHER carrying its let/const/var keyword as `text`, the input of the scope rules.
    **rows(cap(K.OTHER), "lexical_declaration", "variable_declaration"),
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arms
    "ERROR": cap(K.ERROR),
}

# W1: the parameter rows apply to DIRECT children of `formal_parameters` only.
_JS_PARAMETERS = {
    **rows(cap(K.PARAM), *(("formal_parameters", t) for t in (
        "identifier", "object_pattern", "array_pattern", "rest_pattern"))),
    ("formal_parameters", "assignment_pattern"): cap(K.PARAM, left=F.NAME, right=F.VALUE),
}
# W7: a decorator on a parameter feeds R-D, as an ANNOTATION (§6.1).
_TS_PARAMETERS = rows(
    cap(K.PARAM, pattern=F.NAME, type=F.ANNOTATION, value=F.VALUE, decorator=F.ANNOTATION),
    ("formal_parameters", "required_parameter"), ("formal_parameters", "optional_parameter"),
)

_SCOPE = ScopeRules(block_scoped=frozenset({"let", "const", "class"}), function_scoped=frozenset({"var"}))

JAVASCRIPT = LanguageProfile(
    language="javascript",
    grammar_module="tree_sitter_javascript",
    grammar_attr="language",
    node_map=frozen(_PLAIN | _JS_PARAMETERS),
    scope_rules=_SCOPE,
    browser_capable=True,
    arm_types=frozenset(_ARMS),
)

TYPESCRIPT = LanguageProfile(
    language="typescript",
    grammar_module="tree_sitter_typescript",
    grammar_attr="language_typescript",
    node_map=frozen(_PLAIN | _TS_PARAMETERS),
    scope_rules=_SCOPE,
    browser_capable=True,
    arm_types=frozenset(_ARMS),
    pruned=TYPE_ARGUMENTS,
    grammar_variants=frozen({".tsx": "language_tsx"}),
)
