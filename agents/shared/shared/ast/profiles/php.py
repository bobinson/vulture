"""PHP ``NODE_MAP`` (feature 0102, LLD §6.3; tree-sitter-php 0.25.1, ``language_php``).

``expression_statement``, ``argument``, ``named_type``, ``parenthesized_expression``,
``text_interpolation`` and ``cast_expression`` are unlisted, hence transparent (W1):
``arguments`` is the ARGS container, so ``argument`` re-parents its expression into it.
Children the grammar gives no field are mapped by position (``subscript_expression``,
``foreach_statement``, ``object_creation_expression``, ``class_constant_access_expression``).

The builtins are the language's own (R7: ext/curl ships with PHP); a profile never names a
package (D7).
"""

from __future__ import annotations

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    ASSIGN_LR,
    AUG_ASSIGN_LR,
    CALL_FA,
    CLASS_ROW,
    EVERY_ARG_PATH,
    FUNCTION_ROW,
    LAMBDA_ROW,
    LOOP_BODY,
    PATH,
    REQUEST,
    TRY_BODY,
    Builtin,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    rows,
)

__all__ = ["PHP"]

_ARMS = ("case_statement", "default_statement", "match_conditional_expression",
         "match_default_expression")  # L10
_PARAMETER = cap(K.PARAM, name=F.NAME, type=F.ANNOTATION, default_value=F.VALUE)
_METHOD_CALL = cap(K.CALL, object=F.OBJECT, name=F.CALLEE, arguments=F.ARGS)
_MEMBER = cap(K.MEMBER, object=F.OBJECT, name=F.PROPERTY)

# §6.3: grammar nodes that are calls in disguise -> their glued synthetic callee key.
_SYNTHETIC_CALLS = {
    "include_expression": "include",
    "include_once_expression": "include",
    "require_expression": "require",
    "require_once_expression": "require",
    "shell_command_expression": "shellexec",  # backticks: every interpolated NAME is an arg
}

_NODE_MAP = {
    "program": cap(K.MODULE),
    "class_declaration": CLASS_ROW,
    "declaration_list": cap(K.BLOCK),
    **rows(FUNCTION_ROW, "function_definition", "method_declaration"),
    **rows(LAMBDA_ROW, "anonymous_function", "arrow_function"),
    "formal_parameters": cap(K.ARGS),
    **rows(_PARAMETER, "simple_parameter", "property_promotion_parameter"),
    "variadic_parameter": cap(K.PARAM, name=F.NAME, type=F.ANNOTATION),
    "compound_statement": cap(K.BLOCK),
    # else-if = a nested IF under ALT; else = an IF whose body is its CONSEQ.
    "if_statement": cap(K.IF, condition=F.TEST, body=F.CONSEQ, alternative=F.ALT),
    "else_if_clause": cap(K.IF, condition=F.TEST, body=F.CONSEQ),
    "else_clause": cap(K.IF, body=F.CONSEQ),
    **rows(LOOP_BODY, "for_statement", "while_statement", "do_statement"),
    # positional: the iterated expression, then the value (or the key => value pair).
    "foreach_statement": cap(K.LOOP, {0: F.ITER, 1: F.TARGET}, body=F.BODY),
    "try_statement": TRY_BODY,
    "catch_clause": cap(K.CATCH, name=F.PARAMS, body=F.BODY),
    "finally_clause": cap(K.FINALLY, body=F.BODY),
    "return_statement": cap(K.RETURN),
    **rows(cap(K.THROW), "throw_expression", "exit_statement"),
    **rows(cap(K.JUMP), "break_statement", "continue_statement"),
    "assignment_expression": ASSIGN_LR,
    "augmented_assignment_expression": AUG_ASSIGN_LR,
    "function_call_expression": CALL_FA,
    **rows(_METHOD_CALL, "member_call_expression", "nullsafe_member_call_expression"),
    "scoped_call_expression": cap(K.CALL, scope=F.OBJECT, name=F.CALLEE, arguments=F.ARGS),
    "object_creation_expression": cap(K.CALL, {0: F.CALLEE, 1: F.ARGS}),
    **rows(cap(K.CALL), *_SYNTHETIC_CALLS),
    **rows(_MEMBER, "member_access_expression", "nullsafe_member_access_expression"),
    "subscript_expression": cap(K.SUBSCRIPT, {0: F.OBJECT, 1: F.INDEX}),
    "class_constant_access_expression": cap(K.MEMBER, {0: F.OBJECT, 1: F.PROPERTY}),
    **rows(cap(K.NAME), "variable_name", "name"),  # variable_name: text without the `$`
    # W3 compound names. tree-sitter-php 0.25.1 gives a qualified_name's final `name` no
    # field (only `prefix`), so like the field-less namespace_name it takes W3's
    # no-field rule: the last child is the PROPERTY.
    "qualified_name": cap(K.MEMBER, prefix=F.OBJECT),
    "namespace_name": cap(K.MEMBER),
    **rows(cap(K.LITERAL), "string", "integer", "float", "boolean", "null", "nowdoc"),
    **rows(cap(K.TEMPLATE), "encapsed_string", "heredoc"),
    "binary_expression": cap(K.BINOP),
    "unary_op_expression": cap(K.UNARY),
    "conditional_expression": cap(K.TERNARY),
    "array_creation_expression": cap(K.ARRAY),
    "array_element_initializer": cap(K.PAIR),
    "list_literal": cap(K.DESTRUCT),
    **rows(cap(K.IMPORT), "namespace_use_declaration", "namespace_use_clause"),
    **rows(cap(K.DECORATOR), "attribute_group", "attribute"),
    **rows(cap(K.GLOBAL), "global_declaration", "static_variable_declaration"),
    **rows(cap(K.OTHER), "echo_statement", "switch_statement", "match_expression"),
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arms
    "ERROR": cap(K.ERROR),
}

_PATH_OR_REQUEST = PATH | REQUEST

PHP = LanguageProfile(
    language="php",
    grammar_module="tree_sitter_php",
    grammar_attr="language_php",
    node_map=frozen(_NODE_MAP),
    scope_rules=ScopeRules(function_scoped=frozenset({"*"}), global_statement=True),
    call_shape="object_name",
    builtin_sources=frozen({
        **dict.fromkeys(("_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES"), "request"),
        **dict.fromkeys(("_SERVER", "_ENV"), "env"),
    }),
    builtin_sinks=frozen({
        "filegetcontents": Builtin(_PATH_OR_REQUEST),
        "fopen": Builtin(_PATH_OR_REQUEST),
        "readfile": Builtin(PATH),
        "fileputcontents": Builtin(PATH),
        "copy": EVERY_ARG_PATH,  # R10: source and destination are paths
        "curlinit": Builtin(REQUEST),
        # W5/R7: a sink on arg 2 only when arg 1 is the NAME CURLOPT_URL.
        "curlsetopt": Builtin(REQUEST, request_args=(2,), when=(1, "curlopturl")),
    }),
    synthetic_calls=frozen(_SYNTHETIC_CALLS),
    arm_types=frozenset(_ARMS),
    # §6.3: the PHP open tag and inline HTML are not shipped.
    pruned=frozenset({"php_tag", "text"}),
)
