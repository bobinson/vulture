"""Java ``NODE_MAP`` (feature 0102, LLD §6.3; tree-sitter-java 0.23.5).

``cast_expression``, ``parenthesized_expression``, ``expression_statement``, ``modifiers``,
``generic_type`` and ``local_variable_declaration`` are unlisted, hence transparent (W1): an
annotation in ``modifiers`` is a DECORATOR child of its method or PARAM. A method call has an
``object`` and a ``name`` (``call_shape="object_name"``).
"""

from __future__ import annotations

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    ASSIGN_LR,
    ASSIGN_NV,
    CLASS_ROW,
    COMMAND,
    EVERY_ARG_PATH,
    FUNCTION_ROW,
    IF_ROW,
    LAMBDA_ROW,
    LOOP_BODY,
    TRY_BODY,
    TYPE_ARGUMENTS,
    Builtin,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    pair,
    rows,
)

__all__ = ["JAVA"]

_ARMS = ("switch_block_statement_group", "switch_rule")  # L10

_NODE_MAP = {
    "program": cap(K.MODULE),
    **rows(CLASS_ROW, "class_declaration", "interface_declaration"),
    "class_body": cap(K.BLOCK),
    **rows(FUNCTION_ROW, "method_declaration", "constructor_declaration"),
    "lambda_expression": LAMBDA_ROW,
    **rows(cap(K.ARGS), "formal_parameters", "inferred_parameters"),
    "formal_parameter": cap(K.PARAM, name=F.NAME, type=F.ANNOTATION),
    "spread_parameter": cap(K.PARAM),
    # W1: a spread parameter's name sits in a declarator, which binds no value here.
    ("spread_parameter", "variable_declarator"): cap(None, name=F.NAME),
    "catch_formal_parameter": cap(K.PARAM, name=F.NAME),
    "block": cap(K.BLOCK),
    "if_statement": IF_ROW,
    **rows(LOOP_BODY, "for_statement", "while_statement", "do_statement"),
    "enhanced_for_statement": cap(K.LOOP, name=F.TARGET, value=F.ITER, body=F.BODY),
    **rows(TRY_BODY, "try_statement", "try_with_resources_statement"),
    "resource": ASSIGN_NV,
    "catch_clause": cap(K.CATCH, body=F.BODY),
    "finally_clause": cap(K.FINALLY),
    "return_statement": cap(K.RETURN),
    "throw_statement": cap(K.THROW),
    **rows(cap(K.JUMP), "break_statement", "continue_statement"),
    "variable_declarator": ASSIGN_NV,
    # an operator other than `=` makes it an AUG_ASSIGN (the worker reads its operator).
    "assignment_expression": ASSIGN_LR,
    "method_invocation": cap(K.CALL, object=F.OBJECT, name=F.CALLEE, arguments=F.ARGS),
    "object_creation_expression": cap(K.CALL, type=F.CALLEE, arguments=F.ARGS),
    "field_access": cap(K.MEMBER, object=F.OBJECT, field=F.PROPERTY),
    "array_access": cap(K.SUBSCRIPT, array=F.OBJECT, index=F.INDEX),
    # W3: `type_identifier` is the callee of `new File(...)` and the words of a param type.
    **rows(cap(K.NAME), "identifier", "type_identifier", "this"),
    "scoped_identifier": cap(K.MEMBER, scope=F.OBJECT, name=F.PROPERTY),  # W3 compound
    "scoped_type_identifier": cap(K.MEMBER),  # W3 compound, no fields
    **rows(cap(K.LITERAL), "string_literal", "decimal_integer_literal", "hex_integer_literal",
           "octal_integer_literal", "binary_integer_literal", "decimal_floating_point_literal",
           "hex_floating_point_literal", "character_literal", "true", "false",
           "null_literal"),
    "template_expression": cap(K.TEMPLATE),
    "binary_expression": cap(K.BINOP),
    **rows(cap(K.UNARY), "unary_expression", "update_expression"),
    "ternary_expression": cap(K.TERNARY),
    **rows(cap(K.DECORATOR), "annotation", "marker_annotation"),  # on a PARAM: R-D input
    "import_declaration": cap(K.IMPORT),
    "array_initializer": cap(K.ARRAY),
    "switch_expression": cap(K.OTHER),
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arms
    "ERROR": cap(K.ERROR),
}

JAVA = LanguageProfile(
    language="java",
    grammar_module="tree_sitter_java",
    grammar_attr="language",
    node_map=frozen(_NODE_MAP),
    scope_rules=ScopeRules(block_scoped=frozenset({"*"}), module_is_scope=False),
    call_shape="object_name",
    builtin_sinks=frozen({
        # L9/W5: the File constructors and the glued pairs Paths.get / Path.of take a path on
        # EVERY argument (`new File(DOC_ROOT, name)` reports on `name`).
        **dict.fromkeys(
            ("file", "fileinputstream", "fileoutputstream", "filereader", "filewriter",
             "randomaccessfile"),
            EVERY_ARG_PATH,
        ),
        **pair("paths", "get", EVERY_ARG_PATH),
        **pair("path", "of", EVERY_ARG_PATH),
        # L3/L7: the program is arg 0; later arguments only after an interpreter + flag.
        "processbuilder": Builtin(COMMAND),
    }),
    arm_types=frozenset(_ARMS),
    pruned=TYPE_ARGUMENTS,
)
