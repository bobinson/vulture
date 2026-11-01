"""C ``NODE_MAP`` (feature 0102, LLD §6.3; tree-sitter-c 0.24.2). The C++ table extends it.

Scope: CWE-22 (path) and CWE-78 (command) only (D-H) — SSRF stays regex-owned on C, since
its one idiomatic sink is a third-party library's. ``pointer_declarator`` and
``array_declarator`` are unlisted, hence transparent (C4: unwrapped to their identifier);
``function_declarator`` is transparent WITH its own fields (W1). The preprocessor is not
expanded (§16 risk 17): directives that carry no code are pruned, while conditional blocks
(``#ifdef`` ... ``#endif``, every header guard) stay transparent so the code inside them ships.
"""

from __future__ import annotations

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    ASSIGN_LR,
    CALL_FA,
    COMMAND,
    IF_ROW,
    LOOP_BODY,
    NO_FAMILY,
    PATH,
    Builtin,
    LanguageProfile,
    ScopeRules,
    cap,
    frozen,
    rows,
)

__all__ = ["C"]

_ARMS = ("case_statement",)  # L10

_NODE_MAP = {
    "translation_unit": cap(K.MODULE),
    "function_definition": cap(K.FUNCTION, declarator=F.NAME, body=F.BODY),
    # W1: the grammar's `parameters` field belongs to function_declarator.
    "function_declarator": cap(None, declarator=F.NAME, parameters=F.PARAMS),
    "parameter_list": cap(K.ARGS),
    "parameter_declaration": cap(K.PARAM, declarator=F.NAME, type=F.ANNOTATION),
    "compound_statement": cap(K.BLOCK),
    "if_statement": IF_ROW,
    **rows(LOOP_BODY, "for_statement", "while_statement", "do_statement"),
    "switch_statement": cap(K.OTHER),
    ("switch_statement", "compound_statement"): cap(None),  # L10: arms under the switch
    **rows(cap(K.BLOCK), *_ARMS),  # L10 arm
    "return_statement": cap(K.RETURN),
    **rows(cap(K.JUMP), "break_statement", "continue_statement", "goto_statement"),
    # A declaration is the ASSIGN; each init_declarator is transparent and names its LHS and
    # RHS (`int a = 1, b = 2;` -> LHS a, RHS 1, LHS b, RHS 2: bound pairwise, W11). The type
    # is the ANNOTATION the C3 / R-X synthetic constructor CALL takes as its callee (W3).
    "declaration": cap(K.ASSIGN, declarator=F.LHS, type=F.ANNOTATION),
    "init_declarator": cap(None, declarator=F.LHS, value=F.RHS),
    "assignment_expression": ASSIGN_LR,
    "update_expression": cap(K.UNARY),
    "call_expression": CALL_FA,
    "field_expression": cap(K.MEMBER, argument=F.OBJECT, field=F.PROPERTY),
    "subscript_expression": cap(K.SUBSCRIPT, argument=F.OBJECT, index=F.INDEX),
    "pointer_expression": cap(K.UNARY),  # `*p` / `&p`, child kept
    # W3: `type_identifier` is the callee of the C3 / R-X synthetic constructor call.
    **rows(cap(K.NAME), "identifier", "field_identifier", "type_identifier"),
    **rows(cap(K.LITERAL), "string_literal", "concatenated_string", "char_literal",
           "number_literal", "true", "false", "null"),
    "binary_expression": cap(K.BINOP),
    "unary_expression": cap(K.UNARY),
    "conditional_expression": cap(K.TERNARY),
    "ERROR": cap(K.ERROR),
}

_BUILTINS = {
    # L9/P4: openat(dirfd, path, flags) - arg 0 is a directory fd.
    "openat": Builtin(PATH, path_args=(1,)),
    # C5/P4/R5: arg 0 is an fd (read, write) or a buffer (fread, fgets, fwrite), never a path;
    # the EMPTY family set overrides the generic `read`/`write` path words (the one shared
    # ``NO_FAMILY`` entry, A47 (2) (i)).
    **dict.fromkeys(("read", "fread", "fgets", "write", "fwrite"), NO_FAMILY),
    # posix_spawn(pid, path, actions, attrs, argv, envp): the program is arg 1.
    "posixspawn": Builtin(COMMAND, command_args=(1,)),
}

C = LanguageProfile(
    language="c",
    grammar_module="tree_sitter_c",
    grammar_attr="language",
    node_map=frozen(_NODE_MAP),
    scope_rules=ScopeRules(block_scoped=frozenset({"*"})),
    builtin_sinks=frozen(_BUILTINS),
    owned_families=PATH | COMMAND,  # D-H: the families C and C++ own
    arm_types=frozenset(_ARMS),
    pruned=frozenset({"preproc_include", "preproc_def", "preproc_function_def", "preproc_call"}),
    main_argv=("main", 1),  # C4 (P6): argv is `main`'s second parameter, by position
)
