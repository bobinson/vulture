"""C++ ``NODE_MAP`` (feature 0102, LLD §6.3; tree-sitter-cpp 0.23.4): the C profile plus the
C++ rows. Same CWE-22 + CWE-78 scope as C (D-H).

``reference_declarator``, ``subscript_argument_list`` and ``template_declaration`` are
unlisted, hence transparent (C4, W15 e). ``template_argument_list`` is pruned for the reason
``type_arguments`` is elsewhere (W1): ``std::make_shared<Foo>(x)``'s callee must end in
``make_shared``, not in a type argument.

Two declarations are calls. C3 (A28 (9)): the ``argument_list`` an ``init_declarator`` takes
as its value (``std::ifstream in(p.c_str())``) is a stack constructor: its row makes the worker
ship a synthetic CALL, the declarator's RHS, whose CALLEE is a copy of the declaration's type
and whose ARGS container is the list (``Capture.callee_from``). R-X (C2): a vexing parse
(``std::ifstream in(docPath);``) ships as C's local prototype — an ASSIGN holding the type
(ANNOTATION), the declared name (NAME) and the parameter list (PARAMS) whose bare types are
NAMEs — the candidate the scope pass confirms as a constructor call (``constructors``) only
when every such NAME reads an in-scope local or param Def. A36: a vexing parse whose one
parameter is a type name over an ``abstract_array_declarator`` (``std::ifstream in(argv[1]);``)
ships its parameter list, still under PARAMS, as C3's synthetic CALL, the parameter its one
argument as SUBSCRIPT(NAME, INDEX) (``Capture.subscript``); the scope pass keeps it a call only
when that NAME reads an in-scope Def, else it is a prototype (``prototypes``). Casts,
qualified types and several arguments keep the prototype shape (a SKILLS.md known gap).
"""

from __future__ import annotations

from dataclasses import replace

from shared.ast.kinds import Field as F
from shared.ast.kinds import Kind as K
from shared.ast.profiles import (
    CLASS_ROW,
    PATH,
    TRY_BODY,
    Builtin,
    Capture,
    Subscript,
    cap,
    frozen,
    rows,
)
from shared.ast.profiles.c import C

__all__ = ["CPP"]

_CPP_ROWS = {
    **rows(CLASS_ROW, "class_specifier", "struct_specifier"),
    "namespace_definition": cap(K.OTHER),  # body walked
    "lambda_expression": cap(K.FUNCTION, declarator=F.PARAMS, body=F.BODY),
    "abstract_function_declarator": cap(None, parameters=F.PARAMS),  # W1: a lambda's params
    "try_statement": TRY_BODY,
    "catch_clause": cap(K.CATCH, parameters=F.PARAMS, body=F.BODY),
    "new_expression": cap(K.CALL, type=F.CALLEE, arguments=F.ARGS),
    "throw_statement": cap(K.THROW),
    "qualified_identifier": cap(K.MEMBER, scope=F.OBJECT, name=F.PROPERTY),  # W3 compound
    **rows(cap(K.NAME), "namespace_identifier", "this"),
    "raw_string_literal": cap(K.LITERAL),  # `nullptr` ships through C's `null` row
    "subscript_expression": cap(K.SUBSCRIPT, argument=F.OBJECT, indices=F.INDEX),  # W15 e
    "for_range_loop": cap(K.LOOP, declarator=F.TARGET, right=F.ITER, body=F.BODY),
    # C3: a stack constructor's arguments; the CALLEE is the declaration's type (ANNOTATION).
    ("init_declarator", "argument_list"): Capture(K.CALL, callee_from=F.ANNOTATION),
    # A36: a declarator's parameter list over one subscript is C3's CALL; any other keeps C's row.
    ("function_declarator", "parameter_list"): replace(
        C.node_map["parameter_list"],
        callee_from=F.ANNOTATION,
        subscript=Subscript(
            "parameter_declaration", "abstract_array_declarator", object="type",
            declarator="declarator", index="size",
        ),
    ),
}

# C's owned families, arm types and `main` argv (C4) hold as they are; the scope rules are C's
# with the vexing parse (C2, R-X); the table, the builtins and the pruned set are C's plus
# C++'s own.
CPP = replace(
    C,
    language="cpp",
    grammar_module="tree_sitter_cpp",
    node_map=frozen(C.node_map | _CPP_ROWS),
    scope_rules=replace(C.scope_rules, vexing_parse=True),
    # C's builtins (R5: C++ inherits the empty read/write sets) plus the stream
    # constructors, reached through the C3 / R-X synthetic CALL or `.open(p)`.
    builtin_sinks=frozen(C.builtin_sinks | dict.fromkeys(("ifstream", "ofstream", "fstream"), Builtin(PATH))),
    pruned=C.pruned | {"template_argument_list"},
)
