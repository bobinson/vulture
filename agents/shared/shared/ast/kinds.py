"""The closed node-kind and field sets of the AST layer (feature 0102, LLD §6.1, D4).

Every shipped node carries one ``Kind`` and the ``Field`` under which it hangs from its
parent. Both are ``IntEnum``s because the worker ships them as parallel int arrays and the
boundary validator range-checks them (§6.2). ``OTHER`` is the largest kind (the opaque
statement passthrough) and ``NONE`` the largest field (a positional child).
"""

from __future__ import annotations

from enum import IntEnum, auto

__all__ = ["Field", "Kind"]


class Kind(IntEnum):
    """The 41 node kinds (LLD §6.1), in the LLD's order; ``OTHER`` is last."""

    MODULE = 0
    FUNCTION = auto()
    CLASS = auto()
    PARAM = auto()
    BLOCK = auto()
    IF = auto()
    LOOP = auto()
    TRY = auto()
    CATCH = auto()
    FINALLY = auto()
    WITH = auto()
    RETURN = auto()
    THROW = auto()
    JUMP = auto()
    ASSIGN = auto()
    AUG_ASSIGN = auto()
    CALL = auto()
    MEMBER = auto()
    SUBSCRIPT = auto()
    NAME = auto()
    LITERAL = auto()
    TEMPLATE = auto()
    BINOP = auto()
    UNARY = auto()
    TERNARY = auto()
    AWAIT = auto()
    SPREAD = auto()
    DESTRUCT = auto()
    IMPORT = auto()
    EXPORT = auto()
    DECORATOR = auto()
    ARGS = auto()
    KWARG = auto()
    OBJECT = auto()
    ARRAY = auto()
    PAIR = auto()
    YIELD = auto()
    GLOBAL = auto()
    COMPREHENSION = auto()
    ERROR = auto()
    OTHER = auto()


class Field(IntEnum):
    """The 21 fields a node can hang under (LLD §6.1); ``NONE`` (positional) is last.

    ``ANNOTATION`` marks the NAME children of a PARAM that come from its type annotation or
    its decorator, so R-D can read them (W4).
    """

    CALLEE = 0
    ARGS = auto()
    LHS = auto()
    RHS = auto()
    NAME = auto()
    VALUE = auto()
    BODY = auto()
    TEST = auto()
    CONSEQ = auto()
    ALT = auto()
    PARAMS = auto()
    OBJECT = auto()
    PROPERTY = auto()
    INDEX = auto()
    TARGET = auto()
    ITER = auto()
    SOURCE = auto()
    KEY = auto()
    HANDLER = auto()
    ANNOTATION = auto()
    NONE = auto()
