"""Feature 0102 plan task 2.2: 0101's identifier splitter and the AST layer's ``words`` are ONE
function (LLD §9.1 mode (c): ``roles.words`` = 0101's ``identifier_words``; A10).

The splitter's one definition moves to ``shared/ast/roles/_words.py``; ``cwe_agent.skills.
_lexical`` re-exports it, so a fix to how an identifier splits lands in the 0101 rules and in
the AST tier's word lexicons at once. Identity is the proof: the SAME object, not a copy.

RED until ``shared.ast.roles`` exists: the import inside the test fails with
``ModuleNotFoundError``; then until ``_lexical`` re-exports the shared function.
"""

from __future__ import annotations


def test_identifier_words_is_the_shared_words() -> None:
    """``cwe_agent.skills._lexical.identifier_words is shared.ast.roles.words``."""
    from cwe_agent.skills import _lexical
    from shared.ast import roles

    assert _lexical.identifier_words is roles.words
