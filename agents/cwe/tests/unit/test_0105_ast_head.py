"""Feature 0105 (LLD §4.6): the cwe head reads one model per family, however many rules ask.

``injection_check`` asks the AST tier for three rules per file: CWE-918 (the ``request``
family) and two rules on the ``command`` family, CWE-78 (``_RULE_78``) and CWE-89
(``_RULE_89``, the statement flows a command site re-labels). ``_ast_head.ast_answers`` asks
``owns_answer`` once for each family the rules name and the prefilter found, then
``family_spans`` per rule. A third rule on the command family therefore adds no
``owns_answer``, so no cache ``hit`` event and no prefetch step per file: ``tallies.cache`` and
the prefetch walk stay as they were with two rules. ``family_spans`` twice on one answer is
safe (``accepts`` sends each flow to one rule's ``decide``), so each rule's spans are what it
gets when asked alone.

Pinned on a request handler with a command sink and a request sink, each fed by the request:
``owns_answer`` is called exactly twice (a spy), the request and command rules each report
their sink while CWE-89 reports nothing (the command call has process evidence), and each
rule's spans equal its spans asked alone.

RED until P3: ``_RULE_89`` does not exist, and today the head asks ``owns_answer`` once per
rule. ``_RULE_89`` is imported in the test body, so its absence fails this test instead of
interrupting the session.
"""

from __future__ import annotations

import contextvars
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from cwe_agent.skills import _ast_head
from cwe_agent.skills._ast_head import AstAnswer
from cwe_agent.skills.injection_check import _RULE_78, _RULE_918
from shared.ast import cache as ast_cache
from shared.ast import context

# A request handler: a command sink on line 4 and a request sink on line 5.
HANDLER = (
    'const cp = require("child_process");\n'
    "\n"
    "function handle(req, res) {\n"
    "  cp.exec(req.query.cmd);\n"
    "  fetch(req.query.url);\n"
    "}\n"
)


class Asked(NamedTuple):
    """``ast_answers`` for several rules at once, its ``owns_answer`` calls, and each rule's
    answer asked alone."""

    together: tuple[AstAnswer, ...]
    owns_calls: int
    alone: tuple[AstAnswer, ...]


def _spied(patch: pytest.MonkeyPatch, calls: list[Any]) -> None:
    """``owns_answer`` recording each call, in ``cache`` and wherever the head bound it."""
    real = ast_cache.owns_answer

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return real(*args, **kwargs)

    patch.setattr(ast_cache, "owns_answer", spy)
    if hasattr(_ast_head, "owns_answer"):
        patch.setattr(_ast_head, "owns_answer", spy)


def _audited(path: Path, rules: Sequence[Any]) -> Asked:
    """In a new audit of ``path``'s directory: the rules asked together under the spy, then
    each asked alone."""
    context.enter(path.parent)
    text = path.read_text()
    calls: list[Any] = []
    with pytest.MonkeyPatch.context() as patch:
        _spied(patch, calls)
        together = _ast_head.ast_answers(path, text, rules)
    alone = tuple(_ast_head.ast_answers(path, text, (rule,))[0] for rule in rules)
    return Asked(together, len(calls), alone)


def _asked(path: Path, rules: Sequence[Any]) -> Asked:
    """``_audited`` in a copied context, as the runner submits a skill: its audit is its own."""
    return contextvars.copy_context().run(_audited, path, rules)


def _lines(answers: Sequence[AstAnswer]) -> list[list[int] | None]:
    """Each answer's reported span lines, sorted; None for a file the regex body owns."""
    return [None if a.spans is None else sorted(a.spans) for a in answers]


def test_three_rules_read_one_model_per_family(tmp_path: Path) -> None:
    from cwe_agent.skills.injection_check import _RULE_89

    path = tmp_path / "handler.js"
    path.write_text(HANDLER)
    found = _asked(path, (_RULE_918, _RULE_78, _RULE_89))
    assert found.owns_calls == 2, "owns_answer is asked once per family"
    assert _lines(found.together) == [[5], [4], []]
    assert [a.spans for a in found.together] == [a.spans for a in found.alone]
