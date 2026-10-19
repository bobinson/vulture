"""The cwe side of the AST tier's consumer head (feature 0102, LLD §9.2, §9.3; D10, D19, D21,
A41 (5)).

WHY THIS EXISTS
---------------
Every check the cwe agent moves to the AST tier — CWE-22 in ``input_validation_check``,
CWE-918 and CWE-78 in ``injection_check`` — asks the tier about a file the same way: the D10
ownership decision (the prefilter, then ``owns``), the spans of the check's family, and the
lines its rows are numbered from. One copy here, so no two heads can decide ownership
differently (``test_0102_owner_disjoint``).

CONTRACT
--------
``ast_answers(file_path, text, rules, server_ctx)`` is the tier's answer for one file and each
rule (``AstAnswer``), asked once per file; ``ast_spans`` is its one-rule form. ``claim`` is
``shared.ast.consume.emit_for_line`` over an answer, with the catalog's ``enrich_finding``,
which ``shared.ast`` cannot import (A41 (5)). ``ast_owns`` is the head of a check the tier owns
line by line (LLD §9.3: CWE-918, CWE-78): the row of a reported sink at its line, and whether
the regex body may run at all. CWE-22's head reads the same answer
(``input_validation_check._ast_claims``), its claim chain around it. ``regex_row`` is a regex
body's row: the rule's identity row (``consume.rule_row``, D19), enriched as the AST row is.
The model, the cache and the lexicons are imported where ``ast_answers`` first needs them, as
``consume`` imports its own: importing a skill loads no worker pool, profile or model (D1).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from cwe_agent.catalog import enrich_finding
from shared.ast.consume import emit_for_line, family_spans, rule_row
from shared.ast.context import current

if TYPE_CHECKING:
    from shared.ast.consume import FamilyRule
    from shared.ast.flow import Flow
    from shared.ast.model import FileModel

__all__ = ["FALLBACK", "AstAnswer", "ast_answers", "ast_owns", "ast_spans", "claim", "regex_row"]


class AstAnswer(NamedTuple):
    """The AST tier's answer for one file and one rule (``ast_answers``)."""

    # Each line of every reported sink span -> its flow; None when the regex body owns the file.
    spans: Mapping[int, Flow] | None
    # The model's ``text.split("\n")`` (D21), the lines a row is numbered and quoted from.
    nl_lines: Sequence[str]


# The answer for a file the AST tier falls back on: the regex body owns it (D10).
FALLBACK = AstAnswer(None, ())


def ast_answers(
    file_path: Path, text: str, rules: Sequence[FamilyRule], server_ctx: bool = True
) -> tuple[AstAnswer, ...]:
    """The AST tier's answer for each of ``rules`` on ``file_path``, in order (LLD §9.2): the
    prefilter reads the text once for every rule's family (``needed_families``: one glued
    view), BEFORE any parse — a file with no sink key of a family is never shipped to a worker
    for it, so it skips the parse, not just the flow pass. Each rule still asks ``owns`` on its
    own (``_answer``)."""
    from shared.ast.roles import needed_families

    needed = needed_families(text, {rule.family for rule in rules})
    return tuple(_answer(file_path, rule, needed, server_ctx) for rule in rules)


def ast_spans(
    file_path: Path, text: str, rule: FamilyRule, server_ctx: bool = True
) -> AstAnswer:
    """``ast_answers`` for the one ``rule``."""
    return ast_answers(file_path, text, (rule,), server_ctx)[0]


def _answer(file_path: Path, rule: FamilyRule, needed: Set[str], server_ctx: bool) -> AstAnswer:
    """The AST tier's answer for ``rule`` on ``file_path``, ``needed`` the families the
    prefilter found a sink key of.

    The spans: each line of every ``rule.family`` sink span the tier reports -> its flow,
    declines recorded on the current audit against this file; ``{}`` for an owned file that
    cannot hold such a sink; None when the regex body owns the file (no profile, a profile
    that owns no ``rule.family`` — C and C++ own no ``request``, so CWE-918 stays regex-owned
    there (LLD §6.3) — no model, an ERROR node, the breaker open — D10). The lines: the
    model's ``nl_lines``, the ``text.split("\\n")`` (D21) of the very text the spans index;
    ``()`` with no model."""
    if rule.family not in needed:
        return AstAnswer({} if _owned(file_path, rule.family) else None, ())
    model = _family_model(file_path, rule.family)
    if model is None:
        return FALLBACK
    spans = family_spans(model, rule, current(), file_path, server_ctx=server_ctx)
    return AstAnswer(spans, model.nl_lines)


def _owned(file_path: Path, family: str) -> bool | None:
    """D10 by extension alone, never a parse: whether the file's profile owns ``family``
    (§6.3 ``owned_families``); None when its language has no profile."""
    from shared.ast.profile import profile_for

    profile = profile_for(file_path)
    return None if profile is None else family in profile.owned_families


def _family_model(file_path: Path, family: str) -> FileModel | None:
    """``owns`` (D10: a model, no ERROR node, the breaker closed), unless the file's profile
    owns no ``family`` — then None, and no parse. A file with no profile still asks ``owns``,
    which tallies it ``unsupported`` (§10.2)."""
    from shared.ast.cache import owns

    return None if _owned(file_path, family) is False else owns(file_path)


def claim(
    answer: AstAnswer, rule: FamilyRule, file_path: Path, line_num: int, findings: list[Any]
) -> bool:
    """True when ``line_num`` lies in a sink span ``answer`` reports — the AST owns the line —
    and then, at the sink line itself, the row appended (``emit_for_line``, enriched as the
    regex body's rows are): one per sink. A line outside every span is answered without
    building the call (most lines of an owned file)."""
    spans = answer.spans
    if not spans or line_num not in spans:
        return False
    return emit_for_line(
        spans, line_num, rule, file_path=file_path, nl_lines=answer.nl_lines,
        findings=findings, enrich=enrich_finding,
    )


def ast_owns(
    answer: AstAnswer, rule: FamilyRule, file_path: Path, line_num: int, findings: list[Any]
) -> bool:
    """The head of a check the AST tier owns line by line (LLD §9.3): True when the tier owns
    ``rule``'s check on the file — ``answer`` holds its spans — and then, when ``line_num`` is
    a reported sink line, the row appended (``claim``); False when the regex body owns the
    file and runs on the line."""
    if answer.spans is None:
        return False
    claim(answer, rule, file_path, line_num, findings)
    return True


def regex_row(
    rule: FamilyRule, description: str, file_path: Path, line_num: int, lines: Sequence[str],
    **extra: Any,
) -> dict[str, Any]:
    """A regex body's row at ``line_num``: ``rule``'s identity row (``consume.rule_row``, D19)
    with the body's own ``description`` and ``extra`` keys, numbered from ``lines``,
    enriched."""
    row = rule_row(rule, description, file_path=file_path, line=line_num, lines=lines, **extra)
    return enrich_finding(row, rule.cwe_id)
