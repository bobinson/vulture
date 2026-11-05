"""Feature 0102 — the consumer rules, per AST-owned check id (LLD §14 "Consumer
rules", D13).

For every id in ``OWNED_CHECK_IDS``: the AST tier owns it on some file of the
``ast_v1`` corpus; its facts travel only as the top-level ``validation.ast`` /
``validation.flow`` keys — never a ``checks[]`` entry (which would make them
voter inputs) and never a top-level finding key (which would change the
finding schema). A future consumer (LLD §14 ladder) joins this contract by
adding its check id to ``OWNED_CHECK_IDS``.

Pinned elsewhere, per id: one owner per file (``test_0102_owner_disjoint``)
and the SKILLS.md ``AST usage`` bullet (``test_0102_skills_md``).

RED until ``shared.ast`` exists, then until the corpus and the consumers exist.
"""

from __future__ import annotations

import pytest

from tests import _ast_v1
from tests._ast_v1 import Finding

AST_FACTS = frozenset({"ast", "flow"})


def _facts_outside_validation(finding: Finding) -> set[str]:
    """AST facts outside the two ``validation`` keys: a ``checks[]`` id or a top-level key."""
    checks = finding.get("validation", {}).get("checks", [])
    return ({c.get("id") for c in checks} | set(finding)) & AST_FACTS


def _misplaced(rows: list[Finding]) -> list[str]:
    return [f["file_path"] for f in rows if _facts_outside_validation(f)]


def _without_facts(rows: list[Finding]) -> list[str]:
    return [f["file_path"] for f in rows if not AST_FACTS <= set(f["validation"])]


def _owned_for(rows: list[Finding], check_id: str) -> list[Finding]:
    return _ast_v1.rows_for(_ast_v1.owned(rows), check_id)


@pytest.mark.parametrize("check_id", _ast_v1.OWNED_CHECK_IDS)
def test_ast_rows_carry_ast_and_flow_under_validation(
    ast_v1_rows: list[Finding], check_id: str,
) -> None:
    ast_rows = _ast_v1.ast_rows(_owned_for(ast_v1_rows, check_id))
    assert ast_rows, f"the AST tier never owns {check_id} on the corpus"
    assert not _without_facts(ast_rows)


@pytest.mark.parametrize("check_id", _ast_v1.OWNED_CHECK_IDS)
def test_ast_facts_never_leave_validation(ast_v1_rows: list[Finding], check_id: str) -> None:
    assert not _misplaced(_owned_for(ast_v1_rows, check_id))
