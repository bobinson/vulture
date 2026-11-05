"""Feature 0102 — SKILLS.md documents the AST tier for every migrated check id
(LLD §9.5).

Each migrated skill's section carries an ``**AST usage**`` bullet that names
the check ids the AST tier owns there and states its ``Known gaps``. The
section is derived from the check id itself (``cwe.<skill>.<rule>`` is emitted
by ``<skill>_check``), so a check id added to ``OWNED_CHECK_IDS`` is covered
here without editing this file.

RED until SKILLS.md gains the bullets.
"""

from __future__ import annotations

import pytest

from tests import _ast_v1

MIGRATED = sorted({_ast_v1.skill_of(check_id) for check_id in _ast_v1.OWNED_CHECK_IDS})


@pytest.mark.parametrize("check_id", _ast_v1.OWNED_CHECK_IDS)
def test_ast_usage_bullet_names_the_check_id(check_id: str) -> None:
    skill = _ast_v1.skill_of(check_id)
    assert check_id in _ast_v1.ast_bullet(skill), (
        f"## {skill}: no {_ast_v1.BULLET} bullet naming {check_id}"
    )


@pytest.mark.parametrize("skill", MIGRATED)
def test_ast_usage_bullet_states_known_gaps(skill: str) -> None:
    assert "Known gaps" in _ast_v1.ast_bullet(skill), (
        f"## {skill}: {_ast_v1.BULLET} bullet has no Known gaps"
    )
