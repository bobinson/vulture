"""Feature 0102 — one owner per migrated check id per file (LLD D10, D12, §12).

The AST tier owns ``shared.ast.OWNED_CHECK_IDS`` on every file it parses
cleanly; the regex bodies own them on every file it cannot. Which tier owns a
file is decided by the parse outcome alone — there is no flag — and the two
tiers never both emit one check id on one file. An AST row says so under
``validation.ast`` (``engine: "ast"``, D13); a row without it is a regex row.

RED until ``shared.ast`` exists: each test reads the tier's own
``OWNED_CHECK_IDS`` (or ``owns``) in its body, so it fails as a named test on
``No module named 'shared.ast'``.
"""

from __future__ import annotations

from tests import _ast_v1
from tests._ast_v1 import Finding


def test_owned_check_ids_are_the_three_families() -> None:
    """The literal every 0102 test is parametrized over IS the tier's set."""
    from shared.ast import OWNED_CHECK_IDS

    assert OWNED_CHECK_IDS == set(_ast_v1.OWNED_CHECK_IDS)


def test_one_owner_per_check_id_per_file(ast_v1_rows: list[Finding]) -> None:
    both = _ast_v1.contested(_ast_v1.owned(ast_v1_rows))
    assert not both, both


def test_both_tiers_own_files_on_the_corpus(ast_v1_rows: list[Finding]) -> None:
    """Non-vacuity: the group has clean-parsing positives (AST-owned) and a
    trailing-syntax-error positive (regex-owned), so the disjointness above is
    measured across both tiers rather than inside one."""
    engines = {_ast_v1.engine_of(f) for f in _ast_v1.owned(ast_v1_rows)}
    assert engines == {"ast", "regex"}


def test_ast_rows_only_on_files_the_ast_owns(ast_v1_rows: list[Finding]) -> None:
    """``owns(path)`` is the whole ownership rule (D10): no model, an ERROR
    node, or a tripped breaker leaves the file to the regex tier."""
    ast_files = {f["file_path"] for f in _ast_v1.ast_rows(_ast_v1.owned(ast_v1_rows))}
    unowned = ast_files - _ast_v1.ast_owned(ast_files)
    assert not unowned, sorted(unowned)
