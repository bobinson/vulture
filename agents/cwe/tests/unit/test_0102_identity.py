"""Feature 0102 — a migrated check keeps its identity whichever tier emits it
(LLD invariant 3, D11, D19).

The regex body and the AST head of a migrated rule share one ``FamilyRule``
constant, so ``(check_id, category, title, severity, recommendation)`` cannot
drift between them. Pinned on the rows themselves: per owned check id, the
corpus rows of BOTH tiers and the pre-0102 regex snapshot rows carry exactly
the identity the regex tier emitted before 0102 (``identity.json``). An AST row
also anchors at its sink line: ``line_start == line_end`` and
``evidence_quote`` is that line of the text the skill read, numbered by
``\\n`` only (D21).

RED until ``shared.ast`` exists, then until the AST tier emits the rows.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from itertools import chain
from pathlib import Path

import pytest

from shared.tools.file_scanner import read_file_safe
from tests import _ast_v1
from tests._ast_v1 import Finding

IDENTITY = ("check_id", "category", "title", "severity", "recommendation")
# Per owned check id, the identity the regex tier emitted before any 0102 code
# existed (captured with the snapshot groups; SSRF has no snapshot-group row).
_PRE_0102 = {
    check_id: tuple(row[key] for key in IDENTITY)
    for check_id, row in json.loads(
        (_ast_v1.SNAPSHOT_DIR / "identity.json").read_text(encoding="utf-8")).items()
}


def _identity(row: Finding) -> tuple[object, ...]:
    return tuple(row[key] for key in IDENTITY)


def _ast_only(rows: list[Finding]) -> list[Finding]:
    """The AST tier's rows of an owned check id; none at all fails the caller
    (a property of zero rows proves nothing)."""
    found = _ast_v1.ast_rows(_ast_v1.owned(rows))
    assert found, "no AST-owned row on the corpus"
    return found


def _where(finding: Finding) -> tuple[str, int]:
    return finding["file_path"], finding["line_start"]


def _quotes_its_line(finding: Finding) -> bool:
    """``evidence_quote`` is the row's own line of the text the skill read
    (one buffer, numbered by ``\\n`` only — D21)."""
    text = read_file_safe(Path(finding["file_path"])) or ""
    line = text.split("\n")[finding["line_start"] - 1]
    return finding.get("evidence_quote", "").strip() == line.strip()


def _multi_line(rows: Iterable[Finding]) -> list[tuple[str, int]]:
    return [_where(f) for f in rows if f["line_end"] != f["line_start"]]


def _misquoted(rows: Iterable[Finding]) -> list[tuple[str, int]]:
    return [_where(f) for f in rows if not _quotes_its_line(f)]


@pytest.mark.parametrize("check_id", _ast_v1.OWNED_CHECK_IDS)
def test_one_identity_per_owned_check_id(ast_v1_rows: list[Finding], check_id: str) -> None:
    """Both tiers' corpus rows and the pre-0102 snapshot rows carry exactly the
    identity the regex tier emitted before 0102 (``identity.json``)."""
    corpus = _ast_v1.owned(ast_v1_rows)
    snapshot = list(chain.from_iterable(map(_ast_v1.load_snapshot, _ast_v1.GROUPS)))
    rows = _ast_v1.rows_for([*corpus, *snapshot], check_id)
    assert set(map(_identity, rows)) == {_PRE_0102[check_id]}


def test_ast_rows_span_their_sink_line_only(ast_v1_rows: list[Finding]) -> None:
    assert not _multi_line(_ast_only(ast_v1_rows))


def test_ast_rows_quote_their_sink_line(ast_v1_rows: list[Finding]) -> None:
    assert not _misquoted(_ast_only(ast_v1_rows))
