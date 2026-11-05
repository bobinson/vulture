"""Feature 0102 — the regex bodies are the permanent per-file fallback, and they
are unchanged (LLD D10, D12, §12).

There is no flag: a file the AST tier cannot parse is regex-owned, and the
regex bodies are reached by that parse outcome alone. Pinned against the
pre-0102 snapshot in ``_0102_regex_snapshot/`` (the owned check ids' rows on
``fixtures/p8_inputval`` and ``fixtures/injection``, captured before any 0102
code existed): every snapshot fixture made unparseable (a stray ``)(``
appended — an ERROR node in every v1 grammar, after every row, so no line
moves) yields exactly the snapshot, byte for byte, through the real skills
and their real dispatchers, and no row carries ``validation.ast``.

RED until ``shared.ast`` exists.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

import corpus_runner
import pytest

from tests import _ast_v1
from tests._ast_v1 import Finding


class _Unparseable(NamedTuple):
    group: str
    root: Path
    rows: list[Finding]  # every row of the two migrated skills


@pytest.fixture(scope="module", params=_ast_v1.GROUPS)
def unparseable(request: pytest.FixtureRequest) -> _Unparseable:
    group = request.param
    root = _ast_v1.copy_fixtures(request, src=corpus_runner.FIXTURES_DIR / group)
    for path in root.iterdir():
        path.write_bytes(path.read_bytes() + _ast_v1.UNPARSEABLE.encode())
    return _Unparseable(group, root, _ast_v1.migrated_rows(root))


def test_the_ast_does_not_own_an_unparseable_file(unparseable: _Unparseable) -> None:
    owned = _ast_v1.ast_owned(unparseable.root.iterdir())
    assert not owned, sorted(owned)


def test_an_unparseable_file_carries_no_ast_evidence(unparseable: _Unparseable) -> None:
    assert not _ast_v1.ast_rows(_ast_v1.owned(unparseable.rows))


def test_an_unparseable_file_yields_the_regex_snapshot(unparseable: _Unparseable) -> None:
    rows = _ast_v1.owned(unparseable.rows)
    assert _ast_v1.as_snapshot(rows, unparseable.group) == _ast_v1.snapshot_text(unparseable.group)
