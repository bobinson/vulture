"""Feature 0102 — an AST row is answerable by the lineage evidence ladder
(LLD D11, D24; feature 0091 §6.2).

An AST-owned row anchors at its sink line and quotes it (D11). The lineage
ladder then answers from the CODE: ``confirmed`` while the sink line is in the
file, ``gone`` once it is deleted — and still ``confirmed`` once a syntax error
makes the file unparseable, because a parse failure is a fact about the
checker, never evidence of a fix.

The handler below is a two-statement flow: the request value is parked in a
local, so the sink line itself names no request source and the regex tier
cannot see it. That is exactly the AST-only row D24 protects — after the file
falls back to regex nothing re-reports it, and only its quote can say it is
still there. The source is written here, not taken from the corpus, so the
quote's length and its distance from every other line (which decide
``exact``/``absent`` against ``near_miss``) are fixed by this file.

RED until ``shared.ast`` exists, then until the CWE-22 AST head emits the row.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from shared import quote_store
from shared.lineage_checks import verify_lineage_checks
from shared.testing.lineage import local_quote_store
from shared.tools.file_scanner import clear_caches
from tests import _ast_v1
from tests._ast_v1 import Finding
from tests._neutral import neutral_dir

PATH_TRAVERSAL = "cwe.input_validation.path_traversal"
REL_PATH = "src/ledger.js"
SINK = '  const ledgerBytes = fs.readFileSync(ledgerName, { encoding: "latin1" });'
LINES = (
    'const fs = require("fs");',
    "",
    "function serveArchivedLedger(req, res) {",
    "  const ledgerName = req.query.ledger;",
    SINK,
    "  res.status(200).end(ledgerBytes);",
    "}",
    "",
    "module.exports = { serveArchivedLedger };",
    "",
)
SOURCE = "\n".join(LINES)
SINK_LINE = LINES.index(SINK) + 1

# The file as a later scan finds it -> what the ladder must answer.
EDITS = {
    "unchanged": (SOURCE, "confirmed"),
    "sink_line_deleted": ("\n".join(line for line in LINES if line != SINK), "gone"),
    "syntax_error_appended": (SOURCE + _ast_v1.UNPARSEABLE, "confirmed"),
}


@pytest.fixture(autouse=True)
def _local_quote_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    # No anchor.clear_cache() here: every _write() calls clear_caches(), which drops it.
    yield from local_quote_store(monkeypatch, tmp_path)


@pytest.fixture
def repo(request: pytest.FixtureRequest) -> Path:
    root = neutral_dir(request) / "repo"
    (root / "src").mkdir(parents=True)
    _write(root, SOURCE)
    return root


def _write(root: Path, text: str) -> None:
    """Replace the handler and drop the path-keyed caches, as a new scan would."""
    (root / REL_PATH).write_text(text, encoding="utf-8")
    clear_caches()


def _ast_rows(root: Path) -> list[Finding]:
    return _ast_v1.ast_rows(_ast_v1.rows_for(_ast_v1.owned_rows(root), PATH_TRAVERSAL))


def _lineage_row(finding: Finding) -> dict[str, Any]:
    """The backend's question about ``finding``; its quote stored as the emit path stores it."""
    return {
        "lineage_id": "ln-0102-ast",
        "rel_path": REL_PATH,
        "line_start": finding["line_start"],
        "line_end": finding["line_end"],
        "quote_hash": quote_store.store_by_hash(finding["evidence_quote"]),
        "status": "open",
    }


def test_the_ast_row_quotes_its_sink_line(repo: Path) -> None:
    rows = _ast_rows(repo)
    assert [(f["line_start"], f["line_end"]) for f in rows] == [(SINK_LINE, SINK_LINE)], rows
    assert rows[0]["evidence_quote"].strip() == SINK.strip()


def test_the_appended_error_is_a_parse_failure(repo: Path) -> None:
    from shared.ast import owns

    _write(repo, SOURCE + _ast_v1.UNPARSEABLE)
    assert owns(repo / REL_PATH) is None


@pytest.mark.parametrize(("text", "outcome"), list(EDITS.values()), ids=list(EDITS))
def test_the_ladder_answers_from_the_code(repo: Path, text: str, outcome: str) -> None:
    rows = _ast_rows(repo)
    assert len(rows) == 1, rows
    question = _lineage_row(rows[0])
    _write(repo, text)
    assert [c["outcome"] for c in verify_lineage_checks([question], repo)] == [outcome]
