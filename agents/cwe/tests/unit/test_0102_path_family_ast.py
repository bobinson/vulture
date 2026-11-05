"""Feature 0102 — CWE-22 is owned by the AST tier on every file it parses (LLD §9.2, D10,
D11, D19; plan task 3.2).

The path leaf of ``input_validation_check`` gains the one consumer head: on a file ``owns()``
models, ``_ast_spans`` maps every line of a reported sink's call to its flow and
``_claim_path_row`` hands those lines to ``emit_for_line`` — one row, at the sink line, with
``validation.ast`` — before any sibling path rule (CWE-36/23/73) runs on them; any other line
of that file has no CWE-22. A file the AST cannot model reaches the former body, renamed
``_check_path_traversal_regex`` and unchanged.

Pinned here, on the ``ast_v1`` fixtures the plan names: the two-statement flow
(``cwe_22_1.js``), the four-line call (``cwe_22_16.js``), the sanitised twin and its decline
(``cwe_22_1_clean.js``), the ten ``TestCWE22Negatives`` twins, and the fallback of a
snapshot fixture made unparseable, served by the renamed body.

Pinned elsewhere: one owner per check id per file (``test_0102_owner_disjoint``); the
identity and sink-line quote of every AST row (``test_0102_identity``); every snapshot
fixture made unparseable, through both skills (``test_0102_fallback_parity``); the fallback
tallies (``test_0102_fallback``); ``family_spans`` and ``emit_for_line`` themselves (the
shared suite's ``test_0102_finding``).

RED until the head lands: the AST rows, the span claim, the decline and the renamed body do
not exist yet. The no-blunder twins and the fallback rows are regex behaviour today and must
stay exactly so.
"""

from __future__ import annotations

import json
from operator import attrgetter
from pathlib import Path

import corpus_runner
import pytest

from cwe_agent.skills import input_validation_check
from cwe_agent.skills.input_validation_check import check_input_validation
from tests import _ast_heads, _ast_v1
from tests._ast_heads import PATH_ID

TWO_STATEMENT = "cwe_22_1.js"  # req.query.f bound to p, then fs.readFile(p), all on line 2
FOUR_LINE_CALL = "cwe_22_16.js"  # fs.readFile( on line 3, its arguments on lines 4-6
SANITISED = "cwe_22_1_clean.js"  # cwe_22_1 with path.basename around the request value
# Line 2 of each is one line of test_no_blunders.py's TestCWE22Negatives.
NB_TWINS = tuple(sorted(p.name for p in _ast_v1.AST_V1.glob("cwe_22_nb_*_clean.*")))

# The pre-0102 snapshot fixture whose CWE-22 row the fallback must reproduce, and where its
# unparseable copy is staged.
GROUP, SNAPSHOT_FIXTURE = "p8_inputval", "cwe_23_1_clean.js"
BROKEN = _ast_heads.unparsed(SNAPSHOT_FIXTURE)

# CWE-73, the sibling claim that fires on cwe_22_16.js line 4 (a path.join of req.query.f with
# no I/O on that line) while the regex tier owns the file.
EXTERNAL_PATH_ID = input_validation_check._EXTERNAL_PATH_RULE.check_id
# Every line of the call's span, which ``emit_for_line`` claims (LLD §9.2, A41 (10)): the call
# spans lines 3-6 (the shared ``test_0102_finding._FOUR_LINE_CALL``).
SIBLING_SILENT_LINES = range(3, 7)


@pytest.fixture(scope="module")
def root(request: pytest.FixtureRequest) -> Path:
    """The named ``ast_v1`` files, each AST-owned, and one unparseable snapshot fixture."""
    root = _ast_v1.stage(request, (TWO_STATEMENT, FOUR_LINE_CALL, SANITISED, *NB_TWINS))
    _ast_heads.stage_unparseable(root, corpus_runner.FIXTURES_DIR / GROUP / SNAPSHOT_FIXTURE)
    return root


def _scan(root: Path) -> _ast_heads.Scan:
    return _ast_heads.scan(check_input_validation, root)


def _rows(root: Path, rel: str, check_id: str = PATH_ID) -> list[tuple[int, str | None]]:
    return _ast_heads.rows_at(_scan(root), root, rel, check_id)


def test_two_statement_flow_is_one_ast_row_at_its_sink(root: Path) -> None:
    assert _rows(root, TWO_STATEMENT) == [(2, "ast")]


def test_four_line_call_is_one_ast_row_at_its_first_line(root: Path) -> None:
    """``emit_for_line`` appends at the sink line only, however many span lines it claims."""
    assert _rows(root, FOUR_LINE_CALL) == [(3, "ast")]


def test_four_line_call_raises_no_external_path_row(root: Path) -> None:
    """The head claims every line of the call before ``_check_external_path`` runs."""
    lines = {line for line, _ in _rows(root, FOUR_LINE_CALL, EXTERNAL_PATH_ID)}
    assert lines.isdisjoint(SIBLING_SILENT_LINES), sorted(lines)


def test_sanitised_twin_reports_nothing_and_declines_once(root: Path) -> None:
    """``path.basename`` covers the request origin, so ``decide`` declines: one record, on
    the consumer's file (A30), and no row."""
    assert _rows(root, SANITISED) == []
    assert _ast_heads.declines_on(_scan(root), SANITISED) == [
        f"ast_decline family=path file={SANITISED} line=2 rule=sanitized:path_normalize "
        "origins=external:request"
    ]


def test_the_ten_no_blunder_twins_are_staged() -> None:
    assert len(NB_TWINS) == 10, NB_TWINS


@pytest.mark.parametrize("twin", NB_TWINS)
def test_no_blunder_twin_reports_nothing(root: Path, twin: str) -> None:
    assert _rows(root, twin) == []


def test_only_the_unparseable_file_reaches_the_regex_body(root: Path) -> None:
    """Ownership is the parse outcome alone (D10): every AST-owned file is decided by the
    head, and only the file with an ERROR node runs ``_check_path_traversal_regex``."""
    reached = _ast_heads.reaching(
        check_input_validation, root, input_validation_check, "_check_path_traversal_regex",
        attrgetter("file_path"),  # the body's first argument is the file's ``_FileCtx``
    )
    assert reached == {BROKEN}


def test_unparseable_file_yields_its_regex_snapshot_rows(root: Path) -> None:
    """The fallback body is the pre-0102 one: the unparseable copy yields exactly the
    snapshot rows of its fixture, with no ``validation.ast``."""
    expected, rows = _ast_heads.fallback_rows(_scan(root), root, GROUP, SNAPSHOT_FIXTURE, PATH_ID)
    assert expected, f"the {GROUP} snapshot holds no row of {SNAPSHOT_FIXTURE}"
    assert not _ast_v1.ast_rows(rows), rows
    assert json.loads(_ast_v1.as_snapshot(rows, GROUP)) == expected
