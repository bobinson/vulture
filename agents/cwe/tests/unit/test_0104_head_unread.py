"""Feature 0104 WS-A2 (LLD §4.1; D-N (7) R-A): a sink line a head's line loop never reads is no
member of the file's group of hint-only rows. A pin of the behaviour as built.

A head appends no row at a sink line its loop skips (a line it takes for a non-code one), so
it leaves that line out of the group it stamps (``_ast_head.unread_sinks``): a group naming
the line would lose a member and be refused, and the read members would stay apart.

``SOURCE`` has three hint-only sinks of each family. The third of each sits on a code line the
loop takes for a non-code one: a starred assignment (``*fields, last = ...``), which
``COMMENT_INDICATORS`` reads as a comment continuation, and a ``words = re.split(...)``
assignment, which ``SCANNER_DEF_LINE`` reads as a scanner's pattern definition; ``READ`` is
``SOURCE`` with those two lines respelt (``RESPELT``) so the loop reads them. The second of
each is a multi-line call with a comment line inside its span: an unread span line that is no
sink line, so its sink stays a member. After ``finalize_skill_findings`` (as
``_0104_sites.finalized`` runs it) each check has one group row listing the read sinks alone.
The past-the-end arm of ``unread_sinks`` is pinned on its verdict: no head reaches it, as the
loop reads the same ``text.split("\\n")`` the model's lines are.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from cwe_agent.skills._ast_head import AstAnswer, unread_sinks
from shared import audit_runner, quote_store
from shared.testing.isolation import isolate
from tests import _ast_v1
from tests._0104_sites import CHECK, row_sinks
from tests._neutral import neutral_dir

SOURCE = '''import re
import subprocess


def load_entry(file_path):
    return open(file_path).read()


def load_index(file_path):
    return open(
        # the index file
        file_path,
    ).read()


def load_fields(file_path):
    *fields, last = open(file_path).read().split(",")
    return fields


def show_entry(file_name):
    return subprocess.run("cat " + file_name, shell=True)


def show_index(file_name):
    return subprocess.run(
        # the index file
        "cat " + file_name,
        shell=True,
    )


def show_fields(file_name):
    words = re.split(",", subprocess.check_output("cat " + file_name, shell=True).decode())
    return words
'''
# check id -> (the read sink lines, the unread sink line, the comment line inside a span).
LINES = {
    CHECK["CWE-22"]: ((6, 10), 17, 11),
    CHECK["CWE-78"]: ((22, 26), 34, 27),
}
# Each unread sink line spelt so the loop reads it: no starred target, no ``= re.``.
RESPELT = {
    17: '    fields = open(file_path).read().split(",")',
    34: '    words = subprocess.check_output("cat " + file_name, shell=True).decode().split(",")',
}
READ = "\n".join(RESPELT.get(n, line) for n, line in enumerate(SOURCE.split("\n"), 1))
NAME, READ_NAME = "ledger.py", "ledger_read.py"


class Scan(NamedTuple):
    rows: list[_ast_v1.Finding]  # the two AST skills' rows on ``NAME`` and ``READ_NAME``
    final: list[dict[str, Any]]  # ``finalize_skill_findings`` of them


class _Flow(NamedTuple):
    sink_line: int  # all ``unread_sinks`` reads of a span's flow


@pytest.fixture(scope="module")
def scanned(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Scan:
    """``SOURCE`` and ``READ`` under one neutral root, scanned once and finalized under the
    documented defaults and a private, empty L5 cache (as ``_0104_sites.finalized``)."""
    root = neutral_dir(request)
    (root / NAME).write_text(SOURCE, encoding="utf-8")
    (root / READ_NAME).write_text(READ, encoding="utf-8")
    with pytest.MonkeyPatch.context() as patch:
        isolate(patch, tmp_path_factory.mktemp("head_unread_home"))
        patch.setattr(quote_store, "_table_ready", False)
        rows = _ast_v1.migrated_rows(root)
        # ``finalize_skill_findings`` mutates its rows: it gets a copy.
        final = audit_runner.finalize_skill_findings(copy.deepcopy(rows), str(root), "run-0104")
    return Scan(rows, final)


def _of(rows: list[Any], name: str, check: str) -> list[Any]:
    """The ``check`` rows of ``rows`` on the file ``name`` (a rollup parent has no check id)."""
    return [r for r in rows if (r.get("check_id"), Path(r["file_path"]).name) == (check, name)]


@pytest.mark.parametrize("check", list(LINES))
def test_an_unread_sink_line_is_excluded_from_the_group(scanned: Scan, check: str) -> None:
    """One group row at the anchor, listing the read sinks alone: no row at the unread line."""
    read, _, _ = LINES[check]
    rows = _of(scanned.final, NAME, check)
    assert [(r["line_start"], row_sinks(r)) for r in rows] == [(read[0], list(read))]


@pytest.mark.parametrize("check", list(LINES))
def test_a_sink_past_the_loop_lines_is_unread(check: str) -> None:
    """``unread_sinks``' other arm: a sink line past the end of the lines the loop reads is
    unread, whatever ``scanned`` says; a span line past the end that is no sink line (the
    comment's) is not, and the lines up to the last read sink keep every read sink."""
    read, unread, comment = LINES[check]
    spans = {n: _Flow(n) for n in (*read, unread)} | {comment: _Flow(read[-1])}
    head = SOURCE.split("\n")[: max(read)]
    assert unread_sinks(AstAnswer(spans, ()), head, lambda _line: True) == frozenset({unread})


@pytest.mark.parametrize("check", list(LINES))
def test_only_the_read_sinks_carry_the_stamp(scanned: Scan, check: str) -> None:
    read, _, _ = LINES[check]
    stamps = {r["line_start"]: r.get("_hint_group") for r in _of(scanned.rows, NAME, check)}
    assert stamps == dict.fromkeys(read, read)


@pytest.mark.parametrize("check", list(LINES))
def test_each_head_skips_the_unread_line(scanned: Scan, check: str) -> None:
    """The fixture's premise: the head emits a row at each read sink line and none at the
    unread one, which is a sink it reports once the line is spelt to be read (``READ``)."""
    read, unread, _ = LINES[check]
    rows = [_of(scanned.rows, name, check) for name in (NAME, READ_NAME)]
    assert [[r["line_start"] for r in of] for of in rows] == [list(read), [*read, unread]]
