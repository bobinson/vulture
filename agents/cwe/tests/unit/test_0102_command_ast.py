"""Feature 0102 — CWE-78 is owned by the AST tier on every file it parses (LLD §8.5, §9.3,
§13.2, D10, D19; plan task 3.3).

``check_injection``'s command check gains the consumer head: on a file ``owns()`` models,
``_ast_spans(…, _RULE_78)`` decides every command flow and ``emit_for_line`` emits the
reported ones at the sink line with ``validation.ast``; a file the AST cannot model reaches
the former body, renamed ``_check_command_regex`` and unchanged. ``_RULE_78`` has no gate.

Pinned here: the partial application of ``subprocess.run`` with ``shell=True``
(``cwe_78_3.py``) and its argv-list twin (``cwe_78_5_clean.py``); the existing
``injection/cwe_078_*`` fixtures (three positives at line 6, three clean twins — the
contract the new owner must also satisfy, LLD §13.2), now owned by the AST tier and yielding
exactly the pre-0102 snapshot; and the fallback of one of them made unparseable, served by
the renamed body.

Pinned elsewhere: one owner per check id per file (``test_0102_owner_disjoint``); the
identity and sink-line quote of every AST row (``test_0102_identity``); the whole
``injection`` group made unparseable, through both skills (``test_0102_fallback_parity``).

RED until the head lands: the AST row, ``_RULE_78`` and the renamed body do not exist yet.
The argv-list twin, the existing fixtures' rows and the fallback rows are regex behaviour
today and must stay exactly so.
"""

from __future__ import annotations

import json
from pathlib import Path

import corpus_runner
import pytest

from cwe_agent.skills import injection_check
from cwe_agent.skills.injection_check import check_injection
from tests import _ast_heads, _ast_v1
from tests._ast_heads import COMMAND_ID

PARTIAL_SHELL = "cwe_78_3.py"  # lister = partial(subprocess.run, shell=True); lister(...) line 9
ARGV_LIST = "cwe_78_5_clean.py"  # subprocess.run(["ls", d]) with no shell keyword

# The pre-0102 snapshot group of CWE-78, and the fixture whose unparseable copy falls back.
GROUP, SNAPSHOT_FIXTURE = "injection", "cwe_078_1.py"
BROKEN = _ast_heads.unparsed(SNAPSHOT_FIXTURE)


@pytest.fixture(scope="module")
def root(request: pytest.FixtureRequest) -> Path:
    """The named ``ast_v1`` files, each AST-owned, and one unparseable snapshot fixture."""
    root = _ast_v1.stage(request, (PARTIAL_SHELL, ARGV_LIST))
    _ast_heads.stage_unparseable(root, corpus_runner.FIXTURES_DIR / GROUP / SNAPSHOT_FIXTURE)
    return root


@pytest.fixture(scope="module")
def existing(request: pytest.FixtureRequest) -> Path:
    """The whole ``injection`` group as it is, every file parseable."""
    return _ast_v1.copy_fixtures(request, src=corpus_runner.FIXTURES_DIR / GROUP)


def _scan(root: Path) -> _ast_heads.Scan:
    return _ast_heads.scan(check_injection, root)


def _rows(root: Path, rel: str) -> list[tuple[int, str | None]]:
    return _ast_heads.rows_at(_scan(root), root, rel, COMMAND_ID)


def _reaching(root: Path) -> set[str]:
    """The files of ``root`` that reach ``_check_command_regex``, whose first argument is the
    file itself."""
    return _ast_heads.reaching(check_injection, root, injection_check, "_check_command_regex", Path)


def test_partial_application_with_shell_true_is_an_ast_row(root: Path) -> None:
    assert _rows(root, PARTIAL_SHELL) == [(9, "ast")]


def test_argv_list_reports_nothing(root: Path) -> None:
    assert _rows(root, ARGV_LIST) == []


def test_command_rule_has_no_gate() -> None:
    """Only ``_RULE_918`` carries a gate (§5, §9.3)."""
    from cwe_agent.skills.injection_check import _RULE_78

    assert _RULE_78.gate is None


def test_existing_injection_fixtures_are_unchanged(existing: Path) -> None:
    """The ``injection/cwe_078_*`` rows, byte for byte the pre-0102 snapshot, whichever
    tier emits them (LLD §13.2: the contract the new owner must also satisfy)."""
    rows = _ast_v1.rows_for(_scan(existing).rows, COMMAND_ID)
    assert _ast_v1.as_snapshot(rows, GROUP) == _ast_v1.snapshot_text(GROUP)


def test_existing_injection_fixtures_are_ast_owned(existing: Path) -> None:
    """Every file of the group parses, so none reaches ``_check_command_regex``: the rows
    above are the AST tier's."""
    assert not _reaching(existing)


def test_only_the_unparseable_file_reaches_the_regex_body(root: Path) -> None:
    """Ownership is the parse outcome alone (D10): only the file with an ERROR node runs
    ``_check_command_regex``."""
    assert _reaching(root) == {BROKEN}


def test_unparseable_file_yields_its_regex_snapshot_rows(root: Path) -> None:
    """The fallback body is the pre-0102 one: the unparseable copy yields exactly the
    snapshot rows of its fixture, with no ``validation.ast``."""
    expected, rows = _ast_heads.fallback_rows(
        _scan(root), root, GROUP, SNAPSHOT_FIXTURE, COMMAND_ID)
    assert expected, f"the {GROUP} snapshot holds no row of {SNAPSHOT_FIXTURE}"
    assert not _ast_v1.ast_rows(rows), rows
    assert json.loads(_ast_v1.as_snapshot(rows, GROUP)) == expected
