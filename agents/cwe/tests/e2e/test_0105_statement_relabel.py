"""SQL statement text sent to a data store is one SQL-injection row, not a command (0105).

Business contract
-----------------
``tx.Exec("DELETE FROM t WHERE id = " + r.FormValue("id"))`` starts no process:
it sends a statement to a database. The command rule reported such calls as
CWE-78 OS command injection, and the SQL rule saw them only when an f-string, a
template literal or ``Sprintf`` built the statement. Each unit holds one call
and one marked site:

* ``pos/``: exactly one CWE-89 row in the unit, on the marked line, and no
  CWE-78 row anywhere in the unit. This holds when
  - the argument is SQL statement text and the receiver has no command
    evidence, whatever feeds the text: a request value or a parameter;
  - the receiver is a data store (named ``db``, a static ``Db::`` class, a
    declared ``*sql.Tx``) and a request value reaches the call, whatever the
    argument's shape (the raw value, ``Sprintf``, ``CREATE TABLE``): an
    externally sourced flow is re-labelled, never removed;
  - the SQL rule's own pattern already reports the line (a template literal,
    ``Sprintf``): that row is the one row. A statement hoisted into a variable
    is reported once, on the line that builds it (the marker's line), and the
    call that sends it gets no second row.
* ``neg/``: no CWE-89 row in the unit: a placeholder statement whose value is
  bound apart from it, a value made numeric, a parameter spliced into a
  statement on a data-store receiver (no external source), and a regular
  expression's ``exec``, which is neither SQL nor a process, so it gets no
  CWE-78 row either.

Fixture layout (``fixtures/statement_relabel``): one unit per directory under
``pos/`` or ``neg/``, holding one ``EXPECT`` marker; the unit's name prefix
selects the rule.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from cwe_agent.skills.injection_check import check_injection
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "statement_relabel"
KINDS = ("pos", "neg")
SITES: list[Site] = parse_tree(FIXTURES)

# unit-name prefix -> (skill, the check id a site of that unit is asserted for)
RULES = {"stmt_": (check_injection, "cwe.injection.sql")}
COMMAND = "cwe.injection.command"
# neg/ units that carry no CWE-78 row either: a regular expression runs no process
NO_COMMAND = frozenset({"neg/stmt_js_regex_statement"})


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


def _rule(unit_name: str) -> tuple[Callable[[str], dict], str]:
    """The ``(skill, check id)`` whose prefix starts ``unit_name``; fails when none does."""
    rule = next((r for prefix, r in RULES.items() if unit_name.startswith(prefix)), None)
    assert rule is not None, f"no rule owns {unit_name}"
    return rule


def _check(unit: str) -> str:
    """The check id the unit (``kind/name``) is asserted for."""
    return _rule(unit.split("/")[1])[1]


def _unit_dirs(root: Path) -> list[Path]:
    """Every unit directory under ``root``, ``pos/`` first, each kind in name order."""
    return [p for k in KINDS for p in sorted((root / k).iterdir()) if p.is_dir()]


def _units() -> list[str]:
    """Every unit of the fixture tree, as ``kind/name``, in order."""
    return sorted(f"{p.parent.name}/{p.name}" for p in _unit_dirs(FIXTURES))


def _one_site(unit: str) -> tuple[str, str]:
    """The ``(unit, verdict)`` of the one site a unit holds; raises when no rule owns it."""
    _check(unit)
    return unit, "finding" if unit.startswith("pos/") else "clean"


@pytest.fixture(scope="module")
def scanned(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, list[dict]]:
    """Every unit scanned on its own by its rule's skill, from one neutral copy."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("relabel"))
    rows: list[dict] = []
    for unit in _unit_dirs(root):
        rows += _rule(unit.name)[0](str(unit))["findings"]
    return root, rows


def _is_row(finding: dict, root: Path, unit: str, check: str) -> bool:
    """Whether ``finding`` is a ``check`` row on a file of ``unit`` (``kind/name``)."""
    rel = Path(finding["file_path"]).relative_to(root)
    return finding.get("check_id") == check and "/".join(rel.parts[:2]) == unit


def _lines(rows: list[dict], root: Path, unit: str, check: str) -> list[int]:
    """The line of every ``check`` row on a file of ``unit``, in order."""
    return sorted(int(f.get("line_start") or 0) for f in rows if _is_row(f, root, unit, check))


def _expected(site: Site) -> dict[str, list[int]]:
    """Per check id the unit is held to, the line of every row the unit must carry."""
    unit = _unit(site)
    if site.verdict == "finding":
        return {_check(unit): [site.line], COMMAND: []}
    if unit in NO_COMMAND:
        return {_check(unit): [], COMMAND: []}
    return {_check(unit): []}


def test_population() -> None:
    """One site per unit and a rule for each; pos sites expect a row, neg none."""
    assert sorted((_unit(s), s.verdict) for s in SITES) == [_one_site(u) for u in _units()]
    assert NO_COMMAND <= set(_units())


def test_rows_are_emitted(scanned: tuple[Path, list[dict]]) -> None:
    """The scan reports something, so a clean verdict cannot pass vacuously."""
    assert_population(SITES, scanned[1], min_finding=12, min_clean=4, min_emitted=12)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned: tuple[Path, list[dict]], site: Site) -> None:
    """The unit's rows of each check it is held to sit exactly on the expected lines."""
    root, rows = scanned
    want = _expected(site)
    got = {check: _lines(rows, root, _unit(site), check) for check in want}
    assert got == want, f"{_unit(site)}: row lines {got}, expected {want}"
