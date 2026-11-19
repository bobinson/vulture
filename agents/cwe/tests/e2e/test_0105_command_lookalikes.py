"""A call named like a process API is CWE-78 only while it may run a process (0105).

Business contract
-----------------
The command rule reported CRITICAL rows on ``exec`` / ``Exec`` / ``system`` calls that run no
process. A call keeps its CWE-78 row on process or command evidence, and on no evidence either
way; it loses the row only on evidence that it runs no process:

* A data store runs statements, not processes: a receiver declared a database or transaction type
  (``h *sql.DB``, ``t *sql.Tx``), bound from a database constructor (``sql.Open(...)``,
  ``new Database(...)``) or named a transaction (``tx, _ := s.Begin()``). Fed by a parameter, its
  call is no CWE-78 row and no CWE-89 row either: at a data store only a real external origin (a
  request) is reported, as CWE-89.
* A regular expression's ``exec`` matches text, even fed by a request:
  ``entry.regex.exec(req.url)``.
* ``system`` on a value with no command evidence (``palette.system(label)``, ``palette`` imported
  from a local module) reports only a real external origin: fed by a parameter it is no row, fed
  by a request (``runner.system(req.query.c)``) it stays a CWE-78 row.

Rows that stay: a process API (``exec.Command("sh", "-c", ...)``, ``child_process``, ``Runtime``,
``os.system``, ``posix.system``, ``std::system``, PHP's ``exec``); a namespace, which keeps its
process API (cgo ``C.system``, a PHP ``use``-imported ``Runner::system``); a chained command or a
``psql -c`` shell on a receiver with no evidence (``h`` a parameter); statement text on a receiver
with command evidence (``sh.run("DELETE ..." + ...)``, ``ssh.exec(...)``).

Fixture layout (``fixtures/command_lookalikes``): one unit per directory, one site each, under
``pos/`` (a CWE-78 row at the marker) or ``neg/`` (none); the unit's name prefix selects the rule.
The skill skips test paths, so every unit is scanned on its own from one neutral copy. The
data-store units (``STORE_UNITS``) also hold no CWE-89 row anywhere.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cwe_agent.skills.injection_check import check_injection
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "command_lookalikes"
KINDS = ("pos", "neg")
SITES: list[Site] = parse_tree(FIXTURES)

# unit-name prefix -> (skill, the check id a site of that unit is asserted for)
RULES = {"cmd_": (check_injection, "cwe.injection.command")}
# The data-store neg/ units: a parameter-fed statement on a data store is no CWE-89 row either.
STORE_UNITS = frozenset({
    "neg/cmd_go_a_type", "neg/cmd_go_a_bind", "neg/cmd_js_a_new",
    "neg/cmd_go_a_store_hint", "neg/cmd_go_a_tx",
})
SQL_CATEGORY = "CWE-89"

Row = dict[str, Any]
Scanned = tuple[Path, dict[str, list[Row]]]


def _unit(site: Site) -> str:
    """``<kind>/<unit>`` of a site."""
    return "/".join(site.rel.split("/")[:2])


def _rule(unit_name: str) -> tuple[Callable[[str], dict], str]:
    return next(rule for prefix, rule in RULES.items() if unit_name.startswith(prefix))


def _units(root: Path) -> list[Path]:
    """Every unit directory under ``root``, ``neg/`` and ``pos/`` alike."""
    return sorted(p for kind in KINDS for p in (root / kind).iterdir() if p.is_dir())


def _scan(unit: Path) -> list[Row]:
    """One unit, scanned on its own by its rule's skill."""
    return _rule(unit.name)[0](str(unit))["findings"]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory: pytest.TempPathFactory) -> Scanned:
    """Every unit's rows, keyed ``<kind>/<unit>``, from one neutral copy."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("lookalikes"))
    return root, {unit.relative_to(root).as_posix(): _scan(unit) for unit in _units(root)}


def _on_site(row: Row, root: Path, site: Site) -> bool:
    """The row is the site's rule's, on the site's file and line."""
    return (row.get("check_id") == _rule(_unit(site).split("/")[1])[1]
            and int(row.get("line_start") or 0) == site.line
            and Path(row["file_path"]).relative_to(root).as_posix() == site.rel)


def _sql_rows(rows: list[Row], site: Site) -> list[str]:
    """A data-store unit's CWE-89 rows (``file:line``), anywhere in it; none asked elsewhere."""
    if _unit(site) not in STORE_UNITS:
        return []
    return [f"{r['file_path']}:{r.get('line_start')}" for r in rows
            if r.get("category") == SQL_CATEGORY]


def _fixture_units() -> list[str]:
    return sorted(f"{kind}/{p.name}" for kind in KINDS
                  for p in (FIXTURES / kind).iterdir() if p.is_dir())


def _expected(site: Site) -> str:
    return "finding" if site.rel.startswith("pos/") else "clean"


def test_population() -> None:
    """Every unit has a rule and exactly one site; pos sites expect a row, neg ones none."""
    units = _fixture_units()
    assert sorted(map(_unit, SITES)) == units
    assert all(_rule(u.split("/")[1]) for u in units)
    assert [s.verdict for s in SITES] == list(map(_expected, SITES))


def test_store_units_are_neg_units() -> None:
    """The no-CWE-89 assertion names real units, so a renamed fixture cannot skip it."""
    assert STORE_UNITS <= set(_fixture_units())


def test_rows_are_emitted(scanned: Scanned) -> None:
    """The scan reports something, so a clean verdict cannot pass vacuously."""
    rows = [row for unit_rows in scanned[1].values() for row in unit_rows]
    assert_population(SITES, rows, min_finding=16, min_clean=7, min_emitted=16)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned: Scanned, site: Site) -> None:
    """The site's CWE-78 verdict; a data-store unit also holds no CWE-89 row."""
    root, by_unit = scanned
    rows = by_unit[_unit(site)]
    reported = any(_on_site(row, root, site) for row in rows)
    expected = site.verdict == "finding"
    assert reported == expected, f"{site.rel}:{site.line} expected {site.verdict}"
    sql = _sql_rows(rows, site)
    assert not sql, f"{_unit(site)}: a data-store unit holds a CWE-89 row: {sql}"
