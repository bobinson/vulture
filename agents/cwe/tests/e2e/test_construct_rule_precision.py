"""Four rules report the construct they name, not its words in text.

Business contract
-----------------
A self-scan reported 13 CRITICAL rows on lines that do not do what the rule
describes:

* CWE-269 improper privilege: the verb `run`/`exec` matched inside other words
  (`runs`, `strip_runmode(...) AS root`), and "run as root" matched as English
  in a message string. A `--privileged` or `--user root` / `--user=root` flag
  after `run`/`exec` (a word, or inside a name such as `docker_run`) is
  reported wherever the command sits, even inside a quoted argv. The phrase
  "as root" is English (a message, a docstring, a SQL alias), not an
  operation, and is not reported.
* CWE-89 SQL injection: an f-string, `.format`, `%` or `Sprintf` clause needs
  evidence that the string is SQL: a SQL sink within three lines, or SQL shape
  (`SELECT ... FROM`, `INSERT INTO`, `UPDATE t SET`, `DELETE FROM`,
  `DROP TABLE`). An HTTP method in a message (`f"DELETE {ep} returned 200"`)
  is not SQL. `.format(` formats SQL only when it is called on the literal that
  holds the statement: Go's `time.Now().Format(...)` passed as a parameter is
  not. A Go `fmt.Sprintf` whose `%s` takes a string built only from literals in
  the same function, and whose other verbs are numeric (`$%d`), puts nothing
  variable into the SQL.
* CWE-94 code injection: `eval(`/`exec(` inside a comment, a docstring or a
  string literal is text. A call inside an interpolation (`f"{eval(x)}"`,
  `${eval(x)}`, `"#{eval(x)}"`) is code and is reported.
* CWE-312 cleartext storage: a value with no letter or digit (`"..."`,
  `"********"`) is a placeholder. Value rules still read prose: a value in a
  README is reported.

Fixture layout (`fixtures/construct_rule_precision`): one unit per directory
under ``pos/`` (reported) or ``neg/`` (clean); the unit's name prefix selects
the rule.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.access_control_check import check_access_control
from cwe_agent.skills.info_exposure_check import check_information_exposure
from cwe_agent.skills.injection_check import check_injection
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "construct_rule_precision"
KINDS = ("pos", "neg")
SITES: list[Site] = parse_tree(FIXTURES)

# unit-name prefix -> (skill, the check id a site of that unit is asserted for)
RULES = {
    "priv_": (check_access_control, "cwe.access_control.improper_privilege"),
    "sql_": (check_injection, "cwe.injection.sql"),
    "code_": (check_injection, "cwe.injection.code"),
    "store_": (check_information_exposure, "cwe.info_exposure.cleartext_storage"),
}


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


def _rule(unit_name: str) -> tuple:
    return next(rule for prefix, rule in RULES.items() if unit_name.startswith(prefix))


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    """Every unit scanned on its own by its rule's skill, from one neutral copy."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("construct"))
    rows: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            rows += _rule(unit.name)[0](str(unit))["findings"]
    return root, rows


def _reported(rows: list[dict], root: Path, site: Site) -> bool:
    check = _rule(_unit(site).split("/")[1])[1]
    return any(
        f.get("check_id") == check and int(f.get("line_start") or 0) == site.line
        and Path(f["file_path"]).relative_to(root) == Path(site.rel)
        for f in rows
    )


def test_population() -> None:
    """Every unit has a rule and at least one site; pos sites expect rows, neg none."""
    units = {f"{k}/{p.name}" for k in KINDS for p in (FIXTURES / k).iterdir() if p.is_dir()}
    assert units == {_unit(s) for s in SITES}
    assert all(_rule(u.split("/")[1]) for u in units)
    assert all(s.verdict == ("finding" if s.rel.startswith("pos/") else "clean") for s in SITES)


def test_rows_are_emitted(scanned) -> None:
    """The scan reports something, so a clean verdict cannot pass vacuously."""
    assert_population(SITES, scanned[1], min_finding=24, min_clean=19, min_emitted=24)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, rows = scanned
    reported = _reported(rows, root, site)
    if site.verdict == "finding":
        assert reported, f"{site.rel}:{site.line} expected a row"
    else:
        assert not reported, f"{site.rel}:{site.line} expected clean"
