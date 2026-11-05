"""Single-line rules judge the construct they report, not a nearby word.

Business contract
-----------------
A self-scan reported rows on code that does not have the weakness the rule
names. Each is fixed by reading the construct the way the language defines it:

* CWE-404 improper shutdown: `r, err := os.OpenRoot(dir)` followed by
  `return r.Close()` was reported because the close evidence could never match
  a `.close()` / `.Close()` call. A close anywhere in the routine that opened
  the handle counts (`tmp.Close()` ten lines below the open); a close in the
  NEXT routine does not, and a handle never closed is still reported.
* CWE-476 nil dereference: `p, ok := reg.ByName(name)` was reported because
  the dereference search ran past the end of its routine into the next one,
  which reads a different `p`. The search stops at the end of the block the
  value is bound in, and a comma-ok result tested before the value is used
  (`if !ok {` with an exit, `!ok ||`, `ok &&`) is a guard. A value used before
  the test, or a test that does not exit, is still reported.
* CWE-662 goroutine without synchronisation: `go func() { answer <- probe() }()`
  hands its result over a channel. A channel send, receive or close, or a
  WaitGroup `Done`/`Wait`, inside the goroutine's body is synchronisation; a
  goroutine that writes a captured variable with neither is still reported.
* CWE-252 unchecked return: `_ = os.Setenv(...)` is an explicit discard, a
  visible decision rather than an unchecked value, so the row stays but at low
  severity and says the error was explicitly discarded. The rule is the Go blank
  identifier only: `_ = parser.parse_args()` in Python is an ordinary name.
* CWE-125 out-of-bounds read: `abs[:ends[n-1]]` in Go cannot read out of
  bounds (the runtime checks every index), so index arithmetic is reported for
  C and C++ only. A C `arr[i + offset]` and a Go index named like caller input
  are still reported.
* CWE-369 divide by zero: a division in a constant declaration (a Go `const`
  or `const (` group, a Rust `const`/`static` item, a C++ `constexpr`
  variable) is evaluated by the compiler. A run-time division, a Go `var`
  group, a Rust `const fn` and a C++ `constexpr` function are still reported.
* CWE-200 JWT: a token whose header names no algorithm, or whose signature is
  shorter than any JWS MAC or is readable text, was signed by no key; it is a
  fixture. A token with a 32-byte MAC or a 256-byte signature is still reported.
* CWE-20 missing validation: `return await req.json()` binds nothing, so the
  guard sits at the caller. A returned request value is judged at the same-file
  call sites of its routine, by the excuses that apply on any line; it is
  reported when the routine has no call site in the file or any call site is
  unguarded. Python guard forms (`if not x`, `x is None`, `raise`) count.

Fixture layout (`fixtures/single_rule_precision`): one unit per directory under
``pos/`` (reported) or ``neg/`` (clean). The unit's name prefix selects the
rule. Markers are blanked in the scanned copy: they are test metadata, and the
word `clean` is itself validation vocabulary for CWE-20.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from cwe_agent.skills.buffer_check import check_buffer_handling
from cwe_agent.skills.concurrency_check import check_concurrency
from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero
from cwe_agent.skills.error_handling_check import check_error_handling
from cwe_agent.skills.input_validation_check import check_input_validation
from cwe_agent.skills.resource_check import check_resource_management
from cwe_agent.skills.secret_scan import check_secrets
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "single_rule_precision"
KINDS = ("pos", "neg")
SITES: list[Site] = parse_tree(FIXTURES)
MARKER = re.compile(r"EXPECT(?:-NEXT)?:\s*(?:finding|clean)\b(?:\s+check=[\w.]+)?")
DISCARD_UNIT = "pos/unchecked_go_explicit_discard"

# unit-name prefix -> (skill, the check ids a site of that unit is asserted for)
RULES = {
    "shutdown_": (check_resource_management, ("cwe.resource.improper_shutdown",)),
    "nullderef_": (check_resource_management, ("cwe.resource.null_deref",)),
    "nosync_": (check_concurrency, ("cwe.concurrency.no_sync",)),
    "unchecked_": (check_error_handling, ("cwe.error_handling.unchecked_return",)),
    "oobread_": (check_buffer_handling, ("cwe.buffer.oob_read",)),
    "divzero_": (check_divide_by_zero, ("cwe.divide_by_zero.cwe_369",)),
    "jwt_": (check_secrets, ("cwe.secret_scan.cloud.jwt",)),
    "validation_": (check_input_validation, ("cwe.input_validation.missing_validation",)),
}


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


def _rule(unit_name: str) -> tuple:
    return next(rule for prefix, rule in RULES.items() if unit_name.startswith(prefix))


def _checks(site: Site) -> tuple[str, ...]:
    return (site.check,) if site.check else _rule(_unit(site).split("/")[1])[1]


def _blank_markers(root: Path) -> None:
    """Replace every marker with spaces of its own length, keeping lines and columns."""
    for path in (p for p in root.rglob("*") if p.is_file()):
        text = path.read_text(encoding="utf-8")
        path.write_text(MARKER.sub(lambda m: " " * len(m.group(0)), text), encoding="utf-8")


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    """Every unit scanned on its own by its rule's skill, from one neutral copy."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("singlerules"))
    _blank_markers(root)
    rows: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            rows += _rule(unit.name)[0](str(unit))["findings"]
    return root, rows


def _row_key(row: dict, root: Path) -> tuple:
    rel = Path(row["file_path"]).relative_to(root).as_posix()
    return row.get("check_id"), int(row.get("line_start") or 0), rel


def _rows_at(rows: list[dict], root: Path, site: Site, check: str) -> list[dict]:
    return [f for f in rows if _row_key(f, root) == (check, site.line, site.rel)]


def _units() -> set[str]:
    return {f"{k}/{p.name}" for k in KINDS for p in (FIXTURES / k).iterdir() if p.is_dir()}


def test_population() -> None:
    """Every unit has a rule and at least one site; pos sites expect rows, neg none."""
    assert _units() == {_unit(s) for s in SITES}
    assert all(_rule(u.split("/")[1]) for u in _units())
    assert [s.verdict for s in SITES] == [("clean", "finding")[s.rel.startswith("pos/")] for s in SITES]


def test_rows_are_emitted(scanned) -> None:
    """The scan reports something, so a clean verdict cannot pass vacuously."""
    assert_population(SITES, scanned[1], min_finding=20, min_clean=30, min_emitted=20)


def test_markers_are_not_scanned(scanned) -> None:
    texts = [p.read_text(encoding="utf-8") for p in scanned[0].rglob("*") if p.is_file()]
    assert texts and not any(map(MARKER.search, texts))


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, rows = scanned
    observed = {c: bool(_rows_at(rows, root, site, c)) for c in _checks(site)}
    expected = dict.fromkeys(observed, site.verdict == "finding")
    assert observed == expected, f"{site.rel}:{site.line} expected {site.verdict}, got {observed}"


def _explicit_discard_row(row: dict) -> bool:
    """Low severity, the unchanged title, and a description that says what happened."""
    return (row["severity"], row["title"]) == ("low", "Unchecked return value") and (
        "explicitly discarded" in row["description"]
    )


@pytest.mark.parametrize(
    "site", [s for s in SITES if _unit(s) == DISCARD_UNIT], ids=lambda s: f"{s.rel}:{s.line}",
)
def test_explicit_discard_is_reported_low(scanned, site: Site) -> None:
    """An explicit Go discard keeps its identity (check id, title) at low severity."""
    root, rows = scanned
    found = _rows_at(rows, root, site, "cwe.error_handling.unchecked_return")
    assert found and all(map(_explicit_discard_row, found)), f"{site.rel}:{site.line}: {found}"
