"""Line rules read the code they report on, not a word inside another word.

Business contract
-----------------
A self-scan reported rows on lines that do not do what the rule describes:

* CWE-681 numeric conversion: `int(` matched inside `fmt.Sprint(err)` and
  `keys.isdisjoint(found)`. A conversion is a call of the type itself, so the
  name must start at a word boundary; `int32(size)` and `int(request...)` are
  still reported. Python's `int(raw)` has no width to lose, and Go's bare
  `int(x)` narrows only an operand declared wider in the same function
  (`n int64`, `v.(float64)`); `int(uid)` of a 32-bit field is not reported.
* CWE-113 response splitting: `requestid.Header` and `*http.Request` read as
  user input, and a function named `hasCSRFHeader` read as a header write.
  Input words count only as whole words and a header call only as a whole
  name; a request value written to a header is still reported.
* CWE-1004 / 614 / 1275 cookie attributes: `http.SetCookie(w, sessionCookie(...))`
  was judged on the call line alone although `sessionCookie`, defined in the
  same file, sets HttpOnly, Secure and SameSite=Strict. A cookie built by a
  routine of the same file is judged by that routine's body. `Secure` set from
  a value (`Secure: https`) is set, and an enum member naming Strict or Lax
  (`http.SameSiteLaxMode`) is Strict or Lax. A builder that sets no flag, sets
  `Secure: false` or SameSite=None is still reported, and so is a cookie call
  whose window holds only an unrelated routine.
* CWE-778 auth decision: a line inside a docstring (`... a forbidden status`)
  is prose, not a decision. The same word in code is still reported.

Fixture layout (`fixtures/line_rule_precision`): one unit per directory under
``pos/`` (reported) or ``neg/`` (clean). The unit's name prefix selects the rule.
A site that names ``check=`` is asserted for that check only; otherwise for
every category of its unit's rule.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.data_handling_check import check_data_handling
from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging
from cwe_agent.skills.web_security_check import check_web_security
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "line_rule_precision"
KINDS = ("pos", "neg")
SITES: list[Site] = parse_tree(FIXTURES)

# unit-name prefix -> (skill, the check ids a site of that unit is asserted for)
RULES = {
    "numeric_": (check_data_handling, ("cwe.data_handling.numeric_conversion",)),
    "crlf_": (check_web_security, ("cwe.web_security.crlf_injection",)),
    "cookie_": (check_web_security, (
        "cwe.web_security.cookie_no_httponly",
        "cwe.web_security.cookie_no_secure",
        "cwe.web_security.cookie_improper_samesite",
    )),
    "auth_": (check_insufficient_logging, ("cwe.insufficient_logging.auth_decision",)),
}


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


def _rule(unit_name: str) -> tuple:
    return next(rule for prefix, rule in RULES.items() if unit_name.startswith(prefix))


def _checks(site: Site) -> tuple[str, ...]:
    return (site.check,) if site.check else _rule(_unit(site).split("/")[1])[1]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    """Every unit scanned on its own by its rule's skill, from one neutral copy."""
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("linerules"))
    rows: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            rows += _rule(unit.name)[0](str(unit))["findings"]
    return root, rows


def _reported(rows: list[dict], root: Path, site: Site, check: str) -> bool:
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
    assert_population(SITES, scanned[1], min_finding=20, min_clean=14, min_emitted=20)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, rows = scanned
    observed = {c: _reported(rows, root, site, c) for c in _checks(site)}
    if site.verdict == "finding":
        assert all(observed.values()), f"{site.rel}:{site.line} expected a row per check, got {observed}"
    else:
        assert not any(observed.values()), f"{site.rel}:{site.line} expected clean, got {observed}"
