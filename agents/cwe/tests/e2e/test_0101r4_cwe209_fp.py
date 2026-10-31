"""Feature 0101 revision 4 -- CWE-209 false-positive classes measured on a public corpus.

Business contract
-----------------
A row means an error's internal detail (its message, stack, string form or raw
object) reaches the peer. Four shapes reported that are not that, and each is
excused only on a language-neutral concept read from the code:

* SANITISING QUALIFIER -- a callee whose words carry a detail word AND a
  sanitising qualifier (`toPublicMessage`, `get_redacted_message`,
  `scrubbedMessage`) projects the error when no definition of it can be read;
  it is not a raw-message getter (`safe` is not a qualifier: `safeGetMessage`
  is a null-safe getter; a negated qualifier, `getNonPublicMessage`, is not
  one either). The name is evidence only while there is no definition: a
  DEFINED one (same file, else the tree's only one) is reported unless every
  result it gives is a literal, in every language (Go `return err.Error()`,
  PHP `$e->getMessage()`, Ruby's implicit `e.message`, a Kotlin expression
  body all report).
* CALLER-FACING ERROR CLASS -- the sink runs only for a caught error whose
  CLASS is a caller-facing input / validation / authorization error: a typed
  handler (`catch (InputValidationException e)`, `except ValidationError as
  e`), a positive type test in an enclosing branch (`instanceof`,
  `isinstance`, a `.name` comparison), or a branch on the answer of a
  same-file classifier helper that only ever recognises such classes and
  refuses everything else. The excuse covers the caught error's OWN text
  only, as an allowlist: its message (`message`, `getMessage()`, Go's
  `Error()`, `str(e)`, `args`, `name`) or the bare binding stringified (an
  interpolation, a concatenation, a stringifier call). Any other member of it
  (`e.dbError`, `e.parent`, `exc.orig`, `e.query`), the whole object handed
  to a serialiser (`res.json(err)`), a wrapped cause or context
  (`err.cause`, `getCause()`, `__cause__`, `InnerException`), a name bound
  from one, or any other error value on the sink is still reported. A
  classifier qualifies only when every test in it is of its FIRST parameter
  (or a name bound from it) and every answer it gives is reached through a
  positive caller-facing type test, or after a screen that refuses every
  other class; a code, errno or truthiness test that answers disqualifies
  it. The caller-facing roles are input, validation and authorization; a
  bare HTTP status word (`Forbidden`, `Unauthorized`) is not one, because as
  a class it names an OUTBOUND call's status, and a class is internal when
  ANY segment of its qualified name carries an internal or outbound role
  (`HttpClientErrorException.Forbidden`, `BillingClient.ValidationException`,
  `UnauthorizedAccessException`). Still reported: an internal class
  (`SQLException`, `DatabaseError`, `IOException`, an `InputOutputError`), a
  mixed or negated guard, a sink outside the branch, a stack, and Go
  `errors.Is` (it proves only that the CHAIN holds the sentinel, so
  `err.Error()` carries every wrapper's context).
* CHILD STDIN -- a write to a child process's standard input is not a peer.
* REQUEST PARAMETER -- a name bound from a read of the request's own query or
  form parameters holds the peer's input, not an error (the nearest binding
  decides, so a later rebinding from a caught error still reports).

Fixture layout (`fixtures/0101r4_cwe209`): one asserted site per unit; a unit is
a directory under ``pos/`` (reported), ``neg/`` (clean) or ``gap/`` (an
adjudicated false-positive class with no narrow local concept, pinned to the
observed verdict so a change either way is seen). Units are scanned one at a
time from a neutral copy (the rule skips test paths). Tuning languages are
TypeScript; Python, Java, Go, Kotlin, C#, PHP and Ruby units are held out of
every lexicon decision above.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from tests.e2e._0101_markers import Site, assert_population, neutral_copy, parse_tree, verdicts

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "0101r4_cwe209"
CWE209 = "CWE-209"
KINDS = ("pos", "neg", "gap")
SITES: list[Site] = parse_tree(FIXTURES)

# (pos floor, neg floor) per concept prefix.
CONCEPT_FLOORS = {"sq_": (8, 6), "tg_": (45, 10), "ns_": (0, 2), "rq_": (1, 2)}
# Every behaviour change carries units in a language the lexicon was not tuned on.
HELD_OUT_SUFFIXES = (".py", ".java", ".go", ".kt", ".cs", ".php", ".rb")


def _unit(site: Site) -> str:
    return "/".join(site.rel.split("/")[:2])


@pytest.fixture(scope="module")
def scanned(tmp_path_factory) -> tuple[Path, list[dict]]:
    root = neutral_copy(FIXTURES, tmp_path_factory.mktemp("cwe209r4"))
    findings: list[dict] = []
    for kind in KINDS:
        for unit in sorted(p for p in (root / kind).iterdir() if p.is_dir()):
            findings += check_information_exposure(str(unit))["findings"]
    return root, findings


def _rows(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("category") == CWE209]


def test_population_floor(scanned) -> None:
    _, findings = scanned
    assert all(s.verdict == "finding" for s in SITES if s.rel.startswith("pos/"))
    assert all(s.verdict == "clean" for s in SITES if s.rel.startswith("neg/"))
    assert_population(SITES, _rows(findings), min_finding=54, min_clean=22, min_emitted=54)


@pytest.mark.parametrize("prefix", sorted(CONCEPT_FLOORS))
def test_concept_floors(prefix: str) -> None:
    pos = sum(1 for s in SITES if _unit(s).startswith(f"pos/{prefix}"))
    neg = sum(1 for s in SITES if _unit(s).startswith(f"neg/{prefix}"))
    want_pos, want_neg = CONCEPT_FLOORS[prefix]
    assert pos >= want_pos and neg >= want_neg, (prefix, pos, neg)


@pytest.mark.parametrize("prefix", sorted(CONCEPT_FLOORS))
def test_every_concept_has_a_held_out_language(prefix: str) -> None:
    held = [s for s in SITES if s.rel.split("/")[1].startswith(prefix) and s.rel.endswith(HELD_OUT_SUFFIXES)]
    assert held, prefix


def test_one_asserted_site_per_unit() -> None:
    per_unit = Counter(_unit(s) for s in SITES)
    assert per_unit and max(per_unit.values()) == 1, [u for u, n in per_unit.items() if n > 1]
    units = {f"{k}/{p.name}" for k in KINDS for p in (FIXTURES / k).iterdir() if p.is_dir()}
    assert units == set(per_unit), sorted(units ^ set(per_unit))


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{_unit(s)}:{s.line}")
def test_site_verdict(scanned, site: Site) -> None:
    root, findings = scanned
    got = verdicts(_rows(findings), [site], CWE209, root)[site]
    assert got == site.verdict, f"{site.rel}:{site.line} expected {site.verdict}, observed {got}"


@pytest.mark.parametrize("site", [s for s in SITES if s.rel.startswith("pos/")], ids=lambda s: _unit(s))
def test_genuine_site_reports_exactly_one_row(scanned, site: Site) -> None:
    root, findings = scanned
    rel = Path(site.rel)
    same = [f for f in _rows(findings)
            if int(f.get("line_start") or 0) == site.line and Path(f["file_path"]).relative_to(root) == rel]
    assert len(same) == 1, same
