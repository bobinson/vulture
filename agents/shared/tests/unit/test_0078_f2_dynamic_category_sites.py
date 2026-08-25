"""F2 known limit (b) — the emitted column must not report `(none)` where the
agent demonstrably emits a `category`.

`scripts/report_category_vocabulary.py` exists (AC0.1, reinstated by §15.3) so
§1.2's per-agent vocabulary table stops being a claim frozen in a document. Its
headline row is "asvs declares [\"asvs_requirements\"] and emits ASVS-V12.1.1".
Before this file, the reporter rendered that agent as::

    emitted by skills    : (none)
    emitted elsewhere    : (none)

because `_str_const` admitted only `ast.Constant` and
`asvs_requirements_check.py` builds its value as ``f"ASVS-{req_id}"``. So the
one artifact whose purpose is to stop a stale claim made the fleet's canonical
declared-vs-emitted mismatch render as clean.

That is not symmetric-with-the-guard-and-therefore-fine. The same script already
REFUSES this exact failure mode one column to the left:
``test_computed_selector_is_declared_but_unresolved`` states that reporting
owasp's computed ``CATEGORY_IDS`` as "not declared" would be "a false claim of
exactly the kind this track exists to stop". ``(none)`` in the emitted column is
the identical false claim of absence.

What this file pins:

1. **Accounting.** Every agent the reporter discovers must have its `category`
   emission visible SOMEWHERE in the report — literals, or a counted dynamic
   site. This extends the accounting from the five SET_VOCAB/SHAPE_VOCAB agents
   (all of which happen to have literals, so emptiness was checked nowhere it
   actually occurs) to all ten.
2. **The escape route is closed.** A new agent emitting ``f"GDPR-{art}"`` used to
   get an `exempt` line in the conformance guard, `(none)` in the reporter, and
   no third check. Proven on a synthetic tree.
3. **AC15.2 is not collateral damage.** `emitted_by_skills` must stay
   byte-identical to the conformance guard's `_emitted`, because that agreement
   invariant is the reason the reporter is trustworthy. The dynamic view is a
   SEPARATE field; a shape must never leak into the literal set.
4. **Non-vacuity.** The accounting assertion is shown to FAIL on a synthetic
   agent that really emits no category at all, and the shape resolver is shown
   to ignore f-strings that live in a comment or a docstring.

Nothing here is demonstrated by mutating a real repo file; every negative case
is synthetic source or a tmp_path tree.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import types

import pytest

TESTS_UNIT = pathlib.Path(__file__).resolve().parent
AGENTS = TESTS_UNIT.parents[2]
REPO = AGENTS.parent
SCRIPT = REPO / "scripts" / "report_category_vocabulary.py"
CONFORMANCE = TESTS_UNIT / "test_0078_finding_category_conformance.py"

# New JSON fields this file requires. Named once so a failure says which.
SHAPE_FIELDS = (
    "emitted_shapes",
    "dynamic_sites",
    "emitted_shapes_outside_skills",
    "dynamic_sites_outside_skills",
)


def _load(path: pathlib.Path, name: str) -> types.ModuleType:
    if not path.is_file():
        pytest.fail(f"{path} does not exist")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def reporter() -> types.ModuleType:
    return _load(SCRIPT, "_0078_vocab_reporter_dyn")


@pytest.fixture(scope="module")
def guard() -> types.ModuleType:
    return _load(CONFORMANCE, "_0078_category_conformance_dyn")


def _rows(reporter: types.ModuleType, root: pathlib.Path) -> dict[str, dict]:
    return {a["agent"]: a for a in reporter.build_report(root)["agents"]}


@pytest.fixture(scope="module")
def rows(reporter: types.ModuleType) -> dict[str, dict]:
    return _rows(reporter, AGENTS)


# --------------------------------------------------------------------------
# the accounting helper -- used by the real assertion AND shown to fail below
# --------------------------------------------------------------------------

def _field(row: dict, name: str):
    assert name in row, (
        f"{row['agent']}: the report has no `{name}` field. F2 known limit (b) "
        f"requires the reporter to surface dynamic `category` sites in NEW "
        f"fields {SHAPE_FIELDS} -- widening `emitted_by_skills` instead would "
        f"break the AC15.2 agreement invariant. See "
        f"scripts/report_category_vocabulary.py."
    )
    return row[name]


def _visible(row: dict) -> dict:
    """Everything the report shows about this agent's category emission."""
    return {
        "literals_in_skills": row["emitted_by_skills"],
        "literals_elsewhere": row["emitted_outside_skills"],
        "shapes_in_skills": _field(row, "emitted_shapes"),
        "shapes_elsewhere": _field(row, "emitted_shapes_outside_skills"),
        "dynamic_in_skills": _field(row, "dynamic_sites"),
        "dynamic_elsewhere": _field(row, "dynamic_sites_outside_skills"),
    }


# Agents that legitimately set no `category` anywhere. EMPTY on this tree: all
# ten are accounted for. The set exists so a future agent that really emits
# nothing is a DECISION on the record rather than a reason to weaken the check
# -- and it is self-checking: `test_no_exemption_is_stale` fails the moment an
# exempted agent turns out to emit something after all. That is precisely how
# the conformance guard's do178c exemption ("objective ids come from data
# tables") went stale while the agent emits six static literals.
SILENT_BY_DESIGN: frozenset[str] = frozenset()


def unaccounted_agents(
    rows: dict[str, dict], exempt: frozenset[str] = SILENT_BY_DESIGN
) -> list[str]:
    """Agents whose category emission is invisible in the whole report."""
    return sorted(
        a
        for a, row in rows.items()
        if a not in exempt and not any(_visible(row).values())
    )


def stale_exemptions(
    rows: dict[str, dict], exempt: frozenset[str] = SILENT_BY_DESIGN
) -> list[str]:
    """Exempted agents that do emit a category, so the exemption is a lie."""
    return sorted(a for a in exempt if a in rows and any(_visible(rows[a]).values()))


def assert_every_agent_is_accounted(rows: dict[str, dict]) -> None:
    blind = unaccounted_agents(rows)
    assert not blind, (
        f"the reporter shows NO category emission at all for {blind}, so for "
        f"those agents the declared-vs-emitted mismatch renders as clean. "
        f"Either they really emit nothing (then the report is right and this "
        f"list is wrong), or the extraction in "
        f"scripts/report_category_vocabulary.py is blind to how they build the "
        f"value -- an f-string, a ternary, an attribute, or a "
        f"`d[\"category\"] = x` subscript assignment. `(none)` where a site "
        f"exists is a false claim of absence, the same class the selector "
        f"column already refuses to make. Detail: "
        f"{ {a: _visible(rows[a]) for a in blind} }"
    )


# --------------------------------------------------------------------------
# 1. accounting over the real tree
# --------------------------------------------------------------------------

def test_every_agent_emission_is_accounted_for(rows: dict[str, dict]) -> None:
    assert len(rows) >= 10, f"only {len(rows)} agents discovered; check the glob"
    assert_every_agent_is_accounted(rows)


def test_no_exemption_is_stale(rows: dict[str, dict]) -> None:
    """An exemption must not outlive the fact it records."""
    stale = stale_exemptions(rows)
    assert not stale, (
        f"{stale} are listed in SILENT_BY_DESIGN but the report shows they DO "
        f"emit a category. Remove the entry."
    )


def test_staleness_check_can_fire(rows: dict[str, dict]) -> None:
    """NON-VACUITY: SILENT_BY_DESIGN is empty, so prove the check can fail.

    cwe emits 145 literals and 15 dynamic sites, so exempting it is the most
    obviously wrong exemption available.
    """
    assert stale_exemptions(rows, frozenset({"cwe/cwe_agent"})) == ["cwe/cwe_agent"]


def test_asvs_headline_mismatch_is_visible(rows: dict[str, dict]) -> None:
    """§1.2's headline row: asvs declares one selector and emits `ASVS-*`."""
    row = rows["asvs/asvs_agent"]
    assert row["selector_vocabulary"] == ["asvs_requirements"]
    assert _field(row, "dynamic_sites") >= 1, (
        "asvs_requirements_check.py builds `\"category\": f\"ASVS-{req_id}\"`; "
        "that site must be COUNTED, not rendered as (none)."
    )
    assert "ASVS-*" in _field(row, "emitted_shapes"), (
        "an f-string's literal prefix is statically resolvable, so the report "
        "can say ASVS-* rather than merely 'something dynamic'."
    )


def test_owasp_subscript_assignment_is_visible(rows: dict[str, dict]) -> None:
    """`out["category"] = cat.slug` is an Assign, not an ast.Dict.

    The literal extractor walks only `ast.Dict`, so owasp's single emission site
    was invisible in a way no widening of the literal view could fix.
    """
    row = rows["owasp/owasp_agent"]
    assert _field(row, "dynamic_sites_outside_skills") >= 1, (
        "owasp/owasp_agent/agent.py assigns the category through a Subscript "
        "target; extend the site scan in "
        "scripts/report_category_vocabulary.py to `ast.Assign` targets keyed "
        "\"category\"."
    )


def test_cwe_dynamic_shape_is_visible(rows: dict[str, dict]) -> None:
    """cwe has BOTH literals and dynamic sites; neither may hide the other."""
    row = rows["cwe/cwe_agent"]
    assert row["emitted_by_skills"], "cwe must still report its literals"
    assert _field(row, "dynamic_sites") >= 10, (
        "cwe builds many categories as f\"CWE-{id}\", `spec['category']` or "
        "`rule.category`; those sites must be counted."
    )
    assert "CWE-*" in _field(row, "emitted_shapes")


def test_prove_and_discover_dynamic_sites_are_visible(rows: dict[str, dict]) -> None:
    """Both emit outside skills/ and neither uses a literal."""
    for rel in ("prove/prove_agent", "discover/discover_agent"):
        assert _field(rows[rel], "dynamic_sites_outside_skills") >= 1, (
            f"{rel} passes a variable as the category value; that site must be "
            f"counted so the agent is not reported as emitting nothing."
        )


# --------------------------------------------------------------------------
# 2. AC15.2 is not collateral damage
# --------------------------------------------------------------------------

def test_literal_view_still_matches_the_conformance_guard(
    rows: dict[str, dict], guard: types.ModuleType
) -> None:
    """The dynamic view must be additive.

    `emitted_by_skills` is compared against the conformance guard agent for
    agent (AC15.2). Folding shapes into it would break that agreement for a
    reason that has nothing to do with either extractor, which is why the
    dynamic sites live in their own fields.
    """
    for rel in sorted(set(guard.SET_VOCAB) | set(guard.SHAPE_VOCAB)):
        assert set(rows[rel]["emitted_by_skills"]) == guard._emitted(rel), (
            f"{rel}: `emitted_by_skills` no longer equals the conformance "
            f"guard's `_emitted`. Keep the literal view byte-identical to the "
            f"guard and report dynamic sites in {SHAPE_FIELDS}."
        )


def test_no_shape_marker_leaks_into_the_literal_view(rows: dict[str, dict]) -> None:
    """A shape is not an emitted value; it must not appear as one."""
    for agent, row in rows.items():
        leaked = [
            v
            for v in row["emitted_by_skills"] + row["emitted_outside_skills"]
            if "*" in v
        ]
        assert not leaked, (
            f"{agent}: {leaked} look like shape markers inside the LITERAL "
            f"view. Shapes belong in {SHAPE_FIELDS}."
        )


# --------------------------------------------------------------------------
# 3. the render must not print (none) where a site exists
# --------------------------------------------------------------------------

def _blocks(text: str) -> dict[str, list[str]]:
    """Split the human-readable report into per-agent line blocks."""
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            current = blocks.setdefault(line.strip(), [])
        elif current is not None:
            current.append(line)
    return blocks


def _cell(block: list[str], label: str) -> str:
    for line in block:
        if line.strip().startswith(label):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"no {label!r} line in {block}")


def test_render_never_claims_none_where_a_site_exists(
    rows: dict[str, dict], reporter: types.ModuleType
) -> None:
    text = reporter.render(reporter.build_report(AGENTS))
    blocks = _blocks(text)
    for agent, row in rows.items():
        assert agent in blocks, f"{agent} missing from the render"
        for label, field in (
            ("emitted by skills", "dynamic_sites"),
            ("emitted elsewhere", "dynamic_sites_outside_skills"),
        ):
            if not _field(row, field):
                continue
            cell = _cell(blocks[agent], label)
            assert cell != "(none)", (
                f"{agent}: the render says `{label}: (none)` while the report "
                f"counts {row[field]} dynamic site(s). `_render_agent` in "
                f"scripts/report_category_vocabulary.py must surface them."
            )


def test_asvs_render_names_the_shape(reporter: types.ModuleType) -> None:
    text = reporter.render(reporter.build_report(AGENTS))
    cell = _cell(_blocks(text)["asvs/asvs_agent"], "emitted by skills")
    assert "ASVS-*" in cell, f"expected the resolved shape in {cell!r}"
    assert "1 dynamic site" in cell, f"expected the site count in {cell!r}"


# --------------------------------------------------------------------------
# 4. non-vacuity, on synthetic trees only
# --------------------------------------------------------------------------

def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


SILENT_SKILL = '''\
"""Docstring decoy: {"category": f"DOC-{x}"} is documentation, not emission."""

# Comment decoy: "category": f"COMMENT-{x}"


def check(path: str) -> list[dict]:
    return [{"severity": "high", "title": "t"}]
'''

GDPR_SKILL = '''\
def check(path: str) -> list[dict]:
    article = "5(1)(f)"
    return [{"category": f"GDPR-{article}", "title": "t"}]
'''

MIXED_SKILL = '''\
IS_PRIVATE = True


def check(path: str) -> list[dict]:
    out = [{"category": "LIT-1"}]
    out.append({"category": "LIT-2" if IS_PRIVATE else "LIT-3"})
    row: dict = {}
    row["category"] = compute()
    return out + [row]
'''


@pytest.fixture()
def synthetic_root(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "agents"
    _write(root / "silent" / "silent_agent" / "skills" / "s.py", SILENT_SKILL)
    _write(root / "gdpr" / "gdpr_agent" / "skills" / "g.py", GDPR_SKILL)
    _write(root / "mixed" / "mixed_agent" / "skills" / "m.py", MIXED_SKILL)
    return root


def test_accounting_helper_flags_an_agent_that_really_emits_nothing(
    reporter: types.ModuleType, synthetic_root: pathlib.Path
) -> None:
    """NON-VACUITY: the accounting assertion must be able to fail.

    An agent whose only f-strings live in a comment and a docstring emits
    nothing, so it MUST come back unaccounted. If it did not, the assertion over
    the real tree would be satisfied by an extractor that counts prose.
    """
    rows = _rows(reporter, synthetic_root)
    assert unaccounted_agents(rows) == ["silent/silent_agent"]
    with pytest.raises(AssertionError) as err:
        assert_every_agent_is_accounted(rows)
    assert "silent/silent_agent" in str(err.value)
    assert "report_category_vocabulary.py" in str(err.value)


def test_the_new_agent_escape_route_is_closed(
    reporter: types.ModuleType, synthetic_root: pathlib.Path
) -> None:
    """The route the limit left open: a new agent emitting f"GDPR-{art}"."""
    row = _rows(reporter, synthetic_root)["gdpr/gdpr_agent"]
    assert row["emitted_by_skills"] == [], "still no LITERAL to compare"
    assert row["emitted_shapes"] == ["GDPR-*"]
    assert row["dynamic_sites"] == 1
    assert unaccounted_agents({"gdpr/gdpr_agent": row}) == []


def test_literals_and_dynamic_sites_are_separated(
    reporter: types.ModuleType, synthetic_root: pathlib.Path
) -> None:
    """A ternary of literals and a subscript assignment are both dynamic sites.

    The ternary's operands resolve exactly, so they are reported as shapes; the
    opaque call does not, so it is reported as `*`. Neither may contaminate
    `emitted_by_skills`, which the conformance guard is compared against.
    """
    row = _rows(reporter, synthetic_root)["mixed/mixed_agent"]
    assert row["emitted_by_skills"] == ["LIT-1"]
    assert row["dynamic_sites"] == 2
    assert row["emitted_shapes"] == ["*", "LIT-2", "LIT-3"]


def test_json_cli_exposes_the_new_fields(synthetic_root: pathlib.Path) -> None:
    """The fields must survive the CLI, not only the in-process call."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", "--root", str(synthetic_root)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    rows = {a["agent"]: a for a in json.loads(proc.stdout)["agents"]}
    for field in SHAPE_FIELDS:
        assert field in rows["gdpr/gdpr_agent"], f"--json omits {field}"


def test_shape_resolver_ignores_comments_and_docstrings(
    reporter: types.ModuleType,
) -> None:
    """AST, not regex -- the mistake the first conformance guard made."""
    shapes, count = reporter.category_shapes(SILENT_SKILL)
    assert (shapes, count) == (set(), 0), (
        "an f-string inside a comment or docstring is documentation, not an "
        "emission site."
    )
