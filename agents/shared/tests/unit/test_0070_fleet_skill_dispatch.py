"""Fleet-wide pin for the 0070 P1 defect: a skill that exists but never runs.

The CWE agent shipped 24 implemented skills while its dispatch list
(``ALL_CATEGORIES``) held 22, so ``secrets`` and ``plaintext_transmission``
were imported, wired, and silently never executed — 41 findings lost in one
sweep, 6 of them critical. That was fixed and pinned by an agent-LOCAL test
(``agents/cwe/tests/unit/test_skill_dispatch_conformance.py``).

A local test cannot stop the same drift in the other seven agents, and the
class is live: ``soc2`` and ``ssdf`` each ship a SECOND module-level
``SKILL_MAP`` that nothing imports, sitting next to the one that is actually
dispatched. Nothing today distinguishes "the map the agent runs" from "a map
that happens to be called SKILL_MAP", which is precisely the confusion that
let CWE drift.

This test states the invariant once, for the whole fleet:

    the map the agent DISPATCHES == ALL_CATEGORIES == the config-schema enum

plus two structural guards that make the first assertion mean something:

  * only ONE module per agent package may define the name ``SKILL_MAP``
    (otherwise "the dispatched map" is ambiguous by construction), and
  * for the two-level agents (soc2 clauses, ssdf practice groups) every leaf
    skill must be reachable from some dispatched auditor — that, not the
    top-level key count, is where a leaf skill could go dark.

Design notes
------------
*Dispatched* is read off the agent module itself (``<agent>.agent.SKILL_MAP``),
not off ``skills/__init__.py``: ``agent.py`` binds that name via its import and
hands that exact object to ``run_combined_audit(skill_map=...)``. A source-level
check pins that the object bound to the name is the one passed, so the
attribute really is the dispatch registry and not a lookalike.

*Enum property* differs per agent by domain term (``categories`` /
``clauses`` / ``practice_groups``). It is declared per agent below rather than
guessed, so a renamed schema field fails loudly instead of silently skipping.

Imports are defensive: an agent that is not installed in this environment
SKIPS with a named reason rather than failing, so the shared suite stays
runnable in a partial checkout.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from dataclasses import dataclass, field
from pathlib import Path

import pytest


@dataclass(frozen=True)
class AgentSpec:
    """One agent's dispatch contract."""

    name: str  # agent type, as the backend registry names it
    package: str  # importable top-level package
    enum_prop: str  # config_schema property carrying the dispatch enum
    # Modules (dotted, relative to `package`) allowed to define SKILL_MAP.
    # More than one definition of the name inside a package is the defect this
    # test exists to catch, so this is a single-element tuple everywhere.
    skill_map_home: str
    # Two-level agents aggregate leaf skills behind a coarser dispatch unit.
    # (leaf module, subpackage holding the dispatched auditors)
    leaf_skills: tuple[str, str] | None = None
    dispatches_skills: bool = True
    note: str = field(default="")


AGENTS: list[AgentSpec] = [
    AgentSpec("cwe", "cwe_agent", "categories", "cwe_agent.skills"),
    AgentSpec("chaos", "chaos_agent", "categories", "chaos_agent.skills"),
    AgentSpec(
        "owasp",
        "owasp_agent",
        "categories",
        "owasp_agent.skills",
        dispatches_skills=False,
        note=(
            "feature 0063: owasp is a CWE->OWASP categorizer, not a scanner. It "
            "dispatches no skills, so the SKILL_MAP/ALL_CATEGORIES/enum identity "
            "does not apply; its own invariant is pinned separately below."
        ),
    ),
    AgentSpec(
        "soc2",
        "soc2_agent",
        "clauses",
        "soc2_agent.clauses",
        leaf_skills=("soc2_agent.skills", "soc2_agent.clauses"),
    ),
    AgentSpec(
        "ssdf",
        "ssdf_agent",
        "practice_groups",
        "ssdf_agent.practice_groups",
        leaf_skills=("ssdf_agent.skills", "ssdf_agent.practice_groups"),
    ),
    AgentSpec("asvs", "asvs_agent", "categories", "asvs_agent.skills"),
    AgentSpec("xss", "xss_agent", "categories", "xss_agent.skills"),
    AgentSpec("do178c", "do178c_agent", "categories", "do178c_agent.skills"),
]

SCAN_AGENTS = [s for s in AGENTS if s.dispatches_skills]
TWO_LEVEL_AGENTS = [s for s in AGENTS if s.leaf_skills]


def _ids(specs: list[AgentSpec]) -> list[str]:
    return [s.name for s in specs]


# Known, currently-unfixed drift for `test_only_one_module_defines_skill_map`.
#
# Both are the SHADOW half of the 0070 P1 class, not the functional half: the
# dispatched map is correct in each case and
# `test_every_leaf_skill_is_reachable_from_a_dispatched_auditor` passes, so no
# skill is going unrun today. What is wrong is that the authoritative-looking
# name `SKILL_MAP` resolves to a dead object in the module a reader would check
# first — the exact ambiguity that hid CWE's two undispatched skills.
#
# Left failing rather than fixed because the fix lands in files this change does
# not own, and because it carries a small API decision: both packages export the
# dead name in `__all__`, so "rename to LEAF_SKILL_MAP" and "delete" are not
# equivalent for any out-of-tree importer.
#
# strict=True: whoever applies the fix gets an XPASS failure telling them to
# delete the marker, so this cannot rot into a permanently-excused test.
# Both known shadow-SKILL_MAP agents were FIXED (2026-08-24): soc2 and ssdf each
# renamed their unimported leaf map to LEAF_SKILL_MAP, so exactly one importable
# SKILL_MAP remains per agent package. The strict xfails that recorded them are
# gone with them — the invariant is now enforced for the whole fleet.
_KNOWN_SHADOW_SKILL_MAP: dict[str, str] = {}


def _shadow_params() -> list:
    """AGENTS, with the two known shadow-SKILL_MAP agents marked xfail."""
    out = []
    for spec in AGENTS:
        reason = _KNOWN_SHADOW_SKILL_MAP.get(spec.name)
        marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
        out.append(pytest.param(spec, id=spec.name, marks=marks))
    return out


def _import(dotted: str, agent: str):
    """Import *dotted* or SKIP with a reason naming the agent.

    A missing agent is an environment fact (partial checkout, per-agent venv),
    not a contract violation — failing there would make the fleet test unusable
    exactly where it is most useful.
    """
    try:
        return importlib.import_module(dotted)
    except Exception as exc:  # ImportError, or a heavy transitive dep
        pytest.skip(f"agent {agent!r}: cannot import {dotted} here ({type(exc).__name__}: {exc})")


def _dispatched_map(spec: AgentSpec) -> dict:
    mod = _import(f"{spec.package}.agent", spec.name)
    assert hasattr(mod, "SKILL_MAP"), (
        f"{spec.package}.agent does not bind SKILL_MAP, so there is no way to "
        f"tell which map it dispatches"
    )
    return mod.SKILL_MAP


def _agent_info(spec: AgentSpec) -> dict:
    return _import(f"{spec.package}.config", spec.name).AGENT_INFO


def _all_categories(spec: AgentSpec) -> list[str]:
    return _import(f"{spec.package}.config", spec.name).ALL_CATEGORIES


def _schema_enum(spec: AgentSpec) -> list[str]:
    props = _agent_info(spec)["config_schema"]["properties"]
    assert spec.enum_prop in props, (
        f"{spec.name}: config schema has no {spec.enum_prop!r} property "
        f"(has {sorted(props)}); the dispatch enum was renamed and this "
        f"test's declaration is now stale"
    )
    return props[spec.enum_prop]["items"]["enum"]


def _package_dir(spec: AgentSpec) -> Path:
    pkg = _import(spec.package, spec.name)
    return Path(pkg.__file__).resolve().parent


def _assign_targets(node: ast.stmt) -> list[ast.expr]:
    """Assignment targets of *node*, or [] if it is not an assignment."""
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, ast.AnnAssign):
        return [node.target]
    return []


def _defines_skill_map(path: Path) -> bool:
    """True if *path* binds ``SKILL_MAP`` at module level.

    Parsed rather than imported: this must see definitions that nothing
    imports, which is the entire point.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):  # pragma: no cover - unreadable source
        return False
    return any(
        isinstance(t, ast.Name) and t.id == "SKILL_MAP"
        for node in tree.body  # module level only
        for t in _assign_targets(node)
    )


def _dotted(spec: AgentSpec, root: Path, path: Path) -> str:
    parts = [p for p in path.relative_to(root).with_suffix("").parts if p != "__init__"]
    return ".".join([spec.package, *parts])


def _modules_defining_skill_map(spec: AgentSpec) -> list[str]:
    """Every module in the package with a module-level ``SKILL_MAP =``."""
    root = _package_dir(spec)
    return [
        _dotted(spec, root, p) for p in sorted(root.rglob("*.py")) if _defines_skill_map(p)
    ]


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", SCAN_AGENTS, ids=_ids(SCAN_AGENTS))
def test_dispatched_skill_map_equals_all_categories(spec: AgentSpec):
    """Implemented-but-never-dispatched is the 0070 P1 defect itself."""
    skill_map = _dispatched_map(spec)
    categories = _all_categories(spec)

    undispatched = sorted(set(skill_map) - set(categories))
    orphans = sorted(set(categories) - set(skill_map))
    assert not undispatched, (
        f"{spec.name}: implemented in the dispatched SKILL_MAP but absent from "
        f"ALL_CATEGORIES, so they never run: {undispatched}"
    )
    assert not orphans, (
        f"{spec.name}: dispatched with no implementing skill: {orphans}"
    )


@pytest.mark.parametrize("spec", SCAN_AGENTS, ids=_ids(SCAN_AGENTS))
def test_config_schema_enum_equals_all_categories(spec: AgentSpec):
    """The schema must not offer the operator a category the agent cannot run."""
    enum = _schema_enum(spec)
    categories = _all_categories(spec)
    assert set(enum) == set(categories), (
        f"{spec.name}: config_schema[{spec.enum_prop!r}] enum {sorted(set(enum))} "
        f"!= ALL_CATEGORIES {sorted(set(categories))}"
    )


@pytest.mark.parametrize("spec", SCAN_AGENTS, ids=_ids(SCAN_AGENTS))
def test_no_duplicate_dispatch_entries(spec: AgentSpec):
    categories = _all_categories(spec)
    enum = _schema_enum(spec)
    assert len(categories) == len(set(categories)), (
        f"{spec.name}: ALL_CATEGORIES contains duplicates: {categories}"
    )
    assert len(enum) == len(set(enum)), (
        f"{spec.name}: config enum contains duplicates: {enum}"
    )


@pytest.mark.parametrize("spec", SCAN_AGENTS, ids=_ids(SCAN_AGENTS))
def test_the_bound_skill_map_is_the_one_handed_to_the_runner(spec: AgentSpec):
    """``SKILL_MAP`` on the agent module must be what dispatch actually uses.

    Without this the three-way identity above could hold for a map the agent
    never passes to ``run_combined_audit`` — a green test over a dead object.
    """
    src = inspect.getsource(_import(f"{spec.package}.agent", spec.name))
    assert "skill_map=SKILL_MAP" in src, (
        f"{spec.name}: {spec.package}/agent.py does not pass its bound "
        f"SKILL_MAP as skill_map=; the name checked here is not the dispatch "
        f"registry"
    )


# ---------------------------------------------------------------------------
# Structural guards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", _shadow_params())
def test_only_one_module_defines_skill_map(spec: AgentSpec):
    """A second ``SKILL_MAP`` makes "the dispatched one" ambiguous.

    This is the drift that let CWE lose two skills: a registry name that reads
    authoritative but is not what runs. A leaf registry is fine — it must just
    not be called ``SKILL_MAP``.
    """
    defs = _modules_defining_skill_map(spec)
    assert defs, f"{spec.name}: no module defines SKILL_MAP"
    assert defs == [spec.skill_map_home], (
        f"{spec.name}: SKILL_MAP is defined in {defs}; exactly one module may "
        f"define it and it must be {spec.skill_map_home!r} (the dispatched "
        f"registry). A second definition is dead weight that shadows the real "
        f"one — rename it LEAF_SKILL_MAP or delete it."
    )


@pytest.mark.parametrize("spec", TWO_LEVEL_AGENTS, ids=_ids(TWO_LEVEL_AGENTS))
def test_every_leaf_skill_is_reachable_from_a_dispatched_auditor(spec: AgentSpec):
    """soc2/ssdf dispatch coarse units; a leaf skill goes dark unaggregated.

    The top-level key check cannot see this: CC6/CC7/CC8 can match
    ALL_CATEGORIES perfectly while a leaf skill nothing calls sits beside them.
    """
    leaf_mod_name, auditors_pkg = spec.leaf_skills
    leaf_mod = _import(leaf_mod_name, spec.name)
    leaf_fns = {
        name
        for name, obj in vars(leaf_mod).items()
        if name.startswith("check_") and not name.endswith("_tool") and callable(obj)
    }
    assert leaf_fns, f"{spec.name}: found no leaf check_* functions in {leaf_mod_name}"

    root = _package_dir(spec) / auditors_pkg.split(".")[-1]
    referenced: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                referenced.add(node.id)

    unreachable = sorted(leaf_fns - referenced)
    assert not unreachable, (
        f"{spec.name}: leaf skills implemented but referenced by no dispatched "
        f"auditor in {auditors_pkg}, so they never run: {unreachable}"
    )


# ---------------------------------------------------------------------------
# Declared exemption: owasp dispatches nothing (feature 0063)
# ---------------------------------------------------------------------------


def test_owasp_dispatches_no_skills_by_design():
    """Pin the exemption so it stays a decision, not an accident.

    If owasp ever grows real detection it must join SCAN_AGENTS above; this
    fails the moment its stub map is populated.
    """
    spec = next(s for s in AGENTS if s.name == "owasp")
    skills = _import(f"{spec.package}.skills", spec.name)
    assert skills.SKILL_MAP == {}, (
        "owasp now defines skills; it is no longer exempt from the fleet "
        "dispatch invariant — move it into SCAN_AGENTS"
    )
    src = inspect.getsource(_import(f"{spec.package}.agent", spec.name))
    assert "skill_map=" not in src, (
        "owasp now dispatches a skill map; move it into SCAN_AGENTS"
    )
