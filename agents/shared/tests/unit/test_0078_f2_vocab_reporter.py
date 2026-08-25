"""AC15.2 -- the category-vocabulary reporter must exist, run, and agree.

`scripts/report_category_vocabulary.py` exists so the plan's per-agent
vocabulary table stops being a claim frozen in a document and becomes something
recomputable on a clean checkout. That only holds if three things are true, and
each is a test here:

1. the script RUNS on this tree (a reporter nobody can execute is prose);
2. it reports EVERY agent, so a new agent cannot be silently absent from the
   table;
3. its emitted-category view AGREES, agent for agent, with
   ``test_0078_finding_category_conformance.py`` -- which is the single source of
   truth for what "the categories this agent emits" means. Two extractors that
   can disagree are two answers to one question, and at most one of them is
   right.

**Non-vacuity is the acceptance condition here**, because every assertion in
this file is of the form "these two views match" and empty matches empty. So:

* the agreement helper is shown to FAIL against a deliberately broken
  (regex-over-source) view of synthetic source whose only ``"category"``
  literals live in a comment and a docstring -- exactly the mistake the first
  conformance guard made;
* the coverage helper is shown to FAIL against a truncated report;
* the compared view is asserted NON-EMPTY for every agent the conformance guard
  claims to check, which closes that guard's own ``pytest.skip`` hole; and
* the column extraction is exercised against a synthetic agent tree under
  ``tmp_path``, never by mutating a real repo file.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import types

import pytest

TESTS_UNIT = pathlib.Path(__file__).resolve().parent
AGENTS = TESTS_UNIT.parents[2]
REPO = AGENTS.parent
SCRIPT = REPO / "scripts" / "report_category_vocabulary.py"
CONFORMANCE = TESTS_UNIT / "test_0078_finding_category_conformance.py"


def _load(path: pathlib.Path, name: str) -> types.ModuleType:
    if not path.is_file():
        pytest.fail(
            f"{path} does not exist. AC15.2 requires the committed reporter "
            f"script; create it (or fix this path if it moved)."
        )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def reporter() -> types.ModuleType:
    return _load(SCRIPT, "_0078_vocab_reporter")


@pytest.fixture(scope="module")
def guard() -> types.ModuleType:
    return _load(CONFORMANCE, "_0078_category_conformance")


def _agent_dirs(root: pathlib.Path) -> set[str]:
    """Filesystem truth, independent of the script's own discovery."""
    return {
        f"{p.parent.name}/{p.name}"
        for p in root.glob("*/[a-z]*_agent")
        if p.is_dir()
    }


# --------------------------------------------------------------------------
# helpers under test -- used by the real assertions AND shown to fail below
# --------------------------------------------------------------------------

def _disagreements(
    script_view: dict[str, set[str]], guard_view: dict[str, set[str]]
) -> list[str]:
    keys = sorted(set(script_view) | set(guard_view))
    return [k for k in keys if script_view.get(k, set()) != guard_view.get(k, set())]


def assert_views_agree(
    script_view: dict[str, set[str]], guard_view: dict[str, set[str]], what: str
) -> None:
    bad = _disagreements(script_view, guard_view)
    detail = {
        k: {
            "reporter": sorted(script_view.get(k, set())),
            "conformance_guard": sorted(guard_view.get(k, set())),
        }
        for k in bad
    }
    assert not bad, (
        f"emitted-category views disagree for {bad} ({what}): {detail}. "
        f"Both must extract dict values keyed \"category\" by AST over the same "
        f"skills/*.py files. Fix `category_literals` in "
        f"scripts/report_category_vocabulary.py to match `_category_literals` in "
        f"{CONFORMANCE.name} (that guard is the single source of truth), or fix "
        f"the scope of `emitted_by_skills` if the file set drifted."
    )


def assert_covers_every_agent(reported: set[str], root: pathlib.Path) -> None:
    missing = _agent_dirs(root) - reported
    assert not missing, (
        f"the vocabulary report omits {sorted(missing)}. Fix "
        f"`discover_agents` in scripts/report_category_vocabulary.py so its "
        f"glob matches every agents/*/[a-z]*_agent directory -- an agent absent "
        f"from the report is an agent whose vocabulary nobody is checking."
    )


def _regex_literals(source: str) -> set[str]:
    """Deliberately WRONG extractor, kept only to prove the guard can fail."""
    return set(re.findall(r'"category"\s*:\s*"([^"]+)"', source))


# --------------------------------------------------------------------------
# 1. the script runs
# --------------------------------------------------------------------------

def test_script_runs_and_prints_every_agent() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=180,
    )
    assert proc.returncode == 0, (
        f"scripts/report_category_vocabulary.py exited {proc.returncode}. "
        f"It must run on a clean checkout using only the standard library "
        f"(no agent imports, no network). stderr:\n{proc.stderr}"
    )
    for agent in sorted(_agent_dirs(AGENTS)):
        assert agent in proc.stdout, (
            f"the human-readable report never names {agent}. Every agent must "
            f"appear; see `render` in scripts/report_category_vocabulary.py."
        )


def test_json_output_covers_every_agent() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json"],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert_covers_every_agent({a["agent"] for a in payload["agents"]}, AGENTS)


def test_coverage_helper_flags_a_dropped_agent() -> None:
    """NON-VACUITY: the coverage assertion must be able to fail."""
    full = _agent_dirs(AGENTS)
    assert full, "no agents found; the coverage check would be vacuous"
    with pytest.raises(AssertionError) as err:
        assert_covers_every_agent(set(sorted(full)[1:]), AGENTS)
    assert "omits" in str(err.value)


# --------------------------------------------------------------------------
# 2. agreement with the conformance guard (the single source of truth)
# --------------------------------------------------------------------------

def _script_view(reporter: types.ModuleType) -> dict[str, set[str]]:
    report = reporter.build_report(AGENTS)
    return {a["agent"]: set(a["emitted_by_skills"]) for a in report["agents"]}


def _guard_view(guard: types.ModuleType) -> dict[str, set[str]]:
    view: dict[str, set[str]] = {}
    for rel in sorted(_agent_dirs(AGENTS)):
        skills = AGENTS / rel / "skills"
        found: set[str] = set()
        if skills.is_dir():
            for path in skills.rglob("*.py"):
                found |= guard._category_literals(path.read_text())
        view[rel] = found
    return view


def test_emitted_view_agrees_with_conformance_guard(
    reporter: types.ModuleType, guard: types.ModuleType
) -> None:
    assert_views_agree(_script_view(reporter), _guard_view(guard), "this checkout")


def test_emitted_view_agrees_with_the_guards_own_entry_point(
    reporter: types.ModuleType, guard: types.ModuleType
) -> None:
    """Pin `_emitted` itself, not only the extractor it calls.

    The check above rebuilds the guard's view from its `_category_literals`. If
    the FILE SCOPE inside `_emitted` drifted (a different glob, a skipped
    subdirectory) that comparison would not notice, because it never calls
    `_emitted`. This one does.
    """
    script = _script_view(reporter)
    for rel in sorted(set(guard.SET_VOCAB) | set(guard.SHAPE_VOCAB)):
        assert (AGENTS / rel / "skills").is_dir(), (
            f"{rel} has no skills/ directory, so `_emitted` would pytest.skip "
            f"and this comparison would be vacuous. Move {rel} to that guard's "
            f"`exempt` set if it no longer has skills."
        )
        assert script[rel] == guard._emitted(rel), (
            f"{rel}: reporter says {sorted(script[rel])}, the conformance "
            f"guard's `_emitted` says {sorted(guard._emitted(rel))}. Align the "
            f"file scope of `emitted_by_skills` in "
            f"scripts/report_category_vocabulary.py with `_emitted` in "
            f"{CONFORMANCE.name}."
        )


def test_agreement_is_non_empty_for_every_guarded_agent(
    reporter: types.ModuleType, guard: types.ModuleType
) -> None:
    """An empty view agrees with everything, so emptiness must be excluded.

    The conformance guard `pytest.skip`s an agent whose literal set comes back
    empty. That makes a broken extractor look like a clean tree, there and
    here. Every agent the guard names must have literals.
    """
    view = _script_view(reporter)
    guarded = set(guard.SET_VOCAB) | set(guard.SHAPE_VOCAB)
    empty = sorted(a for a in guarded if not view.get(a))
    assert not empty, (
        f"{empty} are declared in SET_VOCAB/SHAPE_VOCAB of "
        f"{CONFORMANCE.name} but the reporter finds no `category` literals in "
        f"their skills. Either the extractor is blind (fix `category_literals` "
        f"in scripts/report_category_vocabulary.py) or those agents no longer "
        f"emit literals and belong in that guard's `exempt` set."
    )


SYNTHETIC_SKILL = '''\
"""Docstring decoy -- documents the convention: {"category": "DOC-DECOY"}"""

# Comment decoy: emit "category": "COMMENT-DECOY" for attestations.

FIELD_NAMES = ["category", "severity"]


def check(path: str) -> list[dict]:
    return [
        {"category": "alpha", "title": "a", "kind": "not-a-category"},
        {"severity": "high", "category": "beta"},
    ]


NOT_A_CATEGORY = {"categoryish": "gamma"}
'''


def test_ast_view_ignores_comments_and_docstrings(reporter: types.ModuleType) -> None:
    assert reporter.category_literals(SYNTHETIC_SKILL) == {"alpha", "beta"}


def test_agreement_helper_fails_against_a_regex_view(
    reporter: types.ModuleType,
) -> None:
    """NON-VACUITY: the agreement assertion must be able to fail.

    A regex over source is the exact defect this reporter was specified to
    avoid. Feed one in as the second view: the helper must reject it, and it
    must reject it for the decoys rather than for nothing.
    """
    ast_view = {"synth/synth_agent": reporter.category_literals(SYNTHETIC_SKILL)}
    regex_view = {"synth/synth_agent": _regex_literals(SYNTHETIC_SKILL)}
    assert regex_view["synth/synth_agent"] - ast_view["synth/synth_agent"] == {
        "DOC-DECOY",
        "COMMENT-DECOY",
    }, "the synthetic fixture no longer distinguishes AST from regex extraction"
    with pytest.raises(AssertionError) as err:
        assert_views_agree(ast_view, regex_view, "synthetic")
    assert "synth/synth_agent" in str(err.value)
    assert "report_category_vocabulary.py" in str(err.value)


# --------------------------------------------------------------------------
# 3. the declared columns, on a synthetic tree (never a real repo file)
# --------------------------------------------------------------------------

def _write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture()
def synthetic_root(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "agents"
    synth = root / "synth" / "synth_agent"
    _write(synth / "config.py", 'ALL_CATEGORIES: list[str] = ["alpha", "beta"]\n')
    _write(
        synth / "agent.py",
        "from synth_agent.config import ALL_CATEGORIES\n\n\n"
        "def build():\n"
        "    return run_combined_audit(\n"
        "        skill_tools=[],\n"
        "        category_enum=frozenset(ALL_CATEGORIES),\n"
        "    )\n",
    )
    _write(synth / "skills" / "thing.py", SYNTHETIC_SKILL)
    bare = root / "bare" / "bare_agent"
    _write(bare / "config.py", 'OTHER_NAMES: list[str] = ["x"]\n')
    _write(bare / "agent.py", 'FINDING = {"category": "outside-skills"}\n')
    return root


def _run_json(root: pathlib.Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", "--root", str(root)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _by_agent(payload: dict) -> dict[str, dict]:
    return {a["agent"]: a for a in payload["agents"]}


def test_synthetic_tree_reports_all_three_columns(synthetic_root: pathlib.Path) -> None:
    rows = _by_agent(_run_json(synthetic_root))
    assert set(rows) == {"synth/synth_agent", "bare/bare_agent"}

    synth = rows["synth/synth_agent"]
    assert synth["selector_name"] == "ALL_CATEGORIES"
    assert synth["selector_vocabulary"] == ["alpha", "beta"]
    assert synth["finding_vocabulary"]["declared"] is True
    assert synth["finding_vocabulary"]["values"] == ["alpha", "beta"]
    assert synth["emitted_by_skills"] == ["alpha", "beta"]


def test_synthetic_tree_reports_absent_declarations_as_absent(
    synthetic_root: pathlib.Path,
) -> None:
    bare = _by_agent(_run_json(synthetic_root))["bare/bare_agent"]
    assert bare["selector_name"] is None
    assert bare["selector_vocabulary"] is None
    assert bare["finding_vocabulary"]["declared"] is False
    assert bare["emitted_by_skills"] == []


def test_compared_scope_is_exactly_the_skills_directory(
    synthetic_root: pathlib.Path,
) -> None:
    """The literal outside skills/ must be reported, but not in the view the
    conformance guard is compared against -- otherwise agreement breaks for a
    reason that has nothing to do with either extractor."""
    bare = _by_agent(_run_json(synthetic_root))["bare/bare_agent"]
    assert "outside-skills" not in bare["emitted_by_skills"]
    assert bare["emitted_outside_skills"] == ["outside-skills"]


@pytest.fixture()
def computed_root(tmp_path: pathlib.Path) -> pathlib.Path:
    """An agent whose selector vocabulary is COMPUTED, not a literal list.

    owasp does this (`CATEGORY_IDS = [f"A{n:02d}" for n in range(1, 11)]`). A
    reporter that can only see literal displays reports such an agent as "not
    declared", which is a false claim of exactly the kind this track exists to
    stop.
    """
    root = tmp_path / "agents"
    agent = root / "computed" / "computed_agent"
    _write(
        agent / "config.py",
        'ALL_CATEGORIES: list[str] = [f"A{n:02d}" for n in range(1, 3)]\n',
    )
    return root


def test_computed_selector_is_declared_but_unresolved(
    computed_root: pathlib.Path,
) -> None:
    row = _by_agent(_run_json(computed_root))["computed/computed_agent"]
    assert row["selector_name"] == "ALL_CATEGORIES", (
        "a computed selector vocabulary must still be reported as DECLARED; "
        "see `declared_selector` in scripts/report_category_vocabulary.py"
    )
    assert row["selector_vocabulary"] is None
    assert "range(1, 3)" in row["selector_expr"]


def test_text_render_shows_the_synthetic_agent(synthetic_root: pathlib.Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(synthetic_root)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "synth/synth_agent" in proc.stdout
    assert "alpha" in proc.stdout
    assert "DOC-DECOY" not in proc.stdout
