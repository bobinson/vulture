"""Feature 0076 T5.4 — the Tier M neutral whole-tree copier.

The constraint (plan §5.8): ``is_test_file`` / ``is_skill_source_file`` /
``is_generated_file`` reject any path containing a ``test`` / ``tests`` /
``skills`` / ``fixtures`` part, and ``_llm_eligible_files`` applies the same
filters — so a corpus stored under ``tests/corpus/fixtures/`` renders **zero**
files into the LLM prompt. The CWE corpus runner works around this by copying
each fixture ALONE into a neutral ``mkdtemp()``, which flattens the tree.

Flattening is not usable here. Tier M measures anchor accuracy, which is a
function of in-file and cross-file context; the CWE manifest already records
CWE-219 as a casualty of exactly that flattening. So the copy must be
whole-tree: every path part renamed token-free, **layout preserved**.

These tests are the business contract for that helper. The headline one is
``test_T54_neutral_copy_renders_non_zero_eligible_files``, paired with
``test_T54_in_place_corpus_renders_zero_eligible_files`` so the copier is
measured against the defect it exists to remove rather than against nothing.
"""

from __future__ import annotations

import inspect
from collections import defaultdict
from pathlib import Path, PurePosixPath

import pytest

import shared.base_agent as base_agent_module
from shared.audit_runner import _llm_eligible_files
from shared.tools.ast_parser import parse_ast
from shared.tools.file_scanner import (
    SKIP_DIRS,
    clear_caches,
    is_generated_file,
    is_skill_source_file,
    is_test_file,
    scan_code_files,
)
from shared.validate.judge_tools import JUDGE_TOOL_SPECS
from tests.support.neutral_tree import (
    ORGANISATIONAL_DIRS,
    PRUNE_DIRS,
    copy_tree_neutral,
    neutral_tree,
    neutral_violations,
)

# Every relative path below is chosen to trip at least one scanner filter:
# a `tests`/`skills`/`fixtures` directory part, a `test_`/`_test` stem, or a
# `skills/*_check.py` generated-file match.
_CORPUS: dict[str, str] = {
    "webapp/handlers/test_login.py": (
        "import sqlite3\n"
        "\n"
        "def login(conn, user):\n"
        "    return conn.execute('SELECT * FROM u WHERE n=' + user)\n"
    ),
    "webapp/handlers/session.py": (
        "SECRET = 'not-a-real-secret'\n"
        "\n"
        "def issue(uid):\n"
        "    return f'{uid}:{SECRET}'\n"
    ),
    "webapp/skills/auth_check.py": (
        "def check(path):\n"
        "    return 'eval(' in open(path).read()\n"
    ),
    "webapp/fixtures/seed_data.py": "ROWS = [1, 2, 3]\n",
    "README.md": "# corpus\n\nA planted-defect corpus.\n",
}

# Copied into the source tree but never into the neutral copy: renaming these
# to `d0/f0.js` would make a vendored/VCS tree LOOK like corpus content.
_NEVER_CORPUS: dict[str, str] = {
    "node_modules/pkg/index.js": "module.exports = 1;\n",
    ".git/config": "[core]\n",
    "package-lock.json": '{"lockfileVersion": 3}\n',
}


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)


@pytest.fixture()
def corpus_root(tmp_path: Path) -> Path:
    """A corpus laid out exactly where a corpus really lives: under
    ``tests/corpus/fixtures/``, which is the whole problem."""
    root = tmp_path / "tests" / "corpus" / "fixtures"
    root.mkdir(parents=True)
    _write(root, _CORPUS)
    _write(root, _NEVER_CORPUS)
    clear_caches()
    return root


def _eligible(root: Path) -> list[Path]:
    clear_caches()
    return _llm_eligible_files(scan_code_files(str(root)))


# ── the defect this helper exists to remove ───────────────────────────


def test_T54_in_place_corpus_renders_zero_eligible_files(corpus_root: Path):
    """Scanned where it lives, the corpus is invisible to the LLM tier.

    This is the baseline. If this test ever starts passing a non-zero count,
    the eligibility rule changed and T5.4's premise must be re-derived, not
    the copier patched.
    """
    assert _eligible(corpus_root) == []


# ── the headline contract ─────────────────────────────────────────────


def test_T54_neutral_copy_renders_non_zero_eligible_files(corpus_root: Path):
    """The same corpus, neutrally copied, is eligible."""
    with neutral_tree(corpus_root) as tree:
        eligible = _eligible(tree.root)
        assert eligible, "neutral copy must render at least one eligible file"
        # Every genuine corpus file survives; nothing from _NEVER_CORPUS does.
        assert len(eligible) == len(_CORPUS)
        rels = {p.relative_to(tree.root).as_posix() for p in eligible}
        originals = {tree.to_original[r] for r in rels}
        assert originals == set(_CORPUS)


def test_T54_every_copied_path_is_token_free(corpus_root: Path):
    """No copied path trips any of the three filters — checked with the
    scanner's own predicates, not a re-implementation of them."""
    with neutral_tree(corpus_root) as tree:
        copied = [p for p in tree.root.rglob("*") if p.is_file()]
        assert copied
        for path in copied:
            assert neutral_violations(path) == (), path
            assert not is_test_file(path)
            assert not is_skill_source_file(path)
            assert not is_generated_file(path)


# ── layout, which flattening would destroy ────────────────────────────


def test_T54_layout_is_preserved_not_flattened(corpus_root: Path):
    """Depth is preserved, siblings stay siblings, and two distinct source
    directories never merge into one."""
    with neutral_tree(corpus_root) as tree:
        assert tree.to_original

        for neutral_rel, orig_rel in tree.to_original.items():
            assert neutral_rel.count("/") == orig_rel.count("/"), (
                f"{orig_rel} -> {neutral_rel} changed depth"
            )

        neutral_parents: dict[str, set[str]] = defaultdict(set)
        for neutral_rel, orig_rel in tree.to_original.items():
            op = PurePosixPath(orig_rel).parent.as_posix()
            neutral_parents[op].add(PurePosixPath(neutral_rel).parent.as_posix())

        # siblings stay siblings
        for orig_parent, targets in neutral_parents.items():
            assert len(targets) == 1, f"{orig_parent} split across {targets}"
        # distinct directories stay distinct (no flattening / merging)
        flattened = {next(iter(t)) for t in neutral_parents.values()}
        assert len(flattened) == len(neutral_parents)
        # and the corpus really is nested, so the assertions above have teeth
        assert max(r.count("/") for r in tree.to_original) >= 2


def test_T54_content_is_byte_identical(corpus_root: Path):
    """Renaming is the only transformation. Bytes are untouched, so a
    manifest ``line`` number still points at the same source line."""
    with neutral_tree(corpus_root) as tree:
        for neutral_rel, orig_rel in tree.to_original.items():
            assert (tree.root / neutral_rel).read_bytes() == (
                corpus_root / orig_rel
            ).read_bytes()


def test_T54_mapping_round_trips(corpus_root: Path):
    with neutral_tree(corpus_root) as tree:
        for orig_rel in _CORPUS:
            neutral_rel = tree.neutral_of(orig_rel)
            assert neutral_rel is not None
            assert tree.original_of(neutral_rel) == orig_rel
        assert tree.original_of("nope/f9.py") is None
        assert tree.neutral_of("nope.py") is None


def test_T54_copy_is_deterministic(corpus_root: Path, tmp_path: Path):
    """Same input, same names — a Tier M run must be re-runnable against a
    stable mapping or its per-file buckets cannot be compared across runs."""
    first = copy_tree_neutral(corpus_root, tmp_path / "a")
    second = copy_tree_neutral(corpus_root, tmp_path / "b")
    assert dict(first.to_original) == dict(second.to_original)


# ── pruning: renaming is not always the safe move ─────────────────────


def test_T54_never_corpus_trees_are_pruned_not_renamed(corpus_root: Path):
    """``node_modules`` renamed to ``d0`` would be a vendored tree presented
    to the model as corpus. These are dropped at the SOURCE, and recorded."""
    with neutral_tree(corpus_root) as tree:
        copied_bodies = {
            p.read_text() for p in tree.root.rglob("*") if p.is_file()
        }
        for rel, body in _NEVER_CORPUS.items():
            assert body not in copied_bodies, rel
            assert rel.split("/")[0] in tree.pruned or rel in tree.pruned


def test_T54_organisational_dirs_are_renamed_not_pruned(corpus_root: Path):
    """``fixtures/`` is a SKIP_DIR, but a corpus legitimately organises
    itself with it. It must be renamed through, not dropped."""
    with neutral_tree(corpus_root) as tree:
        assert tree.neutral_of("webapp/fixtures/seed_data.py") is not None
        assert tree.neutral_of("webapp/skills/auth_check.py") is not None


def test_T54_prune_and_organisational_sets_are_disjoint_and_derived():
    """Derived from SKIP_DIRS rather than hand-typed, so a new SKIP_DIRS
    entry cannot silently become eligible corpus content."""
    assert ORGANISATIONAL_DIRS <= SKIP_DIRS
    assert PRUNE_DIRS == SKIP_DIRS - ORGANISATIONAL_DIRS
    assert not (PRUNE_DIRS & ORGANISATIONAL_DIRS)
    assert "node_modules" in PRUNE_DIRS
    assert "fixtures" in ORGANISATIONAL_DIRS


# ── probe hygiene (0076 rule: never write to the scanned tree) ─────────


def test_T54_source_tree_is_not_modified(corpus_root: Path):
    before = {
        p.relative_to(corpus_root).as_posix(): p.stat().st_mtime_ns
        for p in sorted(corpus_root.rglob("*"))
        if p.is_file()
    }
    with neutral_tree(corpus_root):
        pass
    after = {
        p.relative_to(corpus_root).as_posix(): p.stat().st_mtime_ns
        for p in sorted(corpus_root.rglob("*"))
        if p.is_file()
    }
    assert before == after


def test_T54_context_manager_removes_the_copy(corpus_root: Path):
    with neutral_tree(corpus_root) as tree:
        root = tree.root
        assert root.is_dir()
    assert not root.exists()


def test_T54_extensionless_canonical_files_keep_their_name(tmp_path: Path):
    """``Dockerfile`` is already token-free, and its NAME is the only reason
    the scanner reaches it — renaming it to ``f0`` would drop it."""
    src = tmp_path / "tests" / "fixtures" / "case"
    src.mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM alpine\nUSER root\n")
    (src / "app.py").write_text("x = 1\n")
    with neutral_tree(src) as tree:
        assert tree.neutral_of("Dockerfile") == "Dockerfile"
        assert tree.neutral_of("app.py") is not None
        assert _eligible(tree.root)


# ══════════════════════════════════════════════════════════════════════
# T5.6 — the honest-comment corrections.
#
# Comment-only changes, so they get comment-only tests. They live here
# rather than in a file of their own because both corrections are
# small, both are 0076 closeout items owned alongside T5.4, and a
# corrected comment with nothing pinning it drifts back.
#
# The judge one is not merely cosmetic: JUDGE_TOOL_SPECS[*].description
# is sent to the model, so a false description IS model-facing
# behaviour.
# ══════════════════════════════════════════════════════════════════════


def _spec(name: str) -> dict:
    for spec in JUDGE_TOOL_SPECS:
        if spec["function"]["name"] == name:
            return spec["function"]
    raise AssertionError(f"no judge tool named {name}")


def test_T56_parse_ast_tool_no_longer_claims_line_ranges():
    """E11: `parse_ast` emits a single start `line` per def/class and no end
    line at all, so "with line ranges" was false."""
    description = _spec("parse_ast")["description"]
    assert "line ranges" not in description
    assert "PYTHON ONLY" in description
    # The load-bearing half: an empty outline must not read as a refutation.
    assert "NOT PARSED" in description


def test_T56_parse_ast_description_matches_measured_behaviour(tmp_path: Path):
    """The corrected description is checked against the parser, not against
    the plan text — a doc fix asserted only against itself proves nothing."""
    description = _spec("parse_ast")["description"]

    ts = tmp_path / "handler.ts"
    ts.write_text("export function sanitize(x: string) { return x; }\n")
    ts_out = parse_ast(str(ts))
    assert ts_out["language"] == "unknown"
    assert ts_out["functions"] == []  # "not parsed", as now advertised

    py = tmp_path / "handler.py"
    py.write_text("def sanitize(x):\n    return x\n\n\nasync def fetch():\n    pass\n")
    py_out = parse_ast(str(py))
    names = {f["name"] for f in py_out["functions"]}
    assert names == {"sanitize"}, "async defs are missing, as now advertised"
    assert set(py_out["functions"][0]) == {"name", "line"}, "start line only"
    assert "async defs are not reported" in description


def test_T56_temperature_comment_no_longer_claims_determinism():
    """E1: `temperature=0.1` was documented as ensuring "deterministic,
    reproducible audit results". Measured reproducibility is 30.4% Dice."""
    source = inspect.getsource(base_agent_module)
    assert "ensures deterministic, reproducible audit results" not in source
    assert "30.4%" in source
    assert "does NOT make an audit" in source
    # The policy itself is unchanged — T5.6 is comments only.
    assert "ModelSettings(temperature=0.1)" in source


# ══════════════════════════════════════════════════════════════════════
# T5.9 — the "no new skill" statement.
#
# The deliverable IS a durable statement, so the test is that the
# statement is durable: an unpinned sentence in a doc is deletable
# without anyone noticing it was a decision.
# ══════════════════════════════════════════════════════════════════════

_SKILLS_MD = (
    Path(__file__).resolve().parents[2] / "shared" / "validate" / "SKILLS.md"
)


def test_T59_no_new_skill_is_stated_explicitly():
    text = _SKILLS_MD.read_text()
    assert "0076" in text
    assert "no new skill" in text.lower()
    assert "adds no agent skill" in text
