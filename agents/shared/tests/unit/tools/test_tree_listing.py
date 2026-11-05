"""The walker's listing, for code that needs to look at the tree without
re-walking it: ``tree_files`` / ``tree_dirs`` filter it, ``walk_reaches`` and
``present`` give the walker's verdict on one path.

Every answer here must be the walk's own: a file a skill can find is a file
the audit reads, and nothing else. A probe is not a walk, so asking about a
path never adds to what the scan reports it pruned.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from shared.tools import file_scanner
from shared.tools.file_scanner import (
    present,
    pruned_dirs,
    scan_all_files,
    tree_dirs,
    tree_files,
    walk_reaches,
)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("VULTURE_IGNORE_GITIGNORE", raising=False)
    file_scanner.clear_caches()
    yield
    file_scanner.clear_caches()


def _make(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _make(root, {
        ".gitignore": "gen/\n*.log\n",
        ".vultureignore": "recorded/\n",
        "README.md": "x", "app.log": "x", "package-lock.json": "{}",
        "docs/architecture.md": "x", "docs/guide/threat-model.md": "x",
        ".github/workflows/ci.yml": "x", ".github/CODEOWNERS": "x",
        "src/app.py": "x", "src/fuzz_parse.py": "x", "src/sub/.gitignore": "local.py\n",
        "src/sub/local.py": "x", "src/sub/kept.py": "x",
        "gen/architecture.md": "x", "recorded/threat-model.md": "x",
        "node_modules/pkg/architecture.md": "x", ".venv/lib/architecture.md": "x",
        "src_old/app.py": "x", ".vscode/tasks.json": "x", ".vscode/other.json": "x",
    })
    (root / "docs" / "security").mkdir()
    (root / "src" / "__fuzz__").mkdir()
    (root / "node_modules" / "pkg" / "__fuzz__").mkdir()
    (root / "linked.md").symlink_to(root / "README.md")
    return root


def _rels(root: Path, paths) -> set[str]:
    return {p.relative_to(root).as_posix() for p in paths}


class TestTreeFiles:
    def test_the_whole_listing_is_the_walk(self, root: Path) -> None:
        assert _rels(root, tree_files(root)) == _rels(root, scan_all_files(str(root)))

    def test_names_match_at_any_depth_inside_the_walk_only(self, root: Path) -> None:
        found = _rels(root, tree_files(root, names={"architecture.md", "threat-model.md"}))
        assert found == {"docs/architecture.md", "docs/guide/threat-model.md"}

    def test_globs_have_rglob_semantics_on_the_basename(self, root: Path) -> None:
        assert _rels(root, tree_files(root, globs=("fuzz_*",))) == {"src/fuzz_parse.py"}
        assert _rels(root, tree_files(root, globs=("*.md",), under="docs")) == {
            "docs/architecture.md", "docs/guide/threat-model.md"}

    def test_depth_one_is_a_directory_listing(self, root: Path) -> None:
        assert _rels(root, tree_files(root, under=".github", depth=1)) == {".github/CODEOWNERS"}
        top = _rels(root, tree_files(root, depth=1))
        assert {"README.md", "package-lock.json", ".gitignore", ".vultureignore"} <= top
        assert "app.log" not in top and "linked.md" not in top
        assert all("/" not in rel for rel in top)

    def test_under_keeps_the_roots_rules(self, root: Path) -> None:
        assert _rels(root, tree_files(root, under="src/sub")) == {
            "src/sub/.gitignore", "src/sub/kept.py"}
        assert list(tree_files(root, under="gen")) == []
        assert list(tree_files(root, under="node_modules")) == []

    def test_under_tolerates_slashes_and_the_root_token(self, root: Path) -> None:
        assert list(tree_files(root, under="/docs/")) == list(tree_files(root, under="docs"))
        assert list(tree_files(root, under=".")) == list(tree_files(root))


class TestTreeDirs:
    def test_an_empty_directory_the_walk_enters_is_listed(self, root: Path) -> None:
        assert _rels(root, tree_dirs(root, names={"__fuzz__"})) == {"src/__fuzz__"}

    def test_a_restricted_directory_is_listed_as_entered(self, root: Path) -> None:
        assert ".vscode" in _rels(root, tree_dirs(root, depth=1))


class TestWalkReaches:
    def test_agrees_with_the_walk_for_every_path_on_disk(self, root: Path) -> None:
        walked = _rels(root, tree_files(root)) | _rels(root, tree_dirs(root))
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            assert walk_reaches(root, path) is (rel in walked), rel

    def test_the_root_is_reached(self, root: Path) -> None:
        assert walk_reaches(root, root)

    def test_outside_absent_and_dot_dot_are_not_reached(self, root: Path, tmp_path) -> None:
        assert not walk_reaches(root, tmp_path)
        assert not walk_reaches(root, root / "nope.md")
        assert not walk_reaches(root, root / "src" / ".." / "README.md")

    def test_a_probe_records_no_prune(self, root: Path) -> None:
        for rel in ("node_modules/pkg/architecture.md", "gen/architecture.md",
                    ".vscode/other.json", "src_old/app.py"):
            walk_reaches(root, root / rel)
        assert pruned_dirs(str(root)) == []


class TestPresent:
    def test_a_fixed_location_counts_only_where_the_walk_reaches(self, root: Path) -> None:
        assert present(root, "README.md")
        assert present(root, ".github/workflows/ci.yml")
        assert not present(root, "gen/architecture.md")
        assert not present(root, "app.log")
        assert not present(root, "linked.md")
        assert not present(root, "missing.md")

    def test_a_skip_files_name_is_present(self, root: Path) -> None:
        """SKIP_FILES says what the code scan never parses, not what the walk
        never reaches: the lock-file probe depends on the difference."""
        assert present(root, "package-lock.json")

    def test_an_empty_directory_is_present(self, root: Path) -> None:
        assert present(root, "docs/security")
        assert not present(root, "node_modules/pkg/__fuzz__")


class TestCappedListing:
    """The cached listing stops at MAX_FILES and counts every file, images and
    data included. A query must not: evidence past the cap is still evidence."""

    @pytest.fixture
    def capped(self, tmp_path: Path, monkeypatch) -> Path:
        root = tmp_path / "repo"
        _make(root, {f"assets/img{i:02d}.png": "x" for i in range(12)})
        _make(root, {
            "zz/docs/threat-model.md": "x", ".github/CODEOWNERS": "x",
            "zz/node_modules/pkg/threat-model.md": "x",
        })
        (root / "zz" / "src" / "__fuzz__").mkdir(parents=True)
        monkeypatch.setattr(file_scanner, "MAX_FILES", 5)
        return root

    def test_the_listing_knows_it_was_cut_short(self, capped: Path) -> None:
        assert file_scanner._tree_listing(str(capped), 5).truncated

    def test_a_file_past_the_cap_is_still_found(self, capped: Path) -> None:
        assert _rels(capped, tree_files(capped, names={"threat-model.md"})) == {
            "zz/docs/threat-model.md"}

    def test_an_empty_directory_past_the_cap_is_still_found(self, capped: Path) -> None:
        assert _rels(capped, tree_dirs(capped, names={"__fuzz__"})) == {"zz/src/__fuzz__"}

    def test_a_listing_below_a_subdirectory_is_complete(self, capped: Path) -> None:
        assert _rels(capped, tree_files(capped, under=".github", depth=1)) == {
            ".github/CODEOWNERS"}
        assert len(list(tree_files(capped, under="assets"))) == 12

    def test_the_uncapped_query_still_applies_the_walks_rules(self, capped: Path) -> None:
        assert list(tree_files(capped, under="zz/node_modules")) == []

    def test_an_uncapped_query_records_no_prune(self, capped: Path) -> None:
        list(tree_files(capped, names={"threat-model.md"}))
        assert "zz/node_modules" not in pruned_dirs(str(capped))


@pytest.fixture
def case_insensitive(monkeypatch):
    """Simulate a case-insensitive filesystem (APFS, NTFS): a path opens and
    stats whatever its case-folded spelling names, while ``os.listdir`` still
    returns each name as it was created."""
    real = {name: getattr(Path, name) for name in ("is_dir", "is_file", "exists", "is_symlink")}

    def folded(path: Path) -> Path:
        probe = Path(path.anchor)
        for part in path.parts[1:]:
            listed = {n.lower(): n for n in (os.listdir(probe) if real["is_dir"](probe) else ())}
            probe = probe / listed.get(part.lower(), part)
        return probe

    for name, method in real.items():
        monkeypatch.setattr(Path, name, lambda self, _m=method: _m(folded(self)))


class TestSpelling:
    """Every walk rule compares spellings, so a probe may reach a path only as
    its directory spells it: on a case-insensitive filesystem ``.GIT/config``
    opens ``.git/config`` and passes every name rule."""

    def test_a_differently_cased_path_is_not_reached(self, root: Path, case_insensitive) -> None:
        _make(root, {".git/config": "x"})
        assert (root / ".GIT").is_dir(), "the simulation must open the folded path"
        for rel in (".GIT/config", "NODE_MODULES/pkg/architecture.md", "GEN/architecture.md",
                    "Docs/architecture.md"):
            assert not walk_reaches(root, root / rel), rel

    def test_the_spelling_on_disk_is_reached(self, root: Path, case_insensitive) -> None:
        assert walk_reaches(root, root / "docs" / "architecture.md")


class TestWalkExcludes:
    """The walk's rules applied by position, whether or not the path exists."""

    @pytest.mark.parametrize("rel", [
        "node_modules/pkg/missing.js", ".git/nope", "gen/missing.md", "app.log",
        "recorded/missing.md", ".vscode/other.json", "src_old/missing.py",
        "src/sub/local.py",
    ])
    def test_a_rule_hides_the_path_present_or_not(self, root: Path, rel: str) -> None:
        assert file_scanner.walk_excludes(root, root / rel)

    @pytest.mark.parametrize("rel", ["src/missing.py", "docs/new/x.md", ".vscode/tasks.json"])
    def test_no_rule_hides_an_ordinary_path(self, root: Path, rel: str) -> None:
        assert not file_scanner.walk_excludes(root, root / rel)
