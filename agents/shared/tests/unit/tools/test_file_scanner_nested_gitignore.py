"""Nested `.gitignore` files, with git's semantics (see gitignore(5)).

- A `.gitignore` applies to the paths beneath its own directory, its patterns
  relative to that directory (a leading or middle slash anchors there).
- The deepest `.gitignore` whose patterns match decides; within one file the
  last matching pattern does.
- A `.gitignore` inside an ignored directory is never read: git cannot
  re-include a path whose parent directory is excluded.
- A symlinked `.gitignore` is not followed (git >= 2.32).
- `.vultureignore` stays root-only and overrides every `.gitignore`.
- `VULTURE_IGNORE_GITIGNORE=true` disables every `.gitignore`, nested included.

Every walk built on the shared walker (code files, all files, backups, the
pattern search) applies them, and a directory they prune is reported.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from shared.tools import file_scanner
from shared.tools.pattern_matcher import search_pattern


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("VULTURE_IGNORE_GITIGNORE", raising=False)
    file_scanner.clear_caches()
    file_scanner._load_ignore_spec.cache_clear()
    yield
    file_scanner.clear_caches()
    file_scanner._load_ignore_spec.cache_clear()


def _make(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _code(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in file_scanner.scan_code_files(str(root))}


def _all(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in file_scanner.scan_all_files(str(root))}


class TestScope:
    def test_patterns_apply_beneath_their_directory_only(self, tmp_path):
        _make(tmp_path, {
            "sub/.gitignore": "gen.py\n",
            "sub/gen.py": "x=1", "sub/deep/gen.py": "x=1", "gen.py": "x=1",
        })
        names = _code(tmp_path)
        assert "sub/gen.py" not in names
        assert "sub/deep/gen.py" not in names
        assert "gen.py" in names

    def test_a_leading_slash_anchors_to_the_gitignores_directory(self, tmp_path):
        _make(tmp_path, {
            "sub/.gitignore": "/stash/\n",
            "sub/stash/a.py": "x=1", "sub/deep/stash/a.py": "x=1", "stash/a.py": "x=1",
        })
        names = _code(tmp_path)
        assert "sub/stash/a.py" not in names
        assert "sub/deep/stash/a.py" in names
        assert "stash/a.py" in names

    def test_a_middle_slash_anchors_to_the_gitignores_directory(self, tmp_path):
        _make(tmp_path, {
            "sub/.gitignore": "gen/out.py\n",
            "sub/gen/out.py": "x=1", "sub/deep/gen/out.py": "x=1",
        })
        names = _code(tmp_path)
        assert "sub/gen/out.py" not in names
        assert "sub/deep/gen/out.py" in names

    def test_a_self_ignoring_directory_yields_nothing(self, tmp_path):
        _make(tmp_path, {
            ".hypothesis/.gitignore": "# created by Hypothesis\n*\n",
            ".hypothesis/constants/0a1b2c3d": "[1, 2, 'x']\n",
            ".hypothesis/unicode_data/14.0.0/charmap.json.gz": "zz",
            "app.py": "x=1",
        })
        assert not any(n.startswith(".hypothesis/") for n in _all(tmp_path))
        assert "app.py" in _code(tmp_path)


class TestPrecedence:
    def test_a_deeper_negation_reincludes(self, tmp_path):
        _make(tmp_path, {
            ".gitignore": "gen_*.py\n",
            "sub/.gitignore": "!gen_keep.py\n",
            "gen_keep.py": "x=1", "sub/gen_keep.py": "x=1", "sub/gen_other.py": "x=1",
        })
        names = _code(tmp_path)
        assert "gen_keep.py" not in names
        assert "sub/gen_keep.py" in names
        assert "sub/gen_other.py" not in names

    def test_a_shallower_negation_cannot_override_a_deeper_ignore(self, tmp_path):
        _make(tmp_path, {
            ".gitignore": "!sub/x.py\n",
            "sub/.gitignore": "x.py\n",
            "sub/x.py": "x=1",
        })
        assert "sub/x.py" not in _code(tmp_path)

    def test_the_last_matching_pattern_in_one_file_decides(self, tmp_path):
        _make(tmp_path, {
            "sub/.gitignore": "*.py\n!keep.py\n",
            "sub/keep.py": "x=1", "sub/drop.py": "x=1",
        })
        names = _code(tmp_path)
        assert "sub/keep.py" in names
        assert "sub/drop.py" not in names

    def test_a_gitignore_inside_an_ignored_directory_is_never_read(self, tmp_path):
        _make(tmp_path, {
            ".gitignore": "stash/\n",
            "stash/.gitignore": "!*\n",
            "stash/a.py": "x=1",
        })
        assert "stash/a.py" not in _code(tmp_path)

    def test_vultureignore_overrides_a_nested_negation(self, tmp_path):
        _make(tmp_path, {
            ".vultureignore": "sub/keep.py\n",
            "sub/.gitignore": "*.py\n!keep.py\n",
            "sub/keep.py": "x=1",
        })
        assert "sub/keep.py" not in _code(tmp_path)

    def test_a_vultureignore_negation_overrides_a_nested_ignore(self, tmp_path):
        _make(tmp_path, {
            ".vultureignore": "!sub/gen.py\n",
            "sub/.gitignore": "gen.py\n",
            "sub/gen.py": "x=1",
        })
        assert "sub/gen.py" in _code(tmp_path)


class TestSwitchesAndSafety:
    def test_the_opt_out_disables_nested_gitignores_too(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VULTURE_IGNORE_GITIGNORE", "true")
        _make(tmp_path, {"sub/.gitignore": "gen.py\n", "sub/gen.py": "x=1"})
        assert "sub/gen.py" in _code(tmp_path)

    def test_a_symlinked_gitignore_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        _make(outside, {"rules": "*.py\n"})
        root = tmp_path / "root"
        _make(root, {"sub/a.py": "x=1"})
        os.symlink(outside / "rules", root / "sub" / ".gitignore")
        assert "sub/a.py" in _code(root)

    def test_a_symlinked_vultureignore_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        _make(outside, {"rules": "*.py\n"})
        root = tmp_path / "root"
        _make(root, {"a.py": "x=1"})
        os.symlink(outside / "rules", root / ".vultureignore")
        assert "a.py" in _code(root)

    def test_an_edited_gitignore_applies_after_clear_caches(self, tmp_path):
        _make(tmp_path, {"sub/.gitignore": "", "sub/a.py": "x=1"})
        assert "sub/a.py" in _code(tmp_path)
        (tmp_path / "sub" / ".gitignore").write_text("a.py\n")
        (tmp_path / ".gitignore").write_text("other/\n")
        file_scanner.clear_caches()
        assert "sub/a.py" not in _code(tmp_path)


class TestEveryWalk:
    def test_backup_walk(self, tmp_path):
        _make(tmp_path, {"sub/.gitignore": "old/\n", "sub/old/a.py.bak": "x", "b.py.bak": "x"})
        names = {p.relative_to(tmp_path).as_posix()
                 for p in file_scanner.scan_backup_files(str(tmp_path))}
        assert names == {"b.py.bak"}

    def test_pattern_search(self, tmp_path):
        _make(tmp_path, {"sub/.gitignore": "gen.py\n",
                         "sub/gen.py": "NEEDLE = 1\n", "sub/main.py": "NEEDLE = 2\n"})
        hits = {Path(h["file"]).relative_to(tmp_path).as_posix()
                for h in search_pattern(str(tmp_path), "NEEDLE")}
        assert hits == {"sub/main.py"}

    def test_a_directory_pruned_by_a_nested_gitignore_is_reported(self, tmp_path):
        _make(tmp_path, {"pkg/.gitignore": "stash/\n", "pkg/stash/a.py": "x=1"})
        _code(tmp_path)
        assert "pkg/stash" in file_scanner.pruned_dirs(str(tmp_path))


class TestPathQuery:
    """`path_ignored` answers, for one path, what the walk decided."""

    @pytest.fixture
    def root(self, tmp_path):
        _make(tmp_path, {
            ".gitignore": "gen_*.py\n",
            "sub/.gitignore": "!gen_keep.py\nstash/\n",
            ".hypothesis/.gitignore": "*\n",
            ".hypothesis/constants/c1": "x",
            "gen_a.py": "x", "sub/gen_keep.py": "x", "sub/gen_b.py": "x",
            "sub/stash/a.py": "x", "sub/main.py": "x", "main.py": "x",
        })
        return tmp_path

    def test_agrees_with_the_walk_for_every_file(self, root):
        walked = _all(root)
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            rel = path.relative_to(root).as_posix()
            assert file_scanner.path_ignored(root, path) is (rel not in walked), rel
