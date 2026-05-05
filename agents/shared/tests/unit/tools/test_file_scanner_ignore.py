"""Tests for .vultureignore and .gitignore handling in the file scanner.

Asserts:
- .vultureignore patterns are honored
- .gitignore patterns are honored by default
- VULTURE_IGNORE_GITIGNORE=true disables .gitignore reading
- Both files compose
- Dir-only patterns (trailing /) only match directories
- Hardcoded SKIP_DIRS still applies even without ignore files
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools import file_scanner


@pytest.fixture(autouse=True)
def clear_caches():
    file_scanner._scan_code_files_cached.cache_clear()
    file_scanner._load_ignore_spec.cache_clear()
    yield
    file_scanner._scan_code_files_cached.cache_clear()
    file_scanner._load_ignore_spec.cache_clear()


@pytest.fixture(autouse=True)
def clear_ignore_env(monkeypatch):
    monkeypatch.delenv("VULTURE_IGNORE_GITIGNORE", raising=False)


def _make_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def _scanned_names(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix()
            for p in file_scanner.scan_code_files(str(root))}


class TestVultureIgnore:
    def test_pattern_excludes_matching_dir(self, tmp_path):
        _make_tree(tmp_path, {
            "src/main.py": "x=1",
            ".playwright-mcp/recorded.py": "junk=1",
            ".vultureignore": ".playwright-mcp/\n",
        })
        names = _scanned_names(tmp_path)
        assert "src/main.py" in names
        assert ".playwright-mcp/recorded.py" not in names

    def test_pattern_excludes_matching_file(self, tmp_path):
        _make_tree(tmp_path, {
            "real.py": "x=1",
            "skipped.py": "y=2",
            ".vultureignore": "skipped.py\n",
        })
        names = _scanned_names(tmp_path)
        assert "real.py" in names
        assert "skipped.py" not in names

    def test_glob_pattern(self, tmp_path):
        _make_tree(tmp_path, {
            "src/foo.py": "x=1",
            "src/foo.generated.py": "y=2",
            ".vultureignore": "**/*.generated.py\n",
        })
        names = _scanned_names(tmp_path)
        assert "src/foo.py" in names
        assert "src/foo.generated.py" not in names

    def test_no_ignore_file_means_no_filtering(self, tmp_path):
        _make_tree(tmp_path, {
            "a.py": "x=1",
            "b.py": "y=2",
        })
        names = _scanned_names(tmp_path)
        assert names == {"a.py", "b.py"}


class TestGitignore:
    def test_gitignore_honored_by_default(self, tmp_path):
        _make_tree(tmp_path, {
            "src/keep.py": "x=1",
            "out/generated.py": "y=2",
            ".gitignore": "out/\n",
        })
        names = _scanned_names(tmp_path)
        assert "src/keep.py" in names
        assert "out/generated.py" not in names

    def test_env_var_disables_gitignore(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VULTURE_IGNORE_GITIGNORE", "true")
        _make_tree(tmp_path, {
            "src/keep.py": "x=1",
            "out/generated.py": "y=2",
            ".gitignore": "out/\n",
        })
        names = _scanned_names(tmp_path)
        assert "src/keep.py" in names
        assert "out/generated.py" in names


class TestComposition:
    def test_vultureignore_adds_to_gitignore(self, tmp_path):
        _make_tree(tmp_path, {
            "src/main.py": "x=1",
            "out/x.py": "y=2",
            ".playwright-mcp/recorded.py": "z=3",
            ".gitignore": "out/\n",
            ".vultureignore": ".playwright-mcp/\n",
        })
        names = _scanned_names(tmp_path)
        assert "src/main.py" in names
        assert "out/x.py" not in names
        assert ".playwright-mcp/recorded.py" not in names

    def test_skip_dirs_still_applies_without_ignore_files(self, tmp_path):
        _make_tree(tmp_path, {
            "src/keep.py": "x=1",
            "node_modules/lodash.py": "y=2",
        })
        names = _scanned_names(tmp_path)
        assert "src/keep.py" in names
        assert "node_modules/lodash.py" not in names


class TestDirOnlyPatterns:
    def test_trailing_slash_matches_dir_not_file(self, tmp_path):
        _make_tree(tmp_path, {
            "build/x.py": "x=1",
            "src/build.py": "y=2",
            ".vultureignore": "build/\n",
        })
        names = _scanned_names(tmp_path)
        assert "build/x.py" not in names
        assert "src/build.py" in names


class TestComments:
    def test_comments_and_blanks_ignored(self, tmp_path):
        _make_tree(tmp_path, {
            "a.py": "x=1",
            "skipped.py": "y=2",
            ".vultureignore": (
                "# comment\n"
                "\n"
                "skipped.py\n"
                "# another comment\n"
            ),
        })
        names = _scanned_names(tmp_path)
        assert "a.py" in names
        assert "skipped.py" not in names
