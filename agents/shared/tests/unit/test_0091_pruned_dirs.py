"""Feature 0091 §6.5 — the walker reports what it refused to descend into.

The backend subtracts these prefixes from the scan's scope. Without them it
cannot tell "this scan proved nothing is there" from "this scan never looked",
and the absence rule then closes every lineage row under a pruned tree — which
is how a finding under `.vscode` disappears from a root scan that never entered
the directory (§2 D2).

What is pruned is NOT changed here: that is P2's job. This phase only makes the
existing pruning visible.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools.file_scanner import clear_caches, pruned_dirs, scan_code_files


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _tree(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")


def test_hardcoded_skip_dirs_are_reported(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _tree(root)
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "index.js").write_text("1\n", encoding="utf-8")

    scan_code_files(str(root))

    assert "node_modules" in pruned_dirs(str(root))


def test_only_the_outermost_prefix_is_reported(tmp_path: Path) -> None:
    """The walker never descends, so it never learns the children exist.

    The prefix is what the backend needs: it matches every path beneath it.
    """
    root = tmp_path / "tree"
    _tree(root)
    (root / "node_modules" / "left-pad").mkdir(parents=True)

    scan_code_files(str(root))

    assert "node_modules/left-pad" not in pruned_dirs(str(root))


def test_nested_prefixes_are_root_relative(tmp_path: Path) -> None:
    """Root-relative, never absolute — the backend joins these onto the root."""
    root = tmp_path / "tree"
    _tree(root)
    (root / "src" / "__pycache__").mkdir()

    scan_code_files(str(root))

    prefixes = pruned_dirs(str(root))
    assert "src/__pycache__" in prefixes
    assert not any(p.startswith("/") for p in prefixes)


def test_gitignored_directories_are_reported(tmp_path: Path) -> None:
    """A .gitignore prune is as invisible to the backend as a SKIP_DIRS one."""
    root = tmp_path / "tree"
    _tree(root)
    (root / ".gitignore").write_text("vendor/\n", encoding="utf-8")
    (root / "vendor").mkdir()
    (root / "vendor" / "lib.py").write_text("y = 2\n", encoding="utf-8")

    scan_code_files(str(root))

    assert "vendor" in pruned_dirs(str(root))


def test_scanned_directories_are_not_reported(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _tree(root)

    scan_code_files(str(root))

    assert "src" not in pruned_dirs(str(root))


def test_an_unscanned_root_reports_nothing(tmp_path: Path) -> None:
    assert pruned_dirs(str(tmp_path / "never-walked")) == []


def test_clear_caches_drops_the_record(tmp_path: Path) -> None:
    """The record is produced BY the cached walk and must die with it.

    A stale entry would report the previous audit's tree as out of scope for
    this one — and out-of-scope rows are exempted from closure, so the error is
    silent rather than loud.
    """
    root = tmp_path / "tree"
    _tree(root)
    (root / "node_modules").mkdir()
    scan_code_files(str(root))
    assert pruned_dirs(str(root))

    clear_caches()

    assert pruned_dirs(str(root)) == []
