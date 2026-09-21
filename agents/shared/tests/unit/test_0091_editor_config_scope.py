"""Feature 0091 P2 (D2) — un-pruning editor directories, and the `pruned_dirs`
record that has to stay honest while it happens.

THE INTERACTION THIS PINS. Two P1/P2 mechanisms meet here and can silently
cancel each other out:

* D2 lifts `WELL_KNOWN_AUTORUN_FILES` out of directories in ``SKIP_DIRS``, so a
  root scan finally READS `.vscode/tasks.json`.
* §6.5 makes the walker report every prefix it refused to enter, and the
  backend subtracts those prefixes from the scan's scope
  (``scanScope.contains`` in ``service/lineage_scan_pass.go``): a lineage row
  whose file lies under one is recorded ``out_of_scope`` and left untouched.

If the walker reported the CONTAINER — a bare `.vscode` — while scanning
`.vscode/tasks.json`, the backend's prefix match would put the file it just
read out of scope. Nothing would be wrongly closed, so the failure is silent;
but the autorun row could then never close either, because the scope check runs
before the tier rules and returns first. A genuinely repaired folder-open task
would stay `open` forever, and the one lineage row this feature exists to
protect would be the one row it broke.

So the record is kept at the granularity that is actually pruned: the files and
sub-directories inside the editor directory that were NOT read, and never the
container the walker entered. ``_contains`` below is a transcription of the Go
predicate, so the assertions are made against the real consumer's semantics
rather than against a restatement of the Python side.

The pruning half is the control: an editor directory with nothing allowlisted in it is
directory is pruned in full again, the container IS the reported prefix, and
every path beneath it is out of scope — which is the correct answer once
nothing in it was read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools.file_scanner import (
    WELL_KNOWN_AUTORUN_FILES,
    clear_caches,
    pruned_dirs,
    scan_autorun_files,
    scan_code_files,
)


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _contains(pruned: list[str], rel_path: str) -> bool:
    """``scanScope.contains`` from ``internal/service/lineage_scan_pass.go``.

    Transcribed rather than approximated: this predicate is what decides
    ``out_of_scope``, and a test that used a looser rule would pass on a record
    the backend rejects.
    """
    rel = rel_path.strip().replace("\\", "/").removeprefix("./").strip("/")
    return not any(rel == p or rel.startswith(p + "/") for p in pruned)


def _tree(root: Path) -> None:
    """A project root with source, an editor directory carrying an autorun file
    plus unrelated content, and an ordinary pruned directory."""
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    (root / ".vscode").mkdir()
    (root / ".vscode" / "tasks.json").write_text("{}\n", encoding="utf-8")
    (root / ".vscode" / "notes.md").write_text("# scratch\n", encoding="utf-8")
    (root / ".vscode" / "extensions").mkdir()
    (root / ".vscode" / "extensions" / "a.json").write_text("{}\n", encoding="utf-8")

    (root / "node_modules").mkdir()
    (root / "node_modules" / "left-pad").mkdir()


def _rels(root: Path, paths: list[Path]) -> set[str]:
    return {p.relative_to(root).as_posix() for p in paths}


# --------------------------------------------------------------------------- #
# Default: the allowlist is on
# --------------------------------------------------------------------------- #


def test_the_autorun_file_is_scanned_from_a_root_scan(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    _tree(root)

    assert ".vscode/tasks.json" in _rels(root, scan_code_files(str(root)))


def test_the_scanned_autorun_file_is_in_scope(tmp_path: Path) -> None:
    """The interaction proper: the file was read, so the backend must not be
    told it was not. An out-of-scope row returns before the tier rules and can
    never close, so this silence would freeze the row rather than mis-close it.
    """
    root = tmp_path / "tree"
    _tree(root)
    scan_code_files(str(root))

    pruned = pruned_dirs(str(root))

    assert _contains(pruned, ".vscode/tasks.json"), (
        "`.vscode/tasks.json` was read by this scan, but a prefix in "
        f"pruned_dirs covers it, so the backend would record every lineage row "
        f"there as out_of_scope and never close one: {pruned}"
    )


def test_the_container_directory_is_not_reported_as_a_blanket_prefix(
    tmp_path: Path,
) -> None:
    """A bare `.vscode` is the one entry that would swallow the file above."""
    root = tmp_path / "tree"
    _tree(root)
    scan_code_files(str(root))

    assert ".vscode" not in pruned_dirs(str(root))


def test_what_was_not_read_inside_it_is_still_reported(tmp_path: Path) -> None:
    """"Everything else stays pruned" is not a figure of speech: the file and
    the sub-directory the walker skipped are reported at their own granularity,
    so a lineage row on either is out of scope rather than fixed."""
    root = tmp_path / "tree"
    _tree(root)
    scan_code_files(str(root))

    pruned = pruned_dirs(str(root))

    assert ".vscode/notes.md" in pruned
    assert ".vscode/extensions" in pruned
    assert not _contains(pruned, ".vscode/extensions/a.json"), (
        "the sub-directory was never entered, so a row beneath it must be out "
        f"of scope: {pruned}"
    )


def test_unrelated_pruning_is_unchanged(tmp_path: Path) -> None:
    """D2 carves one hole and no others."""
    root = tmp_path / "tree"
    _tree(root)
    scan_code_files(str(root))

    pruned = pruned_dirs(str(root))

    assert "node_modules" in pruned
    assert not _contains(pruned, "node_modules/left-pad/index.js")
    assert _contains(pruned, "src/app.py")


def test_an_editor_directory_with_nothing_allowlisted_is_pruned_whole(
    tmp_path: Path,
) -> None:
    """No autorun file, nothing to enter for: the container is the prefix, as
    it was before D2."""
    root = tmp_path / "tree"
    _tree(root)
    (root / ".eclipse").mkdir()
    (root / ".eclipse" / "prefs.epf").write_text("a=b\n", encoding="utf-8")

    scan_code_files(str(root))

    assert ".eclipse" in pruned_dirs(str(root))


def test_extensionless_hook_files_are_reachable(tmp_path: Path) -> None:
    """`.claude/hooks/*` entries routinely carry no extension, so the extension
    allowlist would drop them from the ordinary scan set. The autorun walk is
    keyed on the PATH and reaches them anyway."""
    root = tmp_path / "tree"
    _tree(root)
    (root / ".claude" / "hooks").mkdir(parents=True)
    (root / ".claude" / "hooks" / "pre").write_text("#!/bin/sh\n", encoding="utf-8")

    assert ".claude/hooks/pre" in _rels(root, scan_autorun_files(str(root)))
    assert ".claude/hooks/pre" not in _rels(root, scan_code_files(str(root)))

# --------------------------------------------------------------------------- #
# The allowlist itself
# --------------------------------------------------------------------------- #


def test_every_allowlisted_path_is_lifted_out(tmp_path: Path) -> None:
    """Each entry, materialised and scanned. A pattern that no walk ever yields
    is a coverage claim with nothing behind it."""
    root = tmp_path / "tree"
    _tree(root)
    expected = set()
    for pattern in WELL_KNOWN_AUTORUN_FILES:
        rel = pattern.replace("*.xml", "run.xml").replace("*.sh", "setup.sh")
        rel = rel.replace("hooks/*", "hooks/pre-commit")
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
        expected.add(rel)

    assert _rels(root, scan_autorun_files(str(root))) == expected


def test_a_lookalike_outside_the_editor_directory_is_not_special(
    tmp_path: Path,
) -> None:
    """Patterns are anchored at the scanned root. A `tasks.json` somewhere else
    is an ordinary file and gets no exemption from anything."""
    root = tmp_path / "tree"
    _tree(root)
    nested = root / "pkg" / ".vscode"
    nested.mkdir(parents=True)
    (nested / "tasks.json").write_text("{}\n", encoding="utf-8")

    scan_code_files(str(root))

    assert scan_autorun_files(str(root)) == [root / ".vscode" / "tasks.json"]
    assert "pkg/.vscode" in pruned_dirs(str(root))
