"""Feature 0091 — the autorun SKILL must recognise its rules when the scan root
is the editor directory.

The walker and the skill deliberately share one matcher: the walker decides
which files to yield, the skill decides which rule owns each one. Both match a
ROOT-RELATIVE path against patterns rooted at the repository
(`.vscode/tasks.json`). Stand the scan on `.vscode` and the path becomes
`tasks.json` — the walker was fixed to re-anchor, but the skill's rule
ownership was not, so the file was read and then owned by no rule and reported
nothing.

Measured live: `check_workspace_autorun('…/blu-simulator/.vscode')` returned
`{"findings": []}` while the same call on the parent returned the critical
CWE-506 folder-open finding, and the empty result re-closed VLT-92190.
"""

import json

import pytest

from cwe_agent.skills.workspace_autorun_check import check_workspace_autorun

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
    (tmp_path / "package.json").write_text("{}")
    return tmp_path


def _titles(result):
    return [f["title"] for f in result["findings"]]


def test_reports_from_the_repository_root(workspace):
    """The case that already worked — pinned against regression."""
    got = _titles(check_workspace_autorun(str(workspace)))
    assert got, "expected the folder-open finding from the repository root"


def test_reports_when_scanned_from_the_editor_dir(workspace):
    """The same tree, scanned one level down, must report the same finding."""
    got = _titles(check_workspace_autorun(str(workspace / ".vscode")))
    assert got, (
        "scanning .vscode directly reported nothing; the finding must not "
        "disappear because the scan stood on the editor directory"
    )


def test_same_finding_either_way(workspace):
    """Not merely non-empty — the SAME rule must fire, at the same line."""
    from_root = check_workspace_autorun(str(workspace))["findings"]
    from_dir = check_workspace_autorun(str(workspace / ".vscode"))["findings"]
    key = lambda fs: sorted(  # noqa: E731
        (f["check_id"], f["category"], f["line_start"]) for f in fs
    )
    assert key(from_dir) == key(from_root)


def test_unrelated_directory_reports_nothing(workspace):
    """The re-anchoring must not turn ordinary files into autorun files."""
    src = workspace / "src"
    src.mkdir()
    (src / "tasks.json").write_text(json.dumps(TASKS))
    assert check_workspace_autorun(str(src))["findings"] == []
