"""E2E contract: a `.gitignore` below the scan root is honoured as git honours it.

Git applies every `.gitignore` in the tree to the paths beneath its own
directory, with patterns relative to that directory, and the deepest file that
matches decides. The scanner read only the root's, so a package's own
`.gitignore` and a cache directory that ignores itself (Hypothesis writes
`.hypothesis/.gitignore` containing `*`) were audited as source.

On a root scan with the LLM phase off:

  1. A path ignored by a nested `.gitignore` produces no finding, while the
     same content in a path it does not ignore is reported (the control).
  2. Its patterns are relative to its own directory: a directory of the same
     name elsewhere in the tree is still audited.
  3. A directory pruned by a nested `.gitignore` is reported in `pruned_dirs`,
     root-relative, so lineage reads it as not looked at rather than fixed.
  4. A self-ignoring cache directory contributes nothing.
  5. The offline gate gives the verdict the full audit gives: a staged file
     under a directory a nested `.gitignore` ignores is listed as not scanned,
     whether or not that `.gitignore` is among the staged files.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cwe_agent.agent import run_audit
from cwe_agent.offline import main
from tests._neutral import neutral_dir

COMMAND_INJECTION = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
INJECTION = "cwe.injection.command"
# What Hypothesis writes into its own cache directory, verbatim in substance.
HYPOTHESIS_GITIGNORE = (
    "# This .gitignore file was automatically created by Hypothesis.\n"
    "# Hypothesis gitignores .hypothesis by default.\n"
    "\n"
    "*\n"
)


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _parse_event(events: list[str], name: str) -> dict:
    for event in events:
        if f"event: {name}" in event:
            data = next(ln for ln in event.split("\n") if ln.startswith("data:"))
            return json.loads(data[5:])
    raise AssertionError(f"no '{name}' event in the SSE output")


def _rel(finding: dict, root: Path) -> str:
    raw = str(finding.get("file_path", ""))
    try:
        return Path(raw).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return raw


@pytest.fixture(autouse=True)
def _llm_phase_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
    monkeypatch.delenv("VULTURE_LLM_TIER3", raising=False)
    monkeypatch.delenv("VULTURE_IGNORE_GITIGNORE", raising=False)


@pytest.fixture
def tree(request: pytest.FixtureRequest) -> Path:
    """A project whose `.gitignore` files sit below the root.

    Under a neutrally named directory: the audit classifies a file by every
    component of its absolute path, and pytest's `test_...` tmp_path would
    change what is reported.
    """
    root = neutral_dir(request) / "proj"
    _write(root, "svc/app.py", COMMAND_INJECTION)          # control: audited
    _write(root, "pkg/.gitignore", "stash/\n")
    _write(root, "pkg/stash/app.py", COMMAND_INJECTION)    # ignored by pkg/.gitignore
    _write(root, "stash/app.py", COMMAND_INJECTION)        # same name, not under pkg/
    _write(root, ".hypothesis/.gitignore", HYPOTHESIS_GITIGNORE)
    _write(root, ".hypothesis/examples/app.py", COMMAND_INJECTION)
    return root


def _injection_paths(root: Path) -> tuple[set[str], dict]:
    result = _parse_event(list(run_audit("nested-gitignore", str(root), {})), "result")
    paths = {_rel(f, root) for f in result["findings"] if f.get("check_id") == INJECTION}
    return paths, result


def test_a_nested_gitignore_keeps_its_paths_out_of_the_audit(tree: Path) -> None:
    paths, result = _injection_paths(tree)

    assert "svc/app.py" in paths, (
        "control: the injection must be reported where no .gitignore applies; "
        f"got {sorted(paths)}"
    )
    assert "pkg/stash/app.py" not in paths, (
        "pkg/.gitignore ignores pkg/stash/, so nothing under it may be audited; "
        f"got {sorted(paths)}, pruned_dirs={result.get('pruned_dirs')!r}"
    )


def test_nested_patterns_are_relative_to_their_own_directory(tree: Path) -> None:
    paths, _ = _injection_paths(tree)

    assert "stash/app.py" in paths, (
        "pkg/.gitignore's `stash/` applies beneath pkg/ only; the root's stash/ "
        f"is not ignored by it. Got {sorted(paths)}"
    )


def test_a_self_ignoring_cache_directory_contributes_nothing(tree: Path) -> None:
    paths, result = _injection_paths(tree)

    assert not any(p.startswith(".hypothesis/") for p in paths), (
        ".hypothesis/.gitignore holds `*`: the cache ignores everything in it. "
        f"Got {sorted(paths)}"
    )
    assert not any(_rel(f, tree).startswith(".hypothesis/") for f in result["findings"])


def test_directories_pruned_by_a_nested_gitignore_are_reported(tree: Path) -> None:
    _, result = _injection_paths(tree)
    pruned = set(result.get("pruned_dirs") or [])

    assert {"pkg/stash", ".hypothesis/examples"} <= pruned, (
        "a directory the walk did not enter must be reported root-relative, or "
        f"the backend closes its lineage rows as fixed. pruned_dirs={sorted(pruned)}"
    )


# --- the offline gate ---------------------------------------------------------


@pytest.fixture
def repo(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A hermetic repository and the hook's working directory."""
    root = neutral_dir(request) / "repo"
    (root / ".git").mkdir(parents=True)
    monkeypatch.chdir(root)
    return root


def _json_run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, dict]:
    code = main(["--format", "json", *args])
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("staged_ignore", [False, True])
def test_the_offline_gate_honours_a_nested_gitignore(
    repo: Path, capsys: pytest.CaptureFixture[str], staged_ignore: bool,
) -> None:
    _write(repo, "pkg/.gitignore", "stash/\n")
    _write(repo, "pkg/stash/app.py", COMMAND_INJECTION)
    _write(repo, "svc.py", COMMAND_INJECTION)
    staged = ["pkg/stash/app.py", "svc.py", *(["pkg/.gitignore"] if staged_ignore else [])]

    code, report = _json_run(capsys, *staged)

    assert code == 1
    assert {f["file_path"] for f in report["blocking"]} == {str(repo / "svc.py")}
    assert str(repo / "pkg/stash/app.py") in {row["path"] for row in report["not_scanned"]}
