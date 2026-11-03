"""E2E: the folders Vulture skips by default are listed in one ignore file,
never in code, and a project brings one back from its `.vultureignore`.

Business contract
-----------------
* Every folder skipped by default is a line of ``default.vultureignore`` at the
  repository root, in ``.vultureignore`` syntax. Only the version-control
  stores (``.git``, ``.svn``, ``.hg``, ``.bzr``) are named in code.
* With no ignore file in the project, every folder the file lists is skipped,
  at any depth, and the skip is recorded.
* A negation in the project's root ``.vultureignore`` brings a folder back:
  ``!build/`` every ``build`` directory, ``!web/build/`` that one only, and
  ``!.vscode/`` the whole editor folder rather than only its autorun files. A
  folder brought back is scanned, listed and read by the model's tools, and its
  skip is no longer recorded.
* A ``.gitignore`` negation does not bring a folder back, and nothing brings
  back a version-control store.
* The scanner, the backend and the opengrep plugin are each built from their
  own directory, and each carries a byte-identical copy of the root file.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

NEEDLE = "NEEDLE_9d2e"
REPO = Path(__file__).resolve().parents[4]
VCS = (".git", ".svn", ".hg", ".bzr")
SCANNER_COPY = "agents/shared/shared/tools/default.vultureignore"
COPIES = (
    SCANNER_COPY,
    "backend/pkg/scanignore/default.vultureignore",
    "plugins/opengrep/src/default.vultureignore",
)


def _default_file() -> Path:
    return REPO / "default.vultureignore"


def _globs() -> list[str]:
    """The file's patterns, read here independently of the scanner."""
    lines = (line.strip() for line in _default_file().read_text().splitlines())
    return [line.removesuffix("/") for line in lines if line and not line.startswith("#")]


def _sample(glob: str) -> str:
    """A directory name ``glob`` matches: ``*-backup`` -> ``src-backup``."""
    return glob.replace("*", "src")


def _write(root: Path, rels) -> None:
    for rel in rels:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"// {NEEDLE} {rel}\n")


def _tree(tmp_path: Path, rels, ignore_files: dict[str, str] | None = None) -> Path:
    from shared.tools.file_scanner import clear_caches

    root = tmp_path / "repo"
    _write(root, rels)
    for rel, text in (ignore_files or {}).items():
        (root / rel).write_text(text)
    clear_caches()
    return root


def _scanned(root: Path) -> set[str]:
    from shared.tools.file_scanner import scan_code_files

    return {p.relative_to(root).as_posix() for p in scan_code_files(str(root))}


def _pruned(root: Path) -> set[str]:
    from shared.tools.file_scanner import pruned_dirs

    _scanned(root)
    return set(pruned_dirs(str(root)))


def _invoke(tool, **arguments):
    from agents.tool_context import ToolContext

    raw = json.dumps(arguments)
    ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id="call", tool_arguments=raw)
    return asyncio.run(tool.on_invoke_tool(ctx, raw))


def _read(root: Path, rel: str) -> str:
    from shared.tools.file_reader import make_read_file_tool

    return str(_invoke(make_read_file_tool(str(root)), path=str(root / rel)))


def _listed(root: Path) -> set[str]:
    from shared.tools.file_lister import make_list_files_tool

    out = _invoke(make_list_files_tool(str(root)), path=str(root), pattern="*")
    return {Path(p).relative_to(root).as_posix() for p in out}


def test_the_code_names_only_the_version_control_stores() -> None:
    from shared.tools import file_scanner

    literal = {g for g in _globs() if not set(g) & set("*?[")}
    assert file_scanner.VCS_DIRS == frozenset(VCS)
    assert file_scanner.SKIP_DIRS == file_scanner.VCS_DIRS | literal
    assert file_scanner.DEFAULT_IGNORE_FILE == REPO / SCANNER_COPY


@pytest.mark.parametrize("copy", COPIES)
def test_every_build_carries_the_root_file(copy: str) -> None:
    assert (REPO / copy).read_bytes() == _default_file().read_bytes()


@pytest.mark.parametrize("name", [*map(_sample, _globs()), *VCS])
def test_a_listed_folder_is_skipped_at_any_depth_and_recorded(tmp_path, name: str) -> None:
    root = _tree(tmp_path, ("app.py", f"{name}/a.py", f"pkg/{name}/b.py"))
    assert _scanned(root) == {"app.py"}
    pruned = _pruned(root)
    for where in (name, f"pkg/{name}"):
        assert any(p == where or p.startswith(f"{where}/") for p in pruned), (where, pruned)


def test_a_root_vultureignore_negation_brings_every_such_folder_back(tmp_path) -> None:
    root = _tree(
        tmp_path, ("build/app.js", "web/build/app.js", "dist/app.js"),
        {".vultureignore": "!build/\n"},
    )
    assert _scanned(root) == {"build/app.js", "web/build/app.js"}
    assert NEEDLE in _read(root, "web/build/app.js")
    assert {"build/app.js", "web/build/app.js"} <= _listed(root)
    assert not {"build", "web/build"} & _pruned(root)


def test_a_path_negation_brings_back_that_folder_only(tmp_path) -> None:
    root = _tree(
        tmp_path, ("build/app.js", "web/build/app.js"), {".vultureignore": "!web/build/\n"},
    )
    assert _scanned(root) == {"web/build/app.js"}
    assert "excluded" in _read(root, "build/app.js")


def test_a_glob_negation_brings_back_a_backup_folder(tmp_path) -> None:
    root = _tree(
        tmp_path, ("src-backup/old.py", "lib_old/old.py"), {".vultureignore": "!*-backup/\n"},
    )
    assert _scanned(root) == {"src-backup/old.py"}


def test_bringing_back_an_editor_folder_reads_all_of_it(tmp_path) -> None:
    rels = (".vscode/tasks.json", ".vscode/extensions.json")
    assert _scanned(_tree(tmp_path / "a", rels)) == {".vscode/tasks.json"}
    root = _tree(tmp_path / "b", rels, {".vultureignore": "!.vscode/\n"})
    assert _scanned(root) == set(rels)


def test_a_gitignore_negation_does_not_bring_a_folder_back(tmp_path) -> None:
    root = _tree(tmp_path, ("build/app.js", "app.js"), {".gitignore": "!build/\n"})
    assert _scanned(root) == {"app.js"}
    assert "excluded" in _read(root, "build/app.js")


@pytest.mark.parametrize("name", VCS)
def test_a_version_control_store_is_never_brought_back(tmp_path, name: str) -> None:
    root = _tree(tmp_path, (f"{name}/hooks/run.py",), {".vultureignore": f"!{name}/\n"})
    assert _scanned(root) == set()
    assert "excluded" in _read(root, f"{name}/hooks/run.py")
