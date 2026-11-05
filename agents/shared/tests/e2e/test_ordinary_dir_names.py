"""E2E: a directory named with an ordinary word is source; a tool's own tree is not.

Business contract
-----------------
The walker pruned every directory whose NAME was on a hardcoded list, at any
depth. The list mixed names a tool gives its own output (`.git`,
`node_modules`, `dist`, `.venv`) with words projects use for their own code, so
a Next.js `app/api/data/route.ts`, a Go `internal/data` package,
`config/env/production.js`, `bin/deploy.sh` and `src/mocks/handlers.ts` were
never read by any agent or tool.

* A directory named `data`, `bin`, `env` or `mocks` is walked like any other: its files are scanned, and the model's tools list and read them.
* Tool-owned names (`node_modules`, `dist`, `build`, `target`, `.venv`,
  `coverage`) and test data (`fixtures`, `testdata`) are still pruned.
* A Python virtualenv is pruned whatever it is called: it is recognised by the
  `pyvenv.cfg` every virtualenv carries, so `env/` holding one stays out, and
  the prune is recorded like any other.
* An ordinary-named output directory the project ignores (`bin/` in a
  `.gitignore`) is still pruned, by the ignore rules.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

NEEDLE = "NEEDLE_b41c"

ORDINARY = (
    "app/api/data/route.ts",
    "internal/data/repo.go",
    "bin/deploy.sh",
    "config/env/production.js",
    "src/mocks/handlers.ts",
)
STILL_PRUNED = (
    "node_modules/pkg/index.js",
    "dist/app.js",
    "build/package/Dockerfile",
    "target/generated/Main.java",
    ".venv/lib/site.py",
    "coverage/lcov-report/sorter.js",
    "fixtures/vulnerable.py",
    "testdata/case.go",
    "env/lib/python3.12/site-packages/pkg/mod.py",
    "tools/py311/lib/python3.11/site-packages/pkg/mod.py",
    "pkg/bin/tool.py",
)
VIRTUALENVS = ("env", "tools/py311")


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    from shared.tools import file_scanner

    root = tmp_path / "repo"
    _write(root, {rel: f"// {NEEDLE} {rel}\n" for rel in ORDINARY + STILL_PRUNED})
    _write(root, {f"{venv}/pyvenv.cfg": "home = /usr/bin\n" for venv in VIRTUALENVS})
    _write(root, {"pkg/.gitignore": "bin/\n"})
    file_scanner.clear_caches()
    return root


def _scanned(root: Path) -> set[str]:
    from shared.tools.file_scanner import scan_code_files

    return {p.relative_to(root).as_posix() for p in scan_code_files(str(root))}


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


@pytest.mark.parametrize("rel", ORDINARY)
def test_an_ordinary_directory_name_is_scanned(tree: Path, rel: str) -> None:
    assert rel in _scanned(tree)


@pytest.mark.parametrize("rel", STILL_PRUNED)
def test_a_tool_tree_is_still_not_scanned(tree: Path, rel: str) -> None:
    assert rel not in _scanned(tree)


@pytest.mark.parametrize("rel", ORDINARY)
def test_the_models_tools_read_an_ordinary_directory(tree: Path, rel: str) -> None:
    assert NEEDLE in _read(tree, rel)


@pytest.mark.parametrize("rel", STILL_PRUNED)
def test_the_models_tools_refuse_a_tool_tree(tree: Path, rel: str) -> None:
    out = _read(tree, rel)
    assert out.startswith("Error:") and "excluded" in out and NEEDLE not in out, out


def test_a_missing_path_in_a_virtualenv_is_refused_as_an_existing_one_is(tree: Path) -> None:
    missing = "env/lib/python3.12/site-packages/pkg/missing.py"
    assert not (tree / missing).exists()
    assert _read(tree, missing) == _read(tree, "node_modules/pkg/index.js")


def test_the_listing_holds_ordinary_directories_and_no_tool_tree(tree: Path) -> None:
    listed = _listed(tree)
    assert set(ORDINARY) <= listed
    assert not listed & set(STILL_PRUNED), sorted(listed & set(STILL_PRUNED))


def test_a_virtualenv_prune_is_recorded(tree: Path) -> None:
    from shared.tools.file_scanner import pruned_dirs

    _scanned(tree)
    assert set(VIRTUALENVS) <= set(pruned_dirs(str(tree)))
