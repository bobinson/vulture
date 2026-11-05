"""The model-facing tools' one confinement check, ``scan_refusal``.

Three properties a model must not be able to get around:

* the answer for a path does not depend on whether it exists -- otherwise the
  choice between "excluded" and "not found" tells the model whether a hidden
  file is there (``node_modules/pkg/missing.js`` against ``index.js``);
* no tool hands over the dotenv family (``.env``, ``.env.<anything>``,
  ``.envrc``), committed or not;
* a directory is a scope, not a file: ``.vscode`` can be listed, and the walk
  decides that only its autorun files are inside.

On a case-insensitive filesystem a differently-cased spelling opens the same
file while every name rule compares spellings; the walk check refuses it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools import file_scanner
from shared.tools.confine import EXCLUDED, OUTSIDE, admitted_files, scan_refusal
from tests.unit.tools.test_tree_listing import case_insensitive  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("VULTURE_IGNORE_GITIGNORE", raising=False)
    file_scanner.clear_caches()
    yield
    file_scanner.clear_caches()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    root = (tmp_path / "repo").resolve()
    files = {
        ".gitignore": "secrets/\n", ".vultureignore": "recorded/\n",
        "src/app.py": "x", "node_modules/pkg/index.js": "x", ".git/config": "x",
        "secrets/key.py": "x", "recorded/capture.py": "x", "package-lock.json": "{}",
        ".env": "A=1", ".env.local": "A=1", "config/.env.production": "A=1",
        ".env.example": "A=", ".envrc": "export A=1", "environment.py": "x",
        ".vscode/tasks.json": "{}", ".vscode/other.json": "{}", "src_old/app.py": "x",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _refusal(root: Path, rel: str) -> str:
    return scan_refusal(root / rel, root)


class TestExistenceIsNotRevealed:
    @pytest.mark.parametrize("present, missing", [
        ("node_modules/pkg/index.js", "node_modules/pkg/missing.js"),
        (".git/config", ".git/nope"),
        ("secrets/key.py", "secrets/missing.py"),
        ("recorded/capture.py", "recorded/missing.py"),
        (".vscode/other.json", ".vscode/missing.json"),
        ("src_old/app.py", "src_old/missing.py"),
        ("package-lock.json", "src/yarn.lock"),
        (".env.local", ".env.staging"),
    ])
    def test_a_missing_hidden_path_gets_the_answer_an_existing_one_gets(
        self, root: Path, present: str, missing: str,
    ) -> None:
        assert not (root / missing).exists()
        assert _refusal(root, present) == EXCLUDED
        assert _refusal(root, missing) == EXCLUDED

    @pytest.mark.parametrize("missing", ["src/missing.py", "docs/new.md", ".vscode/launch.json"])
    def test_a_missing_ordinary_path_is_left_to_the_tools_not_found(
        self, root: Path, missing: str,
    ) -> None:
        assert _refusal(root, missing) == ""

    def test_outside_stays_outside(self, root: Path) -> None:
        assert _refusal(root, "../elsewhere.py") == OUTSIDE


class TestDotenvFamily:
    @pytest.mark.parametrize("rel", [
        ".env", ".env.local", "config/.env.production", ".env.example", ".envrc",
    ])
    def test_every_dotenv_file_is_withheld(self, root: Path, rel: str) -> None:
        assert _refusal(root, rel) == EXCLUDED

    def test_a_name_that_merely_starts_with_env_is_not(self, root: Path) -> None:
        assert _refusal(root, "environment.py") == ""

    def test_no_dotenv_file_is_listed(self, root: Path) -> None:
        listed = {p.relative_to(root).as_posix() for p in admitted_files(root)}
        assert not {n for n in listed if Path(n).name.startswith(".env")}
        assert "environment.py" in listed


class TestDirectoryScopes:
    def test_an_editor_directory_is_a_scope(self, root: Path) -> None:
        assert _refusal(root, ".vscode") == ""
        assert [p.name for p in admitted_files(root, ".vscode")] == ["tasks.json"]

    def test_a_pruned_directory_is_not(self, root: Path) -> None:
        assert _refusal(root, "node_modules") == EXCLUDED
        assert _refusal(root, "node_modules/pkg") == EXCLUDED


class TestCaseInsensitiveFilesystem:
    @pytest.mark.parametrize("rel", [".GIT/config", ".ENV", "SECRETS/key.py", "Recorded/capture.py",
                                     "NODE_MODULES/pkg/index.js"])
    def test_another_spelling_of_a_hidden_path_is_refused(
        self, root: Path, rel: str, case_insensitive,  # noqa: F811
    ) -> None:
        assert (root / rel).exists(), "the simulation must open the folded path"
        assert _refusal(root, rel) == EXCLUDED

    def test_another_spelling_of_an_ordinary_path_is_refused_too(
        self, root: Path, case_insensitive,  # noqa: F811
    ) -> None:
        """The walk never lists ``SRC/app.py``: only the spelling it lists is
        reached, so a probe cannot step around a name rule by changing case."""
        assert _refusal(root, "src/app.py") == ""
        assert _refusal(root, "SRC/app.py") == EXCLUDED
