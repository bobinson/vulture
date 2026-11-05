"""The folders the engine never walks are Vulture's default ignore file, not
a list of the plugin's own.

The plugin carries a copy of the repository root's ``default.vultureignore``.
Every folder it lists is excluded, plus the version-control stores, unless the
scanned root's ``.vultureignore`` brings the folder back with a negation, as
the scanner and the backend's staging copy do.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
COPY = Path(__file__).resolve().parents[2] / "src" / "default.vultureignore"
VCS = (".git", ".svn", ".hg", ".bzr")


def _globs() -> list[str]:
    lines = (line.strip() for line in COPY.read_text().splitlines())
    return [line.removesuffix("/") for line in lines if line and not line.startswith("#")]


def _excludes(argv: list[str]) -> list[str]:
    return [b for a, b in zip(argv, argv[1:]) if a == "--exclude"]


@pytest.fixture
def source(tmp_path) -> Path:
    root = tmp_path / "src"
    root.mkdir()
    return root


def test_the_copy_is_the_root_file() -> None:
    assert COPY.read_bytes() == (REPO / "default.vultureignore").read_bytes()


def test_every_listed_folder_and_vcs_store_is_excluded(source) -> None:
    from src.wrapper import _engine_argv

    excludes = _excludes(_engine_argv(str(source), {}))
    for name in (*VCS, *_globs()):
        assert name in excludes, f"missing --exclude {name}: {excludes}"


@pytest.mark.parametrize("line", ["!build/", "!build", "!web/build/"])
def test_a_root_vultureignore_negation_brings_a_folder_back(source, line: str) -> None:
    from src.wrapper import _engine_argv

    (source / ".vultureignore").write_text(f"recorded/\n{line}\n")
    excludes = _excludes(_engine_argv(str(source), {}))
    assert "build" not in excludes, excludes
    assert "dist" in excludes, excludes


def test_nothing_brings_back_a_vcs_store(source) -> None:
    from src.wrapper import _engine_argv

    (source / ".vultureignore").write_text("!.git/\n")
    assert ".git" in _excludes(_engine_argv(str(source), {}))


def test_a_symlinked_vultureignore_is_not_read(source, tmp_path) -> None:
    from src.wrapper import _engine_argv

    outside = tmp_path / "outside"
    outside.write_text("!build/\n")
    (source / ".vultureignore").symlink_to(outside)
    assert "build" in _excludes(_engine_argv(str(source), {}))
