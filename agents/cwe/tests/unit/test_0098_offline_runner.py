"""Unit tests for the offline runner's private helpers (feature 0098).

The business contract lives in ``tests/e2e/test_0098_offline_*.py``; these pin
the helpers it is built from.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from cwe_agent import offline
from cwe_agent.offline import _extract


def test_extract_normalises_list_and_unknown() -> None:
    """A skill may return {'findings': [...]}, a bare list, or neither."""
    assert _extract({"findings": [{"a": 1}]}) == [{"a": 1}]
    assert _extract([{"b": 2}]) == [{"b": 2}]
    assert _extract(None) == []


@pytest.mark.parametrize("name", ["tests", "e2e", "__tests__", "fixtures", "vendor", "skills"])
def test_a_classified_ancestor_is_not_neutral(tmp_path: Path, name: str) -> None:
    assert not offline._is_neutral(tmp_path / name / "tmp")


def test_a_plain_directory_is_neutral() -> None:
    assert offline._is_neutral(Path("/opt/plainbase/x"))


def test_no_neutral_temp_base_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    tainted = tmp_path / "tests" / "tmp"
    tainted.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(offline, "_candidate_bases", lambda: [tainted])

    assert offline.main(["a.py"]) == 2
    assert "TMPDIR" in capsys.readouterr().err


def test_an_unknown_finding_severity_never_blocks() -> None:
    rows = [{"severity": "urgent"}, {"severity": "HIGH"}, {}]

    assert offline.blocking_findings(rows, "info") == [{"severity": "HIGH"}]


def test_gitmodules_paths_are_read_without_git(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitmodules").write_text(
        '[submodule "a"]\n\tpath = libs/a \n\turl = x\n[submodule "b"]\npath=b\n',
        encoding="utf-8",
    )

    assert offline._gitmodule_paths(tmp_path) == {tmp_path / "libs" / "a", tmp_path / "b"}
    assert offline._declared_submodule(tmp_path / "b")
    assert not offline._declared_submodule(tmp_path / "c")


def test_gitmodules_parsing_is_linear(tmp_path: Path) -> None:
    """ReDoS guard: a hostile ``.gitmodules`` line cannot stall the gate."""
    (tmp_path / ".gitmodules").write_text(
        "path =" + " \t" * 50_000 + "x\n" + ("path" * 25_000) + "\n", encoding="utf-8",
    )
    start = time.monotonic()
    offline._gitmodule_paths(tmp_path)

    assert time.monotonic() - start < 0.5


@pytest.mark.parametrize("text", [
    '[submodule "x"]\n\tpath = "' + "\\\\" * 50_000,
    '[submodule "x"]\n\tpath = ' + '"a' * 50_000,
    '[submodule "x"]\n\tpath = ' + "a " * 50_000 + ";",
    "[" * 100_000,
    '[submodule "x"]\n' + "\tpath = lib\n" * 20_000,
], ids=["escapes", "quotes", "spaces", "brackets", "many-lines"])
def test_gitmodules_section_parsing_is_linear(tmp_path: Path, text: str) -> None:
    """ReDoS guard for the ``.gitmodules`` reader (100k characters, well under 0.5 s)."""
    (tmp_path / ".gitmodules").write_text(text, encoding="utf-8")
    start = time.monotonic()
    offline._gitmodule_paths(tmp_path)

    assert time.monotonic() - start < 0.5
