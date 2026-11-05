"""``list_files`` keeps ``rglob(pattern)`` semantics over the audit walk.

The listing is the walk's, not a raw ``rglob``; the PATTERN still means what
``Path.rglob`` makes of it: an implied leading ``**``, ``**`` spanning any
number of directories, ``*`` and ``?`` within one name. A pattern ``rglob``
refuses or answers with directories only matches no file -- and the tool never
raises on one, because the pattern is model-supplied.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools import file_scanner
from shared.tools.file_lister import list_files


@pytest.fixture(autouse=True)
def _fresh():
    file_scanner.clear_caches()
    yield
    file_scanner.clear_caches()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in ("m.py", ".h.py", "src/s.py", "src/x/y/t.py", "src/z.ts", "src2/q.py",
                "a/1.py", "b/a/2.py", "web/app.ts"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n")
    return root


def _rglob(root: Path, pattern: str) -> list[str]:
    return sorted(str(p) for p in root.rglob(pattern) if p.is_file())


@pytest.mark.parametrize("pattern", [
    "*.py", "src/**/*.py", "**/*.ts", "a/*.py", "*", "**/a/*.py", "s*/**/*.py",
    "src//*.py", "./*.py", "**/**/*.py", "[sa]*/*.py", "?.py", "*.PY", ".", "**", "src/**",
])
def test_a_pattern_means_what_rglob_makes_of_it(tree: Path, pattern: str) -> None:
    assert list_files(str(tree), pattern) == _rglob(tree, pattern)


@pytest.mark.parametrize("pattern", ["/abs/*.py", "a**b", "", "../*.py", "src/../*.py"])
def test_a_pattern_rglob_refuses_lists_nothing_and_never_raises(tree: Path, pattern: str) -> None:
    assert list_files(str(tree), pattern) == []


def test_the_recursive_wildcard_spans_directories(tree: Path) -> None:
    got = {Path(p).relative_to(tree).as_posix() for p in list_files(str(tree), "src/**/*.py")}
    assert got == {"src/s.py", "src/x/y/t.py"}
