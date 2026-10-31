"""Unit contract: ``scan_set_exclusion`` is the walker's own scan-set predicate.

The offline gate reports WHY a file was not scanned. It must not re-derive the
scanner's rules, so the reason comes from the same predicate the walker uses:
a file the walker yields has no exclusion, and a file it drops names its cause.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared.tools.file_scanner import clear_caches, scan_code_files, scan_set_exclusion

_FILES = {
    "src/app.py": "x = 1\n",
    "Dockerfile": "FROM scratch\n",
    "web/app.min.js": "var a=1;\n",
    "web/chunk.js": "var a=1;" * 4000 + "\n",
    "assets/logo.png": "png",
    "data.bin": "bin",
    "notes.md.bak": "# notes\n",
}


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    for rel, text in _FILES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    clear_caches()
    return root


def test_scan_set_exclusion_agrees_with_the_walker(tree: Path) -> None:
    walked = set(scan_code_files(str(tree)))

    for rel in _FILES:
        path = tree / rel
        assert (scan_set_exclusion(path) == "") == (path in walked), rel


@pytest.mark.parametrize(("rel", "reason"), [
    ("assets/logo.png", "extension outside the scan set"),
    ("data.bin", "extension outside the scan set"),
    ("web/app.min.js", "minified or bundled artefact"),
    ("web/chunk.js", "minified or bundled artefact"),
])
def test_scan_set_exclusion_names_the_cause(tree: Path, rel: str, reason: str) -> None:
    assert scan_set_exclusion(tree / rel) == reason
