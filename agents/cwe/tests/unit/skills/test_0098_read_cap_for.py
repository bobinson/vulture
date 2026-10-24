"""Unit contract: one predicate says how many bytes a reader takes of a file.

``dependency_check`` reads manifests under the larger manifest cap and every
other file under the source cap. The offline gate stages a stand-in for a file
over its cap, so it must ask the SAME predicate rather than restate the rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.dependency_check import read_cap_for
from shared.tools.file_scanner import MAX_FILE_SIZE, MAX_MANIFEST_SIZE


@pytest.mark.parametrize("name", ["package.json", "package-lock.json", "requirements.txt",
                                  "go.mod", "package.json.bak"])
def test_read_cap_for_is_the_manifest_cap_only_for_manifests(name: str) -> None:
    assert read_cap_for(Path("/x") / name) == MAX_MANIFEST_SIZE


@pytest.mark.parametrize("name", ["app.py", "blob.bin", "notes.md", "Dockerfile"])
def test_read_cap_for_any_other_file_is_the_source_cap(name: str) -> None:
    assert read_cap_for(Path("/x") / name) == MAX_FILE_SIZE
