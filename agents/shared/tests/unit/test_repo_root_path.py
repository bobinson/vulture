"""Unit: the scan root's one spelling, ``"."``, and what each stage makes of it.

``REPO_ROOT_PATH`` is the ``file_path`` of a finding about the repository as a
whole -- the token the backend's path canonicaliser gives the scan root. Three
agent-side stages must read it as "the repository, no file":

* the pre-egress choke point maps a row that still cites the absolute root;
* the window stage records it as having no code location, not as a file with
  no line (and not as an unreadable directory);
* the agent's dedup key spells the absolute root the same way, so a skill row
  and a model row about the repository collapse.
"""

from __future__ import annotations

import pytest

from shared import audit_runner
from shared.models.finding import REPO_ROOT_PATH
from shared.tools.window import WINDOW_NO_CODE_LOCATION, WINDOW_NO_LINE, ensure_code_window


def test_the_token_is_what_the_backend_canonicalises_the_root_to() -> None:
    assert REPO_ROOT_PATH == "."


@pytest.mark.parametrize("cited", [
    "/scan/repo", "/scan/repo/", "/scan/repo/.", "/scan//repo", "//scan/repo",
])
def test_the_choke_point_maps_the_root_to_the_token(cited: str) -> None:
    row = {"title": "t", "file_path": cited, "line_start": 0}
    audit_runner._finalize_finding_inplace(row, "run", 0, source_path="/scan/repo")
    assert row["file_path"] == REPO_ROOT_PATH


@pytest.mark.parametrize("cited", [
    "/scan/repo/app.py", "/scan/repo-old", "/scan", "app.py", "", ".",
])
def test_the_choke_point_leaves_every_other_path_alone(cited: str) -> None:
    row = {"title": "t", "file_path": cited, "line_start": 1}
    audit_runner._finalize_finding_inplace(row, "run", 0, source_path="/scan/repo")
    assert row["file_path"] == cited


def test_the_choke_point_without_a_root_changes_nothing() -> None:
    row = {"title": "t", "file_path": "/scan/repo", "line_start": 0}
    audit_runner._finalize_finding_inplace(row, "run", 0)
    assert row["file_path"] == "/scan/repo"


def test_the_id_is_assigned_after_the_mapping() -> None:
    """The id hashes the path, so it must hash the one that egresses: the
    same row from two mounts gets one id."""
    first = {"title": "t", "file_path": "/a/repo"}
    second = {"title": "t", "file_path": "/b/elsewhere/repo"}
    audit_runner._finalize_finding_inplace(first, "run", 3, source_path="/a/repo")
    audit_runner._finalize_finding_inplace(second, "run", 3, source_path="/b/elsewhere/repo")
    assert first["id"] == second["id"]


def _window_reason(row: dict, tmp_path) -> str:
    ensure_code_window([row], str(tmp_path), record_reasons=True)
    checks = row["validation"]["checks"]
    return next(c["result"] for c in checks if c["id"] == "window")


def test_the_root_token_has_no_code_location(tmp_path) -> None:
    row = {"title": "t", "category": "PO", "file_path": REPO_ROOT_PATH,
           "line_start": 0, "line_end": 0}
    assert _window_reason(row, tmp_path) == WINDOW_NO_CODE_LOCATION


def test_a_file_without_a_line_is_still_no_line(tmp_path) -> None:
    """The negative control: only the root token stands for "no file"."""
    (tmp_path / "a.py").write_text("x = 1\n")
    row = {"title": "t", "category": "PO", "file_path": "a.py", "line_start": 0, "line_end": 0}
    assert _window_reason(row, tmp_path) == WINDOW_NO_LINE


def test_the_choke_point_maps_the_root_through_a_symlink(tmp_path) -> None:
    """macOS scans ``/var/...`` and resolves it to ``/private/var/...``; a
    symlinked mount does the same. Either spelling of the root is the root."""
    real = tmp_path / "real-repo"
    real.mkdir()
    link = tmp_path / "mounted"
    link.symlink_to(real, target_is_directory=True)
    for root, cited in ((str(link), str(real)), (str(real), str(link))):
        row = {"title": "t", "file_path": cited, "line_start": 0}
        audit_runner._finalize_finding_inplace(row, "run", 0, source_path=root)
        assert row["file_path"] == REPO_ROOT_PATH, (root, cited)


def test_a_file_under_the_root_is_not_resolved_as_the_root(tmp_path) -> None:
    real = tmp_path / "repo"
    real.mkdir()
    (real / "a.py").write_text("x = 1\n")
    row = {"title": "t", "file_path": str(real / "a.py"), "line_start": 1}
    audit_runner._finalize_finding_inplace(row, "run", 0, source_path=str(real))
    assert row["file_path"] == str(real / "a.py")


@pytest.mark.parametrize("cited", ["/scan/repo", "/scan/repo/", ".", "./", "//scan/repo", ""])
def test_the_dedup_key_spells_no_specific_file_as_the_token(cited: str) -> None:
    """The root, its token and an empty path all mean "no specific file": a
    model row that names no file collapses into the repository-wide skill row."""
    assert audit_runner._normalize_dedup_path(cited, "/scan/repo") == REPO_ROOT_PATH


def test_the_dedup_key_still_strips_the_root_from_a_file() -> None:
    assert audit_runner._normalize_dedup_path("/scan/repo/src/a.py", "/scan/repo") == "src/a.py"
    assert audit_runner._normalize_dedup_path("//scan/repo/src/a.py", "/scan/repo") == "src/a.py"
    assert audit_runner._normalize_dedup_path("./src/a.py", "/scan/repo") == "src/a.py"


def test_the_dedup_key_without_a_root_is_unchanged() -> None:
    """Direct callers with no root keep the historical key."""
    assert audit_runner._normalize_dedup_path("", "") == ""
    assert audit_runner._normalize_dedup_path("/scan/repo/a.py", "") == "/scan/repo/a.py"
