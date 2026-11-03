"""E2E: repository-wide SSDF findings cite the repository, not the host path it sat at.

A finding about the WHOLE repository ("no threat model", "no CODEOWNERS") has
no file and no line. It used to carry the absolute scan root as its
``file_path`` and line 1, which had three effects nobody wanted:

* moving the checkout (another mount, another CI workspace) changed the path,
  so every such row looked new to anything keyed on it;
* the code-window stage tried to read the directory and recorded the row as
  ``unreadable`` rather than as having no code location;
* the validator's path classifier read the ROOT's own directory names, so a
  checkout that happened to sit under ``tests/`` or ``build/`` demoted every
  repository-wide row.

They now carry ``"."`` -- the token the backend's path canonicaliser already
gives the scan root -- and line 0. Rows that do cite a file keep its path.
"""

import json
import shutil
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# Every SSDF check that reports on the repository as a whole.
REPO_LEVEL_IDS = frozenset({
    "ssdf.po1.missing_security_policy",
    "ssdf.po2.missing_codeowners",
    "ssdf.po3.no_dast_tool",
    "ssdf.po3.no_sast_tool",
    "ssdf.po3.no_sca_tool",
    "ssdf.po4.no_merge_policy",
    "ssdf.po4.no_quality_gates",
    "ssdf.po5.no_secrets_management",
    "ssdf.ps1.no_commit_signing",
    "ssdf.ps1.no_pre_commit_hooks",
    "ssdf.ps2.no_checksums",
    "ssdf.ps2.no_provenance",
    "ssdf.ps2.no_release_signing",
    "ssdf.ps3.no_release_archive",
    "ssdf.pw1.no_threat_model",
    "ssdf.pw2.no_design_review",
    "ssdf.pw4.no_lock_file",
    "ssdf.pw5.no_linter_config",
    "ssdf.pw7.no_pr_template",
    "ssdf.pw7.no_required_reviews",
    "ssdf.pw8.no_coverage_gate",
    "ssdf.pw8.no_fuzz_tests",
    "ssdf.pw8.no_security_tests",
    "ssdf.rv1.no_container_scanning",
    "ssdf.rv1.no_vuln_scanning",
    "ssdf.rv2.no_patching_sla",
    "ssdf.rv2.no_security_issue_template",
    "ssdf.rv3.no_postmortem_template",
    "ssdf.rv3.no_rca_process",
})


def _write_bare_repo(root: Path) -> Path:
    """A repository with none of the SSDF evidence, so every repo-level check fires.

    The Dockerfile is what makes the container-scanning check applicable, and
    gives one row that DOES cite a file.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text("def main():\n    return 1\n")
    (root / "Dockerfile").write_text("FROM python:3.12-slim\nUSER root\nCOPY . .\n")
    return root


async def _findings(root: Path) -> list[dict]:
    """The ``result`` snapshot of one real ``POST /run`` over ``root``."""
    from ssdf_agent.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run", json={"run_id": "repo-level", "source_path": str(root), "config": {}},
        )
    assert resp.status_code == 200, resp.text
    events = [e for e in resp.text.split("\n\n") if e.startswith("event: result")]
    assert len(events) == 1, "expected exactly one result event"
    data = next(ln for ln in events[0].split("\n") if ln.startswith("data:"))
    return json.loads(data[5:])["findings"]


def _repo_rows(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("check_id") in REPO_LEVEL_IDS]


def _check(finding: dict, check_id: str) -> dict:
    checks = (finding.get("validation") or {}).get("checks") or []
    return next((c for c in checks if c.get("id") == check_id), {})


@pytest.fixture(autouse=True)
def _skills_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rows under test are skill rows; an ambient LLM switch must not add any."""
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_USE_VALIDATE_LLM", "false")


@pytest.mark.anyio
async def test_every_repo_level_row_cites_the_root_token(tmp_path: Path) -> None:
    rows = _repo_rows(await _findings(_write_bare_repo(tmp_path / "repo")))
    assert {r["check_id"] for r in rows} == REPO_LEVEL_IDS, (
        "the bare repository must trip every repository-wide check, or this "
        "test would pass for the checks that happened not to fire"
    )
    wrong = [(r["check_id"], r["file_path"], r["line_start"], r["line_end"])
             for r in rows if (r["file_path"], r["line_start"], r["line_end"]) != (".", 0, 0)]
    assert not wrong, f"repository-wide rows must cite ('.', 0, 0): {wrong}"


@pytest.mark.anyio
async def test_repo_level_rows_have_no_code_location(tmp_path: Path) -> None:
    """Not ``unreadable``: there was never a file to read."""
    rows = _repo_rows(await _findings(_write_bare_repo(tmp_path / "repo")))
    reasons = {r["check_id"]: _check(r, "window").get("result") for r in rows}
    assert set(reasons.values()) == {"no_code_location"}, reasons


@pytest.mark.anyio
async def test_rows_that_cite_a_file_keep_its_absolute_path(tmp_path: Path) -> None:
    root = _write_bare_repo(tmp_path / "repo")
    findings = await _findings(root)
    rooted = [f for f in findings if f.get("check_id") == "ssdf.po5.root_user_container"]
    assert rooted, "the Dockerfile's USER root must still be reported"
    assert rooted[0]["file_path"] == str(root / "Dockerfile")
    assert rooted[0]["line_start"] == 2


@pytest.mark.anyio
async def test_where_the_checkout_sits_does_not_change_repo_level_rows(tmp_path: Path) -> None:
    """The same repository scanned from two mounts reports the same rows.

    One mount sits under a directory named ``tests``: the path classifier must
    judge the repository, not the directory the operator happened to put it in.
    """
    plain = _write_bare_repo(tmp_path / "plain" / "repo")
    nested = tmp_path / "tests" / "repo"
    shutil.copytree(plain, nested)

    def projection(rows: list[dict]) -> set[tuple]:
        return {
            (r["check_id"], r["file_path"], r["line_start"], r["line_end"],
             r["validation"]["status"], r["validation"]["confidence"],
             _check(r, "path").get("result"))
            for r in rows
        }

    first = projection(_repo_rows(await _findings(plain)))
    second = projection(_repo_rows(await _findings(nested)))
    assert first == second
    assert {p[-1] for p in second} == {"neutral"}, (
        "a repository-wide row has no path for the classifier to demote"
    )
