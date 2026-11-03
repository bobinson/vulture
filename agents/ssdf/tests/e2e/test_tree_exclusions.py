"""E2E: SSDF evidence counts only where the audit walk looks.

The SSDF skills decide "missing threat model", "no design review", "no fuzz
tests" and the like by LOOKING for evidence, and each looked with its own
``rglob``. That walked straight into ``.venv``, ``node_modules``, gitignored
build output and ``.vultureignore``d recordings, and followed symlinks out of
the tree, so the project was credited with a vendored package's documents.
Measured: litellm's ``architecture.md`` under ``agents/.venv`` hid this
repository's real "No design review evidence found" finding.

Now every look goes through the walker's own listing, so evidence counts only
where the audit itself reads. Each scenario has a twin with the same evidence
in a tracked location, proving the evidence is still found where it belongs.
"""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# The checks whose evidence the scenario below hides in excluded locations.
EVIDENCE_CHECKS = frozenset({
    "ssdf.pw1.no_threat_model",
    "ssdf.pw2.no_design_review",
    "ssdf.pw8.no_security_tests",
    "ssdf.pw8.no_fuzz_tests",
    "ssdf.rv3.no_postmortem_template",
    "ssdf.rv3.no_rca_process",
    "ssdf.po3.no_sast_tool",
    "ssdf.po1.missing_security_policy",
})

_RCA_DOC = "# Incident postmortem\n\nRoot cause analysis with five whys and a blameless review.\n"
_ROOT_DOCKERFILE = "FROM python:3.12\nUSER root\n"
_PRIVILEGED_COMPOSE = "services:\n  app:\n    privileged: true\n"


def _evidence() -> dict[str, str]:
    """Something that satisfies each check in EVIDENCE_CHECKS, plus container
    files that would raise rows of their own if they were read."""
    return {
        "threat-model.md": "# Threat model\n\nSTRIDE.\n",
        "architecture.md": "# Architecture\n",
        "test_security_auth.py": "def test_login_rejects_bad_token():\n    pass\n",
        "fuzz_parser.py": "def fuzz_parse(data):\n    pass\n",
        "postmortem.md": _RCA_DOC,
        "Dockerfile": _ROOT_DOCKERFILE,
        "docker-compose.yml": _PRIVILEGED_COMPOSE,
    }


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


# Each excluded location, and how it is excluded.
EXCLUDED_DIRS = (
    ".venv/lib/python3.12/site-packages/somepkg",  # SKIP_DIRS
    "node_modules/somepkg",                         # SKIP_DIRS
    "generated",                                    # a .gitignore
    "recorded",                                     # the root .vultureignore
    "linked",                                       # a symlink out of the tree
)


def _hidden_evidence_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, {"app.py": "def main():\n    return 1\n"})
    for where in EXCLUDED_DIRS[:-1]:
        _write(root / where, _evidence())
    outside = tmp_path / "outside"
    _write(outside, _evidence())
    (root / "linked").symlink_to(outside, target_is_directory=True)
    # Evidence at FIXED locations, excluded by the root's ignore files.
    _write(root, {
        ".gitignore": "generated/\ndocs/\n",
        ".vultureignore": "recorded/\n.github/workflows/\nSECURITY.md\n",
        "docs/postmortem.md": _RCA_DOC,
        ".github/workflows/ci.yml": "jobs:\n  scan:\n    steps:\n      - run: semgrep --config auto\n",
        "SECURITY.md": "# Security policy\n\nReport to security@example.com.\n",
    })
    (root / "docs" / "security").mkdir()
    (root / "node_modules" / "somepkg" / "__fuzz__").mkdir()
    return root


def _tracked_evidence_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, {"app.py": "def main():\n    return 1\n"})
    _write(root, {
        "docs/threat-model.md": "# Threat model\n\nSTRIDE.\n",
        "docs/architecture.md": "# Architecture\n",
        "tests/test_security_auth.py": "def test_login_rejects_bad_token():\n    pass\n",
        "fuzz/fuzz_parser.py": "def fuzz_parse(data):\n    pass\n",
        "docs/postmortem.md": _RCA_DOC,
        ".github/workflows/ci.yml": "jobs:\n  scan:\n    steps:\n      - run: semgrep --config auto\n",
        "SECURITY.md": "# Security policy\n\nReport to security@example.com.\n",
    })
    return root


async def _findings(root: Path) -> list[dict]:
    """The ``result`` snapshot of one real ``POST /run`` over ``root``."""
    from ssdf_agent.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run", json={"run_id": "tree-exclusions", "source_path": str(root), "config": {}},
        )
    assert resp.status_code == 200, resp.text
    events = [e for e in resp.text.split("\n\n") if e.startswith("event: result")]
    assert len(events) == 1, "expected exactly one result event"
    data = next(ln for ln in events[0].split("\n") if ln.startswith("data:"))
    return json.loads(data[5:])["findings"]


def _ids(findings: list[dict]) -> set[str]:
    return {f.get("check_id", "") for f in findings}


@pytest.fixture(autouse=True)
def _skills_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_USE_VALIDATE_LLM", "false")


@pytest.mark.anyio
async def test_evidence_the_audit_never_reads_does_not_count(tmp_path: Path) -> None:
    ids = _ids(await _findings(_hidden_evidence_repo(tmp_path)))
    missing = EVIDENCE_CHECKS - ids
    assert not missing, f"evidence in excluded locations was credited: {sorted(missing)}"


@pytest.mark.anyio
async def test_the_same_evidence_in_tracked_locations_still_counts(tmp_path: Path) -> None:
    ids = _ids(await _findings(_tracked_evidence_repo(tmp_path)))
    reported = EVIDENCE_CHECKS & ids
    assert not reported, f"tracked evidence was not found: {sorted(reported)}"


@pytest.mark.anyio
async def test_no_row_cites_a_file_the_audit_never_reads(tmp_path: Path) -> None:
    """Container rows came from Dockerfiles and compose files under
    ``node_modules`` and gitignored trees; and a Dockerfile anywhere made the
    container-scanning check apply to a repository that ships no image."""
    root = _hidden_evidence_repo(tmp_path)
    findings = await _findings(root)
    cited = sorted({f["file_path"] for f in findings if f["file_path"] != "."})
    assert cited == [], f"rows cite excluded files: {cited}"
    assert "ssdf.rv1.no_container_scanning" not in _ids(findings)


@pytest.mark.anyio
async def test_container_files_in_tracked_locations_are_still_checked(tmp_path: Path) -> None:
    root = _tracked_evidence_repo(tmp_path)
    _write(root, {"deploy/Dockerfile": _ROOT_DOCKERFILE,
                  "deploy/docker-compose.yml": _PRIVILEGED_COMPOSE})
    findings = await _findings(root)
    cited = {(f.get("check_id"), f["file_path"]) for f in findings}
    assert ("ssdf.po5.root_user_container", str(root / "deploy" / "Dockerfile")) in cited
    assert ("ssdf.po5.privileged_container", str(root / "deploy" / "docker-compose.yml")) in cited
    assert ("ssdf.pw6.no_minimal_base_image", str(root / "deploy" / "Dockerfile")) in cited
    assert "ssdf.rv1.no_container_scanning" in _ids(findings)


@pytest.mark.anyio
async def test_an_empty_evidence_directory_still_counts_where_it_is_walked(tmp_path: Path) -> None:
    """``docs/security`` and a ``__fuzz__`` directory are evidence by their
    presence alone, as before -- when the walk enters them."""
    root = tmp_path / "repo"
    _write(root, {"app.py": "def main():\n    return 1\n"})
    (root / "docs" / "security").mkdir(parents=True)
    (root / "src" / "__fuzz__").mkdir(parents=True)
    ids = _ids(await _findings(root))
    assert "ssdf.pw1.no_threat_model" not in ids
    assert "ssdf.pw8.no_fuzz_tests" not in ids


@pytest.mark.anyio
async def test_a_skipped_lock_file_is_still_lock_file_evidence(tmp_path: Path) -> None:
    """A fixed-location probe asks whether the walk reaches the file, not
    whether the code scan would parse it: lock files are never parsed, and
    they are exactly what the lock-file check looks for."""
    root = tmp_path / "repo"
    _write(root, {"app.py": "x = 1\n", "package-lock.json": "{}\n"})
    assert "ssdf.pw4.no_lock_file" not in _ids(await _findings(root))


@pytest.mark.anyio
async def test_evidence_past_the_listing_cap_still_counts(tmp_path: Path, monkeypatch) -> None:
    """The shared listing stops at MAX_FILES and counts every file, images
    included; an evidence search must still see the whole walked tree, or a
    large repository is told it has no threat model it does have."""
    from shared.tools import file_scanner

    root = tmp_path / "repo"
    _write(root, {f"assets/img{i:02d}.png": "x" for i in range(30)})
    _write(root, {
        "app.py": "def main():\n    return 1\n",
        "zz/docs/threat-model.md": "# Threat model\n\nSTRIDE.\n",
        "zz/docs/architecture.md": "# Architecture\n",
    })
    monkeypatch.setattr(file_scanner, "MAX_FILES", 5)
    ids = _ids(await _findings(root))
    assert "ssdf.pw1.no_threat_model" not in ids
    assert "ssdf.pw2.no_design_review" not in ids
