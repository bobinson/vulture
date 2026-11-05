"""E2E: repository-wide SOC2 findings cite the repository, not the host path it sat at.

"No monitoring detected" and "no data retention policy" are about the whole
codebase: they have no file and no line. They used to carry the absolute scan
root as their ``file_path``, so a moved checkout made them look new to anything
keyed on the path, and the validator's path classifier judged the directories
ABOVE the repository. They now carry ``"."`` -- the token the backend's path
canonicaliser already gives the scan root -- and line 0, while rows that cite a
file keep its path.
"""

import json
import shutil
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

REPO_LEVEL_IDS = frozenset({"soc2.monitoring.absent", "soc2.data_retention.missing_policy"})


def _write_service(root: Path) -> Path:
    """A web service that stores user rows with no monitoring and no retention."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "server.py").write_text(
        "from flask import Flask\n\n"
        "app = Flask(__name__)\n\n\n"
        '@app.route("/users")\n'
        "def users():\n"
        '    return "ok"\n'
    )
    (root / "db.py").write_text(
        "import sqlite3\n\n\n"
        "def add(name):\n"
        '    conn = sqlite3.connect("app.db")\n'
        '    conn.execute("INSERT INTO users VALUES (?)", (name,))\n'
    )
    return root


async def _findings(root: Path) -> list[dict]:
    """The ``result`` snapshot of one real ``POST /run`` over ``root``."""
    from soc2_agent.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/run", json={"run_id": "repo-level", "source_path": str(root), "config": {}},
        )
    assert resp.status_code == 200, resp.text
    events = [e for e in resp.text.split("\n\n") if e.startswith("event: result")]
    assert len(events) == 1, "expected exactly one result event"
    data = next(ln for ln in events[0].split("\n") if ln.startswith("data:"))
    return json.loads(data[5:])["findings"]


def _path_result(finding: dict) -> str:
    checks = (finding.get("validation") or {}).get("checks") or []
    return next((c.get("result") for c in checks if c.get("id") == "path"), "")


@pytest.fixture(autouse=True)
def _skills_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULTURE_USE_LLM", "false")
    monkeypatch.setenv("VULTURE_USE_VALIDATE_LLM", "false")


@pytest.mark.anyio
async def test_repo_level_rows_cite_the_root_token(tmp_path: Path) -> None:
    findings = await _findings(_write_service(tmp_path / "repo"))
    rows = [f for f in findings if f.get("check_id") in REPO_LEVEL_IDS]
    assert {r["check_id"] for r in rows} == REPO_LEVEL_IDS
    for row in rows:
        assert (row["file_path"], row["line_start"], row["line_end"]) == (".", 0, 0), row


@pytest.mark.anyio
async def test_rows_that_cite_a_file_keep_its_absolute_path(tmp_path: Path) -> None:
    root = _write_service(tmp_path / "repo")
    per_file = [f for f in await _findings(root) if f.get("check_id") not in REPO_LEVEL_IDS]
    assert per_file, "the service must also produce a row that cites a file"
    for row in per_file:
        assert Path(row["file_path"]).is_absolute(), row["file_path"]
        assert Path(row["file_path"]).parent == root, row["file_path"]
        assert row["line_start"] >= 1


@pytest.mark.anyio
async def test_where_the_checkout_sits_does_not_change_repo_level_rows(tmp_path: Path) -> None:
    plain = _write_service(tmp_path / "plain" / "repo")
    nested = tmp_path / "build" / "repo"
    shutil.copytree(plain, nested)

    def projection(findings: list[dict]) -> set[tuple]:
        return {
            (f["check_id"], f["file_path"], f["validation"]["status"], _path_result(f))
            for f in findings if f.get("check_id") in REPO_LEVEL_IDS
        }

    first = projection(await _findings(plain))
    assert first == projection(await _findings(nested))
    assert {p[-1] for p in first} == {"neutral"}
