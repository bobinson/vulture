"""E2E contract: no live ``finding`` event carries a neighbour's secret (feature 0098).

A finding's code window spans several lines, so it can include the line a
DIFFERENT finding reports as a hard-coded secret. The ``result`` snapshot masks
that line in every window once the whole batch is known. The per-finding
``finding`` events are emitted BEFORE that, while the skills are still running,
and the backend persists them when no snapshot arrives. So a live event must
never carry another finding's secret either, and the snapshot must still carry
the full window.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from shared.audit_runner import run_combined_audit
from shared.tools.snippet import extract_snippet

SECRET = "Zx9fakeS3cret" + "Value2024!"
SOURCE = f'import os\nDB_PASSWORD = "{SECRET}"\nos.system(input())\n'


def _row(path: Path, line: int, category: str, check_id: str, severity: str) -> dict:
    lines = path.read_text().splitlines()
    return {"severity": severity, "check_id": check_id, "category": category,
            "title": check_id, "description": "d", "file_path": str(path),
            "line_start": line, "line_end": line, "code_snippet": extract_snippet(lines, line)}


def _events(root: Path, path: Path) -> tuple[list[dict], list[dict]]:
    skills = {
        "a": lambda _r: {"findings": [_row(path, 2, "CWE-798", "t.cred", "high")]},
        "b": lambda _r: {"findings": [_row(path, 3, "CWE-78", "t.cmd", "critical")]},
    }
    live: list[dict] = []
    final: list[dict] = []
    for event in run_combined_audit("r1", str(root), list(skills), skills,
                                    use_llm=False, validate_use_llm=False):
        for line in event.splitlines():
            if not line.startswith("data:"):
                continue
            payload = json.loads(line[5:])
            if isinstance(payload.get("findings"), list):
                final = payload["findings"]
            elif payload.get("check_id") or (payload.get("finding") or {}).get("check_id"):
                live.append(payload)
    return live, final


def test_no_live_finding_event_carries_a_neighbours_secret(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(SOURCE)

    live, final = _events(tmp_path, path)

    assert len(live) == 2
    assert not [e for e in live if SECRET in json.dumps(e)]
    assert final and SECRET not in json.dumps(final)
    (cmd,) = [f for f in final if f.get("check_id") == "t.cmd"]
    rows = cmd["code_snippet"].split("\n")
    assert [r.split(":", 1)[0] for r in rows[:3]] == ["1", "2", "3"]
