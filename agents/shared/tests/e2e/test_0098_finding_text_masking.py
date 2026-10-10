"""E2E contract: finding text keeps its evidence and loses its secrets (feature 0098).

Every agent's findings pass through ``run_combined_audit``, which masks
secret-SHAPED values in each finding's ``code_snippet`` and ``description``.
That masking must be precise:

  1. Prose that merely mentions "Bearer" or "basic" survives, and so does a
     pinned commit SHA in a code window: they are the finding's evidence, and a
     reviewer cannot act on ``actions/checkout@***REDACTED***``.
  2. A real token anywhere in the window is still masked.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from shared.audit_runner import run_combined_audit
from shared.tools.snippet import extract_snippet

PINNED_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"
TOKEN = "ghp_" + "a1" * 18
PROSE = ("The API accepts Bearer authentication for every call; "
         "this is a basic misconfiguration.")
WORKFLOW = (
    "jobs:\n  b:\n    steps:\n"
    f"      - uses: actions/checkout@{PINNED_SHA}\n"
    f"      - run: echo {TOKEN}\n"
)


def _result_findings(root: Path, skill) -> list[dict]:
    final: list[dict] = []
    for event in run_combined_audit("r1", str(root), ["a"], {"a": skill},
                                    use_llm=False, validate_use_llm=False):
        for line in event.splitlines():
            if line.startswith("data:"):
                payload = json.loads(line[5:])
                if isinstance(payload.get("findings"), list):
                    final = payload["findings"]
    return final


def _pin_finding(path: Path, line: int) -> dict:
    lines = path.read_text().splitlines()
    return {"severity": "medium", "check_id": "t.pin", "category": "CWE-829",
            "title": "Action reference", "description": PROSE, "file_path": str(path),
            "line_start": line, "line_end": line, "code_snippet": extract_snippet(lines, line)}


def test_finding_prose_and_pinned_digests_survive_the_audit(tmp_path: Path) -> None:
    ci = tmp_path / "ci.yml"
    ci.write_text(WORKFLOW)

    (row,) = _result_findings(tmp_path, lambda _root: {"findings": [_pin_finding(ci, 4)]})

    assert row["description"] == PROSE
    assert PINNED_SHA in row["code_snippet"]


def test_a_token_in_any_row_is_still_masked(tmp_path: Path) -> None:
    ci = tmp_path / "ci.yml"
    ci.write_text(WORKFLOW)

    rows = _result_findings(tmp_path, lambda _root: {"findings": [_pin_finding(ci, 4)]})

    assert rows
    assert TOKEN not in json.dumps(rows)
