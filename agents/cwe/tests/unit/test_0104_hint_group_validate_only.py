"""Feature 0104 WS-A2, D-P (2): the AST heads stamp a file's group of hint-only rows without
reading the validate stage; whether a group stays one row is the stage's alone (R5).

The heads once pre-checked S2 in the skill phase (``line_signature`` per member, before the
stamp). Now the skill phase never calls ``context_heuristics.line_signature``, and a file
whose members the stage would split -- a suppression marker above one member -- is still
stamped by the heads: every hint-only row carries the group's sink lines. The stage then
restores the members (``test_0104_hint_groups.py``, ``a2/waiver_member``).

RED until D-P (2) lands: the heads call ``line_signature`` while they build a file's context.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from shared.validate import context_heuristics
from tests import _ast_v1
from tests._neutral import neutral_dir

CHECK = "cwe.input_validation.path_traversal"
# Three hint-only CWE-22 rows; the stage would refuse the group (the marker above line 12).
SOURCE = '''import os


def load_entry(file_name):
    with open(file_name) as handle:
        return handle.read()


def save_entry(file_path, text):
    # nosec
    with open(file_path, "w") as handle:
        handle.write(text)


def drop_entry(file_path):
    os.remove(file_path)
'''
SINKS = (5, 11, 16)


def _rows(request: pytest.FixtureRequest) -> list[dict[str, Any]]:
    """The CWE-22 rows the AST skills emit on one file holding ``SOURCE``."""
    root = neutral_dir(request)
    (root / "ledger.py").write_text(SOURCE, encoding="utf-8")
    return [row for row in _ast_v1.migrated_rows(root) if row["check_id"] == CHECK]


def test_the_skill_phase_never_reads_the_validate_stage(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []
    original = context_heuristics.line_signature

    def recorded(finding: dict[str, Any]) -> Any:
        calls.append(Path(finding["file_path"]))
        return original(finding)

    monkeypatch.setattr(context_heuristics, "line_signature", recorded)
    rows = _rows(request)
    assert (len(rows), calls) == (len(SINKS), [])


def test_the_heads_stamp_a_group_the_stage_would_split(request: pytest.FixtureRequest) -> None:
    rows = _rows(request)
    stamps = {row["line_start"]: row.get("_hint_group") for row in rows}
    assert stamps == dict.fromkeys(SINKS, SINKS)
