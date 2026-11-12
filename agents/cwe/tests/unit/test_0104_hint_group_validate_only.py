"""Feature 0104 WS-A2, D-P (2): the AST heads stamp a file's group of hint-only rows without
reading the validate stage; whether a group stays one row is the stage's alone (R5).

The heads once pre-checked S2 in the skill phase (``line_signature`` per member, before the
stamp). Now no code of ``shared/validate/`` runs in the skill phase, and a file whose members
the stage would split -- a suppression marker above one member -- is still stamped by the
heads: every hint-only row carries the group's sink lines. The stage then restores the
members (``test_0104_hint_groups.py``, ``a2/waiver_member``).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import FrameType
from typing import Any

import pytest

from shared import validate
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
# The validate stage's code: no frame of a file under it may run in the skill phase.
VALIDATE = os.path.dirname(validate.__file__) + os.sep


def _rows(request: pytest.FixtureRequest) -> list[_ast_v1.Finding]:
    """The CWE-22 rows the AST skills emit on one file holding ``SOURCE``."""
    root = neutral_dir(request)
    (root / "ledger.py").write_text(SOURCE, encoding="utf-8")
    return _ast_v1.rows_for(_ast_v1.migrated_rows(root), CHECK)


def test_the_skill_phase_never_reads_the_validate_stage(request: pytest.FixtureRequest) -> None:
    ran: set[str] = set()

    def profile(frame: FrameType, event: str, _arg: Any) -> None:
        code = frame.f_code
        if event == "call" and code.co_filename.startswith(VALIDATE):
            ran.add(f"{Path(code.co_filename).name}:{code.co_name}")

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        rows = _rows(request)
    finally:
        sys.setprofile(previous)
    assert (len(rows), sorted(ran)) == (len(SINKS), [])


def test_the_heads_stamp_a_group_the_stage_would_split(request: pytest.FixtureRequest) -> None:
    rows = _rows(request)
    stamps = {row["line_start"]: row.get("_hint_group") for row in rows}
    assert stamps == dict.fromkeys(SINKS, SINKS)
