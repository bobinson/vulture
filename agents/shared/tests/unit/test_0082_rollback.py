"""Feature 0082 T-ROLLBACK-PY — VULTURE_FINDING_WINDOW_PARITY=false must
restore the pre-0082 state exactly: no row carries a window reason.

A switch that does not actually switch anything off is worse than no switch,
because the rollback plan documents it as the way out.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.tools.window import window_reason_of
from shared.validate.rollup import _build_rollup_parent


def _members():
    return [
        {"title": "SQLi", "file_path": "a.ts", "line_start": 11, "line_end": 11,
         "severity": "high", "code_snippet": "11: q(raw)"},
        {"title": "SQLi", "file_path": "a.ts", "line_start": 47, "line_end": 47,
         "severity": "high", "code_snippet": "47: q(x)"},
    ]


def test_non_vacuity_parity_on_does_stamp_a_reason(monkeypatch):
    monkeypatch.setenv("VULTURE_FINDING_WINDOW_PARITY", "true")
    parent = _build_rollup_parent("a1", "CWE-89", "a.ts", _members(), 2)
    assert window_reason_of(parent) == "rollup_parent", (
        "with the switch ON the reason must be present, or the OFF assertion proves nothing"
    )


def test_parity_off_stamps_no_reason_on_a_rollup_parent(monkeypatch):
    monkeypatch.setenv("VULTURE_FINDING_WINDOW_PARITY", "false")
    parent = _build_rollup_parent("a1", "CWE-89", "a.ts", _members(), 2)
    assert window_reason_of(parent) == "", "rollback did not remove the window reason"


def test_parity_off_leaves_the_rest_of_the_blob_intact(monkeypatch):
    """Rollback must remove the reason and nothing else — the obligation check
    and the rollup status predate 0082."""
    monkeypatch.setenv("VULTURE_FINDING_WINDOW_PARITY", "false")
    parent = _build_rollup_parent("a1", "CWE-89", "a.ts", _members(), 2)
    blob = parent["validation"]
    assert blob["status"], "rollup status lost"
    assert blob["confidence"] == 0.40
    assert any(c.get("id") == "obligation" for c in blob["checks"]), (
        f"obligation check lost: {[c.get('id') for c in blob['checks']]}"
    )
