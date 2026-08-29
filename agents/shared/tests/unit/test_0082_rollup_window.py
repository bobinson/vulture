"""Feature 0082 C9 — a rollup parent gets a REASON, never a window.

A parent's `line_start` is `min(member line_starts)` (validate/rollup.py:130),
so handing it one member's window would present 1 of up to 77 sites as evidence
for all of them. That is the same misrepresentation E4 forbids in the verdict
field, moved into the evidence field. v1's "rollup parity" therefore ships as a
LABEL, not a window.

Parents are built during validate (audit_runner.py:2550) and appended at :2596,
which is AFTER `_attach_code_snippet` runs at :2487 — so they never passed
through the window path at all, and carried neither a window nor an explanation.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.tools.window import WINDOW_ROLLUP_PARENT, window_reason_of
from shared.validate.rollup import _build_rollup_parent


def _members():
    return [
        {"title": "SQL injection", "file_path": "routes/address.ts", "line_start": 11,
         "line_end": 11, "severity": "high", "code_snippet": "11: db.query(raw)"},
        {"title": "SQL injection", "file_path": "routes/address.ts", "line_start": 47,
         "line_end": 47, "severity": "high", "code_snippet": "47: db.query(other)"},
        {"title": "SQL injection", "file_path": "routes/address.ts", "line_start": 92,
         "line_end": 92, "severity": "critical", "code_snippet": "92: db.query(third)"},
    ]


def test_non_vacuity_members_span_several_lines_with_windows():
    ms = _members()
    assert len({m["line_start"] for m in ms}) >= 2, "fixture must span >1 line"
    assert all(m["code_snippet"] for m in ms), "members must carry windows"


def test_rollup_parent_carries_no_window():
    parent = _build_rollup_parent("audit-1", "CWE-89", "routes/address.ts", _members(), 3)
    assert not parent.get("code_snippet"), (
        "a parent must not present one member's window as evidence for all members"
    )


def test_rollup_parent_records_why_it_has_no_window():
    parent = _build_rollup_parent("audit-1", "CWE-89", "routes/address.ts", _members(), 3)
    assert window_reason_of(parent) == WINDOW_ROLLUP_PARENT


def test_members_keep_their_own_windows():
    """The parent is labelled; the members are untouched."""
    ms = _members()
    _build_rollup_parent("audit-1", "CWE-89", "routes/address.ts", ms, 3)
    for m in ms:
        assert m["code_snippet"], "building a parent must not strip a member's window"


def test_parent_and_min_line_child_remain_distinct_rows():
    """C1: the parent's line_start EQUALS its min-line member's, so
    (path, line, category) is not an identity. Anything keyed on that tuple
    silently collapses the two. Pinned here so a future consumer cannot
    reintroduce the assumption."""
    ms = _members()
    parent = _build_rollup_parent("audit-1", "CWE-89", "routes/address.ts", ms, 3)
    min_child = min(ms, key=lambda m: m["line_start"])
    assert parent["line_start"] == min_child["line_start"]
    assert parent["file_path"] == min_child["file_path"]
    assert parent["id"], "the parent must carry its own id — that is the real identity"
