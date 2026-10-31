"""Feature 0074 review items 4 and 18 — AC38 for rows that already carry a
snippet, and for an empty file.

Item 4: a past-end-of-file citation must get NO window even when the row
arrives carrying one (a skill or inherited row, or a model snippet under
``TRUST_MODEL_SNIPPET=true``). Before the fix the "already has a snippet"
short-circuit ran first: a non-wide row kept its stale snippet recorded as
``present``, and a wide row kept it recorded as ``out_of_range``.

Item 18: an empty but READABLE file was reported ``unreadable`` by the window
stage while the anchor stamp called the same citation ``past_eof``.

All fixtures are synthetic.
"""

from __future__ import annotations

import pytest

from shared.anchor import RANGE_PAST_EOF, claimed_line_range
from tests.support.past_eof import (
    clear_all_caches,
    five_line_file,
    llm_row,
    window_reason,
    window_stage,
    write_lines,
)

_STALE = "model wrote this"
_NARROW = "CWE-798"   # non-wide: a carried snippet is normally kept
_WIDE = "CWE-200"     # wide scope: re-windowed to the line budget


def _carrying_snippet(path, line, category) -> dict:
    return llm_row(path, line, category=category, provenance="skill", code_snippet=_STALE)


@pytest.mark.parametrize("category", [_NARROW, _WIDE], ids=["non_wide", "wide"])
def test_past_eof_row_loses_its_carried_snippet(category, tmp_path) -> None:
    """Item 4: out_of_range, and the stale snippet is cleared."""
    clear_all_caches()
    path = five_line_file(tmp_path)
    row = window_stage([_carrying_snippet(path, 40, category)], tmp_path)[0]
    assert (window_reason(row), row.get("code_snippet") or "") == ("out_of_range", "")


@pytest.mark.parametrize("category", [_NARROW, _WIDE], ids=["non_wide", "wide"])
def test_in_range_row_keeps_or_rewindows_as_before(category, tmp_path) -> None:
    """Control: an in-range citation still records present with a window."""
    clear_all_caches()
    path = five_line_file(tmp_path)
    row = window_stage([_carrying_snippet(path, 3, category)], tmp_path)[0]
    assert window_reason(row) == "present" and row.get("code_snippet")


def test_non_wide_in_range_keeps_the_carried_snippet(tmp_path) -> None:
    """Control: the additive rule is unchanged for a non-wide in-range row."""
    clear_all_caches()
    path = five_line_file(tmp_path)
    row = window_stage([_carrying_snippet(path, 3, _NARROW)], tmp_path)[0]
    assert row["code_snippet"] == _STALE


def test_lineless_row_with_snippet_is_unchanged(tmp_path) -> None:
    """Control: a row with no cited line has nothing to be past; its carried
    window stands, recorded present."""
    clear_all_caches()
    path = five_line_file(tmp_path)
    row = window_stage([_carrying_snippet(path, None, _NARROW)], tmp_path)[0]
    assert (window_reason(row), row["code_snippet"]) == ("present", _STALE)


@pytest.mark.parametrize("snippet", [None, _STALE], ids=["bare", "carrying"])
def test_empty_readable_file_is_out_of_range(snippet, tmp_path) -> None:
    """Item 18: the window stage and the anchor stamp agree on an empty file."""
    clear_all_caches()
    path = write_lines(tmp_path, "empty.ts", [])
    path.write_text("", encoding="utf-8")
    row = llm_row(path, 5, category=_NARROW, provenance="skill")
    row.update({"code_snippet": snippet} if snippet else {})
    window_stage([row], tmp_path)
    assert claimed_line_range(row, path) == RANGE_PAST_EOF
    assert (window_reason(row), row.get("code_snippet") or "") == ("out_of_range", "")
