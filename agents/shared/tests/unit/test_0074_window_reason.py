"""Feature 0074 P3 (T3.4, T3.5) — the window reason for a citation past end of file.

§5.4 gap 3. ``ensure_code_window`` recorded a citation past end of file as
``unreadable`` even though it had just read the file, and a citation within
context distance of end of file got a window that does not contain the cited
line, recorded as ``present``. Both mislead the L5 judge and every report that
reads the window reason.

AC38: a window that excludes the cited line is never ``present``; an
out-of-range citation records window reason ``out_of_range``, never
``unreadable``. The vocabulary gains ``out_of_range`` (both O3 options agree).

Fixtures follow the plan's §8 "window reason" row: a 42-line file cited at
line 60 (narrow window), and at line 50 with the wide context of 10.
"""

from __future__ import annotations

import pytest

from tests.support.past_eof import (
    QUOTE_AT_3,
    choke_point,
    llm_row,
    numbered_file,
    set_quote_mode,
    window_reason,
    window_stage,
)

_LINES = 42
_NARROW = "CWE-95"    # context 2, the legacy tight window
_WIDE = "CWE-78"      # a data-flow class: context 10, line budget


def _window_check(row: dict) -> dict:
    """The recorded `window` check dict of one row."""
    checks = row.get("validation", {}).get("checks", [])
    return next(filter(lambda check: check.get("id") == "window", checks), {})


def _stamped_then_windowed(monkeypatch, tmp_path, line: int, category: str) -> dict:
    """An LLM row through the anchor choke point, then the window stage."""
    set_quote_mode(monkeypatch, "enforce")
    path = numbered_file(tmp_path, _LINES)
    rows = choke_point([llm_row(path, line, category=category)], tmp_path)
    return window_stage(rows, tmp_path)[0]


def test_out_of_range_is_in_the_closed_vocabulary():
    """AC38 / T3.5 — ``record_window_reason`` drops any reason outside the
    closed set, so the reason must be a member or it can never be recorded."""
    from shared.tools.window import WINDOW_REASONS

    assert "out_of_range" in WINDOW_REASONS


def test_out_of_range_reason_has_tooltip_text_and_zero_weight():
    """AC38 — the reason is bookkeeping like every other window reason: weight
    0.0, and a human-readable explanation the UI tooltip can show."""
    from shared.tools.window import record_window_reason

    holder: dict = {}
    record_window_reason(holder, "out_of_range")
    check = _window_check(holder)
    assert check.get("result") == "out_of_range", "the reason was refused"
    assert check["weight"] == 0.0 and check["reason"]


@pytest.mark.parametrize("category", [_NARROW, _WIDE], ids=["narrow", "wide"])
def test_citation_past_eof_records_out_of_range(monkeypatch, tmp_path, category):
    """AC38 — a 42-line file cited at line 60: the file was read, so the
    reason is ``out_of_range``, never ``unreadable``."""
    row = _stamped_then_windowed(monkeypatch, tmp_path, 60, category)
    assert window_reason(row) == "out_of_range"


def test_unstamped_row_past_eof_is_never_unreadable(tmp_path):
    """AC38 — the rule is about the citation, not the tier: a row with no
    anchor stamp (a skill row, or an LLM row under ``VULTURE_LLM_QUOTE_VERIFY=off``)
    cited past end of a readable file is still ``out_of_range``."""
    path = numbered_file(tmp_path, _LINES)
    row = window_stage([llm_row(path, 60, provenance="skill")], tmp_path)[0]
    assert window_reason(row) == "out_of_range"


def test_wide_window_that_excludes_the_cited_line_is_never_present(monkeypatch, tmp_path):
    """AC38 — cited at line 50 with context 10: the window holds lines 40-42 and
    does NOT contain line 50, so it must not be recorded ``present``."""
    row = _stamped_then_windowed(monkeypatch, tmp_path, 50, _WIDE)
    assert window_reason(row) != "present"
    assert window_reason(row) == "out_of_range"


def test_narrow_window_one_past_eof_is_never_present(monkeypatch, tmp_path):
    """AC38 — cited at line 43 with context 2: the window would hold lines
    41-42 only, so it is not ``present``."""
    row = _stamped_then_windowed(monkeypatch, tmp_path, _LINES + 1, _NARROW)
    assert window_reason(row) == "out_of_range"


def test_out_of_range_check_carries_zero_weight_on_the_row(monkeypatch, tmp_path):
    """AC38 — recording the reason never nudges a verdict."""
    row = _stamped_then_windowed(monkeypatch, tmp_path, 60, _NARROW)
    check = _window_check(row)
    assert check.get("result") == "out_of_range"
    assert check["weight"] == 0.0


@pytest.mark.parametrize("category", [_NARROW, _WIDE], ids=["narrow", "wide"])
def test_the_last_line_is_still_present(monkeypatch, tmp_path, category):
    """AC38 negative — the label is not over-applied: line 42 of a 42-line file
    is a real line and its window contains it. (Regression pin.)"""
    row = _stamped_then_windowed(monkeypatch, tmp_path, _LINES, category)
    assert window_reason(row) == "present"


def test_a_missing_file_is_still_unreadable(monkeypatch, tmp_path):
    """AC38 negative — ``unreadable`` keeps its meaning for a path that does
    not resolve; ``out_of_range`` is only for a file that was read.
    (Regression pin.)"""
    set_quote_mode(monkeypatch, "enforce")
    rows = choke_point([llm_row(tmp_path / "gone.ts", 60, QUOTE_AT_3)], tmp_path)
    assert window_reason(window_stage(rows, tmp_path)[0]) == "unreadable"


def test_fixture_categories_really_differ_in_context():
    """Non-vacuity guard for the narrow/wide parametrisation: the two classes
    must really get context 2 and context 10. (Fixture guard; holds today.)"""
    from shared.audit_runner import _snippet_params_for

    assert _snippet_params_for(_NARROW)[0] == 2
    assert _snippet_params_for(_WIDE)[0] == 10
