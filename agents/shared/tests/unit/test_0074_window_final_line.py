"""Feature 0074 AC38 edge case — a carried window must contain the FINAL line.

A row that arrives carrying a ``code_snippet`` (a skill row, an inherited row,
or an LLM row under ``VULTURE_LLM_TRUST_MODEL_SNIPPET=true``) used to keep it
and be recorded ``present`` whenever its line was inside the file. Under the
0074 O6 default re-anchoring an LLM row claimed at line 30 is moved to line 45
by ``_verify_and_strip`` — and then kept its line-30 window, recorded
``present``: a judge shown other code as though it were the accused line.

The rule: a carried window is kept only if it demonstrably contains the row's
final cited line (its recorded coordinates — the 0089 ``_code_snippet_start``
stamp, or the window's own confirmed ``"NN: "`` numbering — when present). A
re-anchored row and a carried window whose coordinates exclude the line get a
fresh window at the final line through the cached reader; a window that does
not contain the cited line is never ``present``.

All fixtures are synthetic.
"""

from __future__ import annotations

import json

import pytest

from shared.tools.snippet import extract_snippet
from shared.tools.window import CODE_SNIPPET_START
from tests.support.past_eof import (
    choke_point,
    clear_all_caches,
    llm_row,
    numbered_file,
    set_quote_mode,
    window_reason,
    window_stage,
)

_NARROW = "CWE-95"   # narrow class: a carried window is normally kept
_FINAL = 45
_CLAIMED = 30
_QUOTE_AT_45 = "const v45 = compute(45);"


def _lines(count: int = 60) -> list[str]:
    return [f"const v{i} = compute({i});" for i in range(1, count + 1)]


def _fresh_window_at(line: int) -> str:
    """The window the stage itself would extract for a narrow row at ``line``."""
    return extract_snippet(_lines(), line, context=2, max_chars=200, line_end=line)


def _row(path, **over) -> dict:
    return llm_row(path, _FINAL, category=_NARROW, **over)


def test_reanchored_row_gets_a_fresh_window_at_the_final_line(tmp_path) -> None:
    """Claimed at 30, re-anchored to 45, carrying an (unnumbered) line-30
    snippet: re-windowed at 45, never the stale snippet recorded present."""
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    row = _row(path, code_snippet="const v30 = compute(30);", _claimed_line=_CLAIMED)
    window_stage([row], tmp_path)
    assert row["code_snippet"] == _fresh_window_at(_FINAL)
    assert (window_reason(row), row.get(CODE_SNIPPET_START)) == ("present", _FINAL - 2)


def test_numbered_carried_window_excluding_the_line_is_rewindowed(tmp_path) -> None:
    """A carried window whose own confirmed numbering covers 28-32 cannot
    stand for a row cited at 45, re-anchored or not."""
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    row = _row(path, code_snippet=_fresh_window_at(_CLAIMED))
    window_stage([row], tmp_path)
    assert row["code_snippet"] == _fresh_window_at(_FINAL)
    assert (window_reason(row), row.get(CODE_SNIPPET_START)) == ("present", _FINAL - 2)


def test_recorded_window_start_excluding_the_line_is_rewindowed(tmp_path) -> None:
    """The 0089 ``_code_snippet_start`` stamp is the window's recorded
    coordinate: a one-row window stamped at 30 does not contain line 45."""
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    row = _row(path, code_snippet="const v30 = compute(30);", **{CODE_SNIPPET_START: _CLAIMED})
    window_stage([row], tmp_path)
    assert row["code_snippet"] == _fresh_window_at(_FINAL)
    assert row.get(CODE_SNIPPET_START) == _FINAL - 2


def test_carried_window_containing_the_line_is_kept(tmp_path) -> None:
    """Control: a carried window that covers the final line is kept verbatim
    (a one-row window differs from what the stage would extract, so a keep is
    distinguishable from a re-window)."""
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    carried = f"{_FINAL}: {_QUOTE_AT_45}"
    row = _row(path, code_snippet=carried)
    window_stage([row], tmp_path)
    assert (row["code_snippet"], window_reason(row)) == (carried, "present")
    assert row.get(CODE_SNIPPET_START) == _FINAL


def test_stale_window_on_an_unreadable_file_is_never_present(tmp_path) -> None:
    """No fresh window can be read, and the carried one excludes the line:
    the row is left windowless, recorded ``unreadable`` — never ``present``."""
    clear_all_caches()
    row = llm_row(tmp_path / "gone.ts", _FINAL, category=_NARROW,
                  code_snippet="const v30 = compute(30);", _claimed_line=_CLAIMED)
    window_stage([row], tmp_path)
    assert (window_reason(row), row.get("code_snippet") or "") == ("unreadable", "")


@pytest.fixture
def trusting_reanchor(monkeypatch):
    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_SNIPPET", "true")
    set_quote_mode(monkeypatch, "enforce")


def test_trusted_model_snippet_end_to_end(trusting_reanchor, tmp_path) -> None:
    """The reproduced failure, through the real parser, the 0076 choke point and
    the window stage: the model cites line 30 with its own line-30 snippet and
    quotes line 45; the row is re-anchored to 45 and windowed there."""
    from shared.audit_runner import _parse_llm_findings

    path = numbered_file(tmp_path, 60)
    text = json.dumps([{
        "title": "Dynamic evaluation", "severity": "high", "category": _NARROW,
        "file_path": str(path), "line_start": _CLAIMED, "line_end": _CLAIMED,
        "description": "User input reaches eval.",
        "code_snippet": "const v30 = compute(30);",
        "evidence_quote": _QUOTE_AT_45,
    }])
    rows = _parse_llm_findings(text).rows
    assert rows[0]["code_snippet"] == "const v30 = compute(30);"  # trusted
    row = window_stage(choke_point(rows, tmp_path), tmp_path)[0]
    assert row["line_start"] == _FINAL
    assert row["code_snippet"] == _fresh_window_at(_FINAL)
    assert window_reason(row) == "present"
