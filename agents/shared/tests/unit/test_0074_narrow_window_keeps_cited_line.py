"""Feature 0074 AC38: a window that excludes the cited line is never ``present``.

A narrow-category row gets the legacy 200-character window starting two lines
above the cited one. With long preceding lines the whole-snippet cut used to
end before the cited line was reached, and the row was still recorded
``present``. The window must keep its start (feature 0089 pins it) and its
absolute numbering, and must contain the cited line.
"""
from __future__ import annotations

from pathlib import Path

from shared.tools.snippet import extract_snippet, window_first_line
from shared.tools.window import confirmed_window_start, ensure_code_window

LONG = ["x = '" + "a" * 112 + f"'  # {n}" for n in range(1, 11)]


def _rows(snippet: str) -> list[str]:
    return snippet.splitlines()


def test_cited_line_survives_the_character_cut() -> None:
    snippet = extract_snippet(LONG, 5, context=2, max_chars=200)
    assert any(r.startswith("5: ") for r in _rows(snippet)), snippet
    assert len(snippet) <= 200


def test_start_and_numbering_are_unchanged() -> None:
    snippet = extract_snippet(LONG, 5, context=2, max_chars=200)
    first = int(_rows(snippet)[0].split(":", 1)[0])
    assert first == window_first_line(5, 2)
    assert confirmed_window_start(snippet, LONG) == first


def test_every_row_is_a_prefix_of_its_file_line() -> None:
    snippet = extract_snippet(LONG, 5, context=2, max_chars=200)
    for row in _rows(snippet):
        num, text = row.split(": ", 1)
        assert LONG[int(num) - 1].startswith(text), row


def test_short_lines_are_byte_identical_to_the_legacy_cut() -> None:
    short = [f"v{n} = {n}" for n in range(1, 11)]
    legacy = "\n".join(f"{i + 1}: {short[i]}" for i in range(2, 7))[:200]
    assert extract_snippet(short, 5, context=2, max_chars=200) == legacy


def test_window_stage_records_present_only_with_the_cited_line(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("\n".join(LONG) + "\n", encoding="utf-8")
    row = {"file_path": "m.py", "line_start": 5, "category": "CWE-95", "provenance": "llm"}
    ensure_code_window([row], str(tmp_path), record_reasons=True)
    assert any(r.startswith("5: ") for r in _rows(row["code_snippet"])), row["code_snippet"]


def test_cited_line_past_the_lines_keeps_the_legacy_cut() -> None:
    one = ['api_key = "' + "k" * 300 + '"']
    assert extract_snippet(one, 5, context=2, max_chars=200) == ""
    legacy = "\n".join(f"{i + 1}: {LONG[i]}" for i in range(7, 10))[:200]
    assert extract_snippet(LONG, 12, context=4, max_chars=200) == legacy
