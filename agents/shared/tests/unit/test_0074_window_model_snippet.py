"""Feature 0074 AC38 — a model-authored window must show the cited line.

Under ``VULTURE_LLM_TRUST_MODEL_SNIPPET=true`` (a rollback setting) an LLM row
keeps the snippet the model wrote. When that snippet has no coordinate the file
confirms (unnumbered, or numbered and contradicted by the file), nothing proved
it shows the cited line, yet it was recorded ``present``. It now stands only
when one of its rows IS the cited line; otherwise the row is re-windowed at the
cited line. A skill-authored carried window keeps the additive rule
(``test_0074_window_stale_snippet``).

Also: a past-end-of-file row drops its window start with its window.

All fixtures are synthetic.
"""

from __future__ import annotations

import pytest

from shared.tools.window import CODE_SNIPPET_START
from tests.support.past_eof import (
    clear_all_caches,
    five_line_file,
    llm_row,
    numbered_file,
    window_reason,
    window_stage,
)

_CITED = 30
_CITED_TEXT = "const v30 = compute(30);"


@pytest.mark.parametrize("snippet", ["eval(userInput)", "12: eval(userInput)"],
                         ids=["unnumbered", "numbered_contradicted"])
def test_model_snippet_without_the_cited_line_is_rewindowed(snippet, tmp_path) -> None:
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    row = window_stage([llm_row(path, _CITED, code_snippet=snippet)],
                       tmp_path)[0]
    assert _CITED_TEXT in row["code_snippet"] and "eval(userInput)" not in row["code_snippet"]
    assert window_reason(row) == "present"


@pytest.mark.parametrize("snippet", [_CITED_TEXT, f"  {_CITED_TEXT}  ", "compute(30);"],
                         ids=["exact", "padded", "fragment"])
def test_model_snippet_showing_the_cited_line_stands(snippet, tmp_path) -> None:
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    row = window_stage([llm_row(path, _CITED, code_snippet=snippet)],
                       tmp_path)[0]
    assert (row["code_snippet"], window_reason(row)) == (snippet, "present")


def test_masked_model_snippet_of_the_cited_line_stands(tmp_path) -> None:
    """A placeholder stands for the masked value: the row still shows the line."""
    clear_all_caches()
    path = numbered_file(tmp_path, 60)
    snippet = "const v30 = ***REDACTED***;"
    row = window_stage([llm_row(path, _CITED, code_snippet=snippet)],
                       tmp_path)[0]
    assert row["code_snippet"] == snippet


def test_past_eof_row_drops_its_window_start(tmp_path) -> None:
    clear_all_caches()
    path = five_line_file(tmp_path)
    row = llm_row(path, 40, code_snippet="48: stale")
    row[CODE_SNIPPET_START] = 48
    window_stage([row], tmp_path)
    assert window_reason(row) == "out_of_range"
    assert "code_snippet" not in row and CODE_SNIPPET_START not in row
