"""Feature 0074 review item 9 — ONE lenient line parser.

``shared.lines.parse_line`` has the generate parser's semantics (formerly
``audit_runner._coerce_line``): ``bool`` is not a line, NaN / Infinity / an
overflowing value cost the LINE (the default), never the row or the batch.
``anchor.as_int`` / ``int_field``, ``llm_judge._safe_int`` and
``lineage_checks._as_int`` delegate to it, so the four readers can no longer
disagree; before the fix the inputs ``[nan, True, -3, Infinity]`` produced four
different answers, including two exceptions.

Under the ``VULTURE_LLM_COERCE_LINES=false`` rollback, raw line values reach
the default-on re-anchor and the range stamp; they must not raise there.

All fixtures are synthetic.
"""

from __future__ import annotations

import math
from types import SimpleNamespace

import pytest

from shared import anchor, audit_runner, lineage_checks
from shared.lines import parse_line
from shared.validate import llm_judge

_CASES = [
    (math.nan, 0), (math.inf, 0), (-math.inf, 0), (True, 0), (False, 0),
    (-3, -3), (0, 0), (12, 12), (3.9, 3), ("55", 55), (" 7 ", 7), ("x", 0),
    ("", 0), (None, 0), ("NaN", 0), ("Infinity", 0), ([1], 0), (10 ** 30, 10 ** 30),
]


@pytest.mark.parametrize(("value", "expected"), _CASES, ids=repr)
def test_one_parser(value, expected) -> None:
    assert parse_line(value) == expected


@pytest.mark.parametrize(("value", "expected"), _CASES, ids=repr)
def test_every_reader_agrees(value, expected) -> None:
    assert (anchor.as_int(value), llm_judge._safe_int(value),
            audit_runner._coerce_line(value), lineage_checks._as_int(value)) == (
        expected, expected, expected, max(0, expected))


def test_default_is_returned_for_junk() -> None:
    assert (parse_line(math.nan, 9), llm_judge._safe_int("junk", 4)) == (9, 4)


def test_reanchor_with_raw_lines_does_not_raise(monkeypatch) -> None:
    """COERCE_LINES=false: ``line_end`` None, re-anchored by the default-on actuator."""
    monkeypatch.setenv("VULTURE_LLM_COERCE_LINES", "false")
    finding = {"line_start": "12", "line_end": None}
    outcome = SimpleNamespace(status="reanchored", new_line=20, delta=8)
    audit_runner._apply_reanchor(finding, outcome)
    assert (finding["line_start"], finding["line_end"]) == (20, 20)


@pytest.mark.parametrize("raw", [math.inf, math.nan, "Infinity", True])
def test_claimed_line_range_never_raises(raw, tmp_path) -> None:
    path = tmp_path / "m.py"
    path.write_text("a = 1\n")
    assert anchor.claimed_line_range({"line_start": raw}, path) == anchor.RANGE_NO_LINE


@pytest.mark.parametrize(("line", "count", "expected"), [
    (0, 5, anchor.RANGE_NO_LINE), (-4, 5, anchor.RANGE_NO_LINE), (-1, 0, anchor.RANGE_NO_LINE),
    (1, 5, anchor.RANGE_IN_FILE), (5, 5, anchor.RANGE_IN_FILE),
    (6, 5, anchor.RANGE_PAST_EOF), (1, 0, anchor.RANGE_PAST_EOF),
])
def test_line_range(line, count, expected) -> None:
    """Review item 46: every branch of the ONE range rule, ``no_line`` included."""
    assert anchor.line_range(line, count) == expected


def test_remaining_readers_never_raise(tmp_path) -> None:
    """The other bare ``int()`` sites delegate too: L1, the rollup and the
    snippet span accept junk lines as "no line"."""
    from shared.tools.snippet import extract_snippet
    from shared.validate import rollup
    from shared.validate.context_heuristics import run_l1

    assert rollup._sorted_member_lines([{"line_start": math.nan}, {"line_start": "4"}]) == [4]
    assert extract_snippet(["a", "b", "c"], 2, context=0, line_end=math.inf).strip()
    (tmp_path / "m.py").write_text("a = 1\n")
    assert len(run_l1([{"file_path": "m.py", "line_start": math.inf}],
                      source_root=str(tmp_path))) == 1
