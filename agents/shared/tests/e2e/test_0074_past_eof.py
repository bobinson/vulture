"""Feature 0074 P3 (T3.1) — a citation past end of file, end to end.

BUSINESS CONTRACT. A model sometimes cites a line the file does not have:
line 10000 of a five-line module. Before 0074 that row came back from 0076's
verifier as ``unquoted/missing`` (no quote) or ``ambiguous/not_unique`` (a quote
found far away), and the window stage recorded ``unreadable`` for a file it had
just read. Nothing anywhere said "this line does not exist".

Owner decision O3 = C: every LLM row records ``claimed_line_range`` in
``in_file`` / ``past_eof`` / ``no_line`` BESIDE its quote verdict, in the same
place 0076 persists the rest of the verifier's provenance (the ``anchor``
check's ``extras``). The nine-status vocabulary is not changed.

What this file pins, through the real stages in production order
(``_verify_and_strip`` -> ``ensure_code_window`` -> ``run_l1``):

  * AC14 — anchoring is length-preserving: ``len(out) == len(in)``.
  * AC15 — a past-end-of-file row is retained, its line never moved, and
    recorded as ``past_eof``, quoted or not. Recording it never changes the
    quote verdict: ``reanchored`` and ``absent`` survive (no shadowing).
  * AC38 — the window stage records ``out_of_range``, never ``unreadable``,
    for such a row.

All fixtures are synthetic. No model, no network.
"""

from __future__ import annotations

import pytest

from tests.support.past_eof import (
    ABSENT_QUOTE,
    QUOTE_AT_3,
    RANGE_KEY,
    anchor_extras,
    choke_point,
    five_line_file,
    l1_checks,
    llm_row,
    set_quote_mode,
    status_of,
    window_reason,
    window_stage,
)


def _pipeline(rows, root):
    """The three real stages in production order; returns (rows, checks)."""
    out = window_stage(choke_point(rows, root), root)
    return out, l1_checks(out, root)


@pytest.fixture
def module(tmp_path):
    return five_line_file(tmp_path)


@pytest.fixture
def batch(module):
    """One batch over the five-line module, every range case represented."""
    return [
        llm_row(module, 10000),                       # 0 unquoted, past EOF
        llm_row(module, 10000, ABSENT_QUOTE),         # 1 quoted, quote nowhere
        llm_row(module, 7, QUOTE_AT_3),               # 2 quoted, quote at line 3
        llm_row(module, 0),                           # 3 line 0
        llm_row(module, None),                        # 4 no line_start at all
        llm_row(module, 2),                           # 5 unquoted, in file
    ]


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_anchoring_is_length_preserving(monkeypatch, tmp_path, batch, mode):
    """AC14 — no anchor outcome, past EOF included, removes a row."""
    set_quote_mode(monkeypatch, mode)
    size = len(batch)
    out, checks = _pipeline(batch, tmp_path)
    assert len(out) == size and len(checks) == size


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_unquoted_row_past_eof_is_retained_unmoved_and_labelled(
    monkeypatch, tmp_path, module, mode,
):
    """AC15 — unquoted at line 10000 of a 5-line file: kept, line unchanged,
    status still ``unquoted`` (no tenth status), range ``past_eof``."""
    set_quote_mode(monkeypatch, mode)
    out, checks = _pipeline([llm_row(module, 10000)], tmp_path)
    assert out[0]["line_start"] == 10000, "a past-EOF citation must never be moved"
    assert status_of(checks[0]) == "unquoted", "O3 = C keeps the quote verdict"
    assert anchor_extras(checks[0]).get(RANGE_KEY) == "past_eof", (
        f"the anchor check must record the claim as past end of file; "
        f"extras={anchor_extras(checks[0])}"
    )


def test_absent_quote_past_eof_keeps_absent_and_records_past_eof(
    monkeypatch, tmp_path, module,
):
    """AC15 — the fabrication signal survives: status ``absent`` AND
    ``past_eof``. A range check placed before the quote search would erase it."""
    set_quote_mode(monkeypatch, "enforce")
    out, checks = _pipeline([llm_row(module, 10000, ABSENT_QUOTE)], tmp_path)
    assert status_of(checks[0]) == "absent"
    assert out[0]["line_start"] == 10000
    assert anchor_extras(checks[0]).get(RANGE_KEY) == "past_eof"


def test_reanchorable_quote_is_not_shadowed_and_its_claim_records_past_eof(
    monkeypatch, tmp_path, module,
):
    """AC15 (no shadowing) — cited at line 7, quote at line 3: still
    ``reanchored`` per 0076, ``claimed_line`` 7, and the CLAIM is ``past_eof``
    (the range describes what the model said, not where the quote landed)."""
    set_quote_mode(monkeypatch, "enforce")
    out, checks = _pipeline([llm_row(module, 7, QUOTE_AT_3)], tmp_path)
    extras = anchor_extras(checks[0])
    observed = (status_of(checks[0]), out[0]["line_start"], extras.get("claimed_line"))
    assert observed == ("reanchored", 3, 7), "0076's verdict and actuator are unchanged"
    assert extras.get(RANGE_KEY) == "past_eof"


@pytest.mark.parametrize("line", [0, None], ids=["line_zero", "line_absent"])
def test_no_usable_line_records_no_line(monkeypatch, tmp_path, module, line):
    """AC15 — line 0 or no ``line_start`` is "no line", never ``past_eof``."""
    set_quote_mode(monkeypatch, "enforce")
    _out, checks = _pipeline([llm_row(module, line)], tmp_path)
    assert anchor_extras(checks[0]).get(RANGE_KEY) == "no_line"


def test_in_file_citation_records_in_file(monkeypatch, tmp_path, module):
    """AC15 negative — a real line is ``in_file``; the label is not blanket."""
    set_quote_mode(monkeypatch, "enforce")
    _out, checks = _pipeline([llm_row(module, 2)], tmp_path)
    assert anchor_extras(checks[0]).get(RANGE_KEY) == "in_file"


@pytest.mark.parametrize("quote", [None, ABSENT_QUOTE], ids=["unquoted", "absent"])
def test_window_stage_records_out_of_range_never_unreadable(
    monkeypatch, tmp_path, module, quote,
):
    """AC38 — the file WAS read; a past-EOF row's window reason is
    ``out_of_range``, never ``unreadable`` and never ``present``."""
    set_quote_mode(monkeypatch, "enforce")
    out, _checks = _pipeline([llm_row(module, 10000, quote)], tmp_path)
    assert window_reason(out[0]) == "out_of_range"


def test_reanchored_row_windows_its_verified_line(monkeypatch, tmp_path, module):
    """AC38 negative — once 0076 moves the row onto line 3 the window contains
    the cited line, so it is ``present``: the claim's range must not leak into
    the window reason of a row whose final line is in the file."""
    set_quote_mode(monkeypatch, "enforce")
    out, _checks = _pipeline([llm_row(module, 7, QUOTE_AT_3)], tmp_path)
    assert window_reason(out[0]) == "present"


def test_mixed_batch_labels_every_row(monkeypatch, tmp_path, batch):
    """AC14 + AC15 together, one batch: every row survives and carries the
    range its own claim earned."""
    set_quote_mode(monkeypatch, "enforce")
    _out, checks = _pipeline(batch, tmp_path)
    ranges = [anchor_extras(row_checks).get(RANGE_KEY) for row_checks in checks]
    assert ranges == ["past_eof", "past_eof", "past_eof", "no_line", "no_line", "in_file"]
