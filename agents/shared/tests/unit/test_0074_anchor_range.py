"""Feature 0074 P3 (T3.2, T3.3, T3.5) — the claim's range beside 0076's verdict.

Owner decision O3 = C: ``claimed_line_range`` is an ORTHOGONAL fact recorded
beside the quote verdict in the ``anchor`` check's extras. It is computed AFTER
the quote search, so it can never hide a re-anchorable (``reanchored``), a
wrong-file (``found_elsewhere``) or a fabricated (``absent``) quote. It reads
the file through the cache the quote search already populates (H5: no third
reader), and it carries no voter weight.

Also here, §5.4 gap 2: a lone candidate refused by ``MAX_DELTA`` is reported as
reason ``beyond_max_delta`` with ``candidates == 1``, not ``not_unique``.

ACs: AC15, AC28, AC37 (and the O3 = C vocabulary pin).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests.support.past_eof import (
    ABSENT_QUOTE,
    NINE_STATUSES,
    QUOTE_AT_3,
    RANGE_KEY,
    anchor_extras,
    anchor_of,
    choke_point,
    clear_all_caches,
    five_line_file,
    l1_checks,
    llm_row,
    numbered_file,
    set_quote_mode,
    status_of,
    write_lines,
)

# ── an audit hook that counts real file opens (sys.addaudithook cannot be
# removed, so it is installed once and armed only inside `_counting_opens`) ──

_OPENS: list[str] = []
_ARMED: list[bool] = [False]


def _audit(event: str, args: tuple) -> None:
    if _ARMED[0] and event == "open" and isinstance(args[0], (str, Path)):
        _OPENS.append(str(args[0]))


sys.addaudithook(_audit)


def _opens_during(fn, *args) -> list[str]:
    """Run ``fn(*args)`` and return every path opened while it ran."""
    _OPENS.clear()
    _ARMED[0] = True
    try:
        fn(*args)
    finally:
        _ARMED[0] = False
    return list(_OPENS)


def _range_after(rows, root) -> list:
    """Stamp through the real choke point, then read each row's range."""
    stamped = choke_point(rows, root)
    return [anchor_extras(checks).get(RANGE_KEY) for checks in l1_checks(stamped, root)]


# ── AC15: computed AFTER the verdict, so every verdict survives ──────────────


def test_found_elsewhere_survives_a_past_eof_claim(monkeypatch, tmp_path):
    """AC15 — the wrong-file case: cited at line 10000 of a 5-line file, the
    quote exists only in a sibling of the same batch. Still ``found_elsewhere``
    (non-demoting, a wrong PATH), and the claim is ``past_eof``."""
    set_quote_mode(monkeypatch, "enforce")
    cited = write_lines(tmp_path, "cited.ts", ("let a = 1;",) * 5)
    sibling = five_line_file(tmp_path, "sibling.ts")
    rows = [llm_row(cited, 10000, QUOTE_AT_3), llm_row(sibling, 1)]
    checks = l1_checks(choke_point(rows, tmp_path), tmp_path)
    assert status_of(checks[0]) == "found_elsewhere"
    assert anchor_extras(checks[0]).get(RANGE_KEY) == "past_eof"


@pytest.mark.parametrize(("line", "quote", "status", "claim_range"), [
    (10000, None, "unquoted", "past_eof"),
    (10000, ABSENT_QUOTE, "absent", "past_eof"),
    (7, QUOTE_AT_3, "reanchored", "past_eof"),
    (3, QUOTE_AT_3, "exact", "in_file"),
], ids=["unquoted", "absent", "reanchored", "exact"])
def test_range_never_replaces_the_quote_verdict(
    monkeypatch, tmp_path, line, quote, status, claim_range,
):
    """AC15 — the status is the quote verdict 0076 would give; the range is a
    second field. A status of ``past_eof``/``out_of_range`` would be a tenth
    status, which O3 = C forbids."""
    set_quote_mode(monkeypatch, "observe")
    module = five_line_file(tmp_path)
    checks = l1_checks(choke_point([llm_row(module, line, quote)], tmp_path), tmp_path)
    assert status_of(checks[0]) == status
    assert anchor_extras(checks[0]).get(RANGE_KEY) == claim_range


def test_the_last_real_line_is_in_file_and_the_next_is_past_eof(monkeypatch, tmp_path):
    """AC15 boundary — ``len(lines)`` is in the file, ``len(lines) + 1`` is not."""
    set_quote_mode(monkeypatch, "observe")
    module = five_line_file(tmp_path)
    ranges = _range_after([llm_row(module, 5), llm_row(module, 6)], tmp_path)
    assert ranges == ["in_file", "past_eof"]


def test_an_unreadable_file_has_no_range(monkeypatch, tmp_path):
    """AC15 / §5.4 — "an unreadable file has no range": a path that does not
    resolve is never labelled ``in_file`` or ``past_eof``. (Regression pin: the
    plan asks for it and it holds today.)"""
    set_quote_mode(monkeypatch, "observe")
    ghost = tmp_path / "missing.ts"
    ranges = _range_after([llm_row(ghost, 10000)], tmp_path)
    assert ranges[0] not in {"in_file", "past_eof"}


# ── AC28: no new reader ───────────────────────────────────────────────────────


def test_range_adds_no_file_open(monkeypatch, tmp_path):
    """AC28 — a batch of four rows over one file, three of them unquoted (which
    the quote search never reads), opens that file EXACTLY ONCE (the quoted
    row's read, which also proves the hook counts), and every row still carries
    its range: the range reads through the cached reader, not a new one."""
    set_quote_mode(monkeypatch, "observe")
    module = five_line_file(tmp_path)
    rows = [llm_row(module, 10000), llm_row(module, 2), llm_row(module, 0),
            llm_row(module, 7, QUOTE_AT_3)]
    clear_all_caches()
    from shared import audit_runner

    opened = _opens_during(audit_runner._verify_and_strip, rows, str(tmp_path))
    ranges = [anchor_extras(c).get(RANGE_KEY) for c in l1_checks(rows, tmp_path)]
    assert ranges == ["past_eof", "in_file", "no_line", "past_eof"]
    assert opened.count(str(module)) == 1, f"opened {opened.count(str(module))}x"


def test_range_reads_through_anchor_read_lines(monkeypatch, tmp_path):
    """AC28 / H5 — an unquoted row (no quote search) still gets its range, and
    the read goes through ``anchor._read_lines``, the verifier's one reader."""
    from shared import anchor

    set_quote_mode(monkeypatch, "observe")
    module = five_line_file(tmp_path)
    seen: list[str] = []
    real = anchor._read_lines

    def spy(path):
        seen.append(str(path))
        return real(path)

    monkeypatch.setattr(anchor, "_read_lines", spy)
    assert _range_after([llm_row(module, 10000)], tmp_path) == ["past_eof"]
    assert str(module) in seen


# ── O3 = C: the vocabulary and the weights are 0076's, unchanged ──────────────


def test_status_vocabulary_is_unchanged():
    """O3 = C — still the nine 0076 statuses; no ``out_of_range`` status.
    (Regression pin: holds today and must keep holding.)"""
    from shared.anchor import STATUSES

    assert set(STATUSES) == NINE_STATUSES


def test_claimed_line_range_carries_no_voter_weight(monkeypatch, tmp_path):
    """AC15 / O3 = C — the range is labelling only. A past-EOF ``unquoted`` row
    and its in-file twin get the same anchor weight and the same vote."""
    from shared.validate.voter import vote

    set_quote_mode(monkeypatch, "enforce")
    module = five_line_file(tmp_path)
    rows = [llm_row(module, 10000), llm_row(module, 2)]
    past, inside = l1_checks(choke_point(rows, tmp_path), tmp_path)
    assert anchor_extras(past).get(RANGE_KEY) == "past_eof"
    assert anchor_of(past).weight == anchor_of(inside).weight == 0.0
    assert vote(past) == vote(inside)


# ── AC37: a lone candidate refused by MAX_DELTA ──────────────────────────────


def _max_delta_case(monkeypatch, tmp_path):
    """600 distinct lines, the quoted line at 501, the claim at line 3,
    MAX_DELTA 50: one candidate, 498 lines away."""
    set_quote_mode(monkeypatch, "enforce")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_DELTA", "50")
    path = numbered_file(tmp_path, 600)
    quote = path.read_text().splitlines()[500]
    return path, llm_row(path, 3, quote)


def test_lone_candidate_beyond_max_delta_reports_its_reason(monkeypatch, tmp_path):
    """AC37 — the verifier itself: reason ``beyond_max_delta``, candidates 1,
    no new line. The status stays ``ambiguous`` (vocabulary unchanged)."""
    from shared.anchor import verify_anchor

    path, row = _max_delta_case(monkeypatch, tmp_path)
    clear_all_caches()
    result = verify_anchor(row, path, mode="enforce")
    assert (result.status, result.reason) == ("ambiguous", "beyond_max_delta")
    assert result.candidates == 1 and result.new_line is None


def test_beyond_max_delta_reaches_the_anchor_check_and_the_line_stays(
    monkeypatch, tmp_path,
):
    """AC37 — through the choke point: the line does not move, and the
    persisted anchor check names the reason and the single candidate."""
    path, row = _max_delta_case(monkeypatch, tmp_path)
    (checks,) = l1_checks(choke_point([row], tmp_path), tmp_path)
    assert row["line_start"] == 3
    assert "beyond_max_delta" in anchor_of(checks).reason
    assert anchor_extras(checks).get("candidates") == 1


def test_a_genuine_tie_is_still_not_unique(monkeypatch, tmp_path):
    """AC37 negative — two equidistant candidates inside MAX_DELTA are a real
    tie and keep ``not_unique``; only the MAX_DELTA refusal is renamed.
    (Regression pin.)"""
    from shared.anchor import verify_anchor

    set_quote_mode(monkeypatch, "enforce")
    lines = [f"const v{i} = compute({i});" for i in range(1, 41)]
    lines[9] = lines[29] = QUOTE_AT_3
    path = write_lines(tmp_path, "tie.ts", lines)
    clear_all_caches()
    result = verify_anchor(llm_row(path, 20, QUOTE_AT_3), path, mode="enforce")
    assert (result.status, result.reason, result.candidates) == ("ambiguous", "not_unique", 2)
