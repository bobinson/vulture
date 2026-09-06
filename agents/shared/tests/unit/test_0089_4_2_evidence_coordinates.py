"""Feature 0089 item 4.2 — evidence coordinates in ONE space (runtime half).

THE DEFECT, as the audit stated it (LLD §9.5, two blocker rows):

1. ``evidence_line`` was defined in two coordinate spaces at once —
   ``validate_judge.txt`` said *"from the numbered snippet"*, the tool contract
   said *"in the file you read it from"* — while the one consumer
   (``_citation_class``) assumes a single space. The prompt half of the repair
   is pinned by ``tests/unit/prompt/test_0089_4_2_prompt_coordinates.py``; this
   file pins the half that produces the numbers.

2. ``_format_code_window`` ALWAYS renumbered. It stripped the real ``NN:``
   prefixes (A-3 anti-spoofing) and then re-derived a start as
   ``line_start - len(lines) // 2``, which is right only for a window that is
   exactly symmetric around the finding's own line. Every other window — one
   truncated by ``max_chars``, one clipped at the top of a file, one widened
   over a declared multi-line span — was numbered against coordinates the file
   never had.

THE REPAIR. ``ensure_code_window`` records the true 1-based file line of the
window's first row on the finding (``_code_snippet_start``) and
``_format_code_window`` numbers FROM it. A-3 is still met: coordinates come
from a file read, never from the snippet's own text — a snippet whose claimed
numbers the file does not corroborate is rendered UNNUMBERED rather than
mis-numbered.

WHY THE PRE-SET-SNIPPET BRANCH IS CONFIRMED RATHER THAN SKIPPED. The LLD's
spec says the start is "taken from the read it just performed" and expects only
"inherited, rollup" findings to lack one. Measured on a real skills-only CWE run
over ``backend/internal`` (314 findings): **99.0% arrive at
``ensure_code_window`` with a code_snippet a skill already set**, which the
function deliberately does not re-read. Recording only on the read branch would
therefore have left ~99% of judged findings with no line numbers at all — the
opposite of the item's purpose. So the pre-set branch reads the file too, and
records the snippet's own claimed start ONLY when the file corroborates it,
line for line. The coordinate still comes from the file; what the snippet
supplies is a claim the file has to confirm.

Pure and offline: temp files, string composition. No client, no network, no
model call.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.tools.line_format import read_line_number
from shared.tools.snippet import extract_snippet, window_first_line
from shared.tools.window import (
    CODE_SNIPPET_START,
    confirmed_window_start,
    ensure_code_window,
)
from shared.validate.llm_judge import (
    _citation_class,
    _coerce_verdict,
    _format_code_window,
    _render_user_message,
    _verdict_to_check,
)

# ── fixtures ──────────────────────────────────────────────────────────────

# 40 lines, each self-identifying, so a mis-numbered render is legible in the
# failure message rather than merely unequal.
SOURCE = "\n".join(f"code_on_file_line_{i}()" for i in range(1, 41)) + "\n"


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "q.py").write_text(SOURCE, encoding="utf-8")
    return tmp_path


def _finding(**over) -> dict:
    f = {
        "id": "F-1",
        "category": "CWE-89",
        "check_id": "py.sql-injection",
        "severity": "high",
        "file_path": "svc/q.py",
        "line_start": 20,
        "line_end": 20,
        "description": "d",
    }
    f.update(over)
    return f


# ── the read-direction number authority ───────────────────────────────────

def test_read_line_number_is_the_inverse_of_the_write_direction():
    """`line_format` owns both directions of `"NN: "`; the number half is new.

    `strip_line_number` already reads the TEXT back out of a numbered line.
    Reading the NUMBER back was open-coded nowhere, so the confirmation step
    below would have had to invent a second pattern — which is exactly how the
    feed probe and `_redact_snippet` came to disagree about leading whitespace
    (feature 0076).
    """
    assert read_line_number("30: code") == 30
    assert read_line_number("  7: indented") == 7
    assert read_line_number("no number here") is None
    assert read_line_number("") is None
    # One prefix, the outermost: a source line that itself looks numbered.
    assert read_line_number("1: 12: x") == 1


def test_window_first_line_is_the_start_extract_snippet_actually_uses():
    """The helper must not be a second, drifting copy of the window arithmetic.

    Driven against `extract_snippet` itself at every offset that clips: near
    the top of the file, in the middle, and past the end.
    """
    lines = SOURCE.splitlines()
    for line_num in range(1, len(lines) + 1):
        for context in (0, 2, 10):
            snippet = extract_snippet(lines, line_num, context=context,
                                      max_chars=None)
            first = read_line_number(snippet.splitlines()[0])
            assert first == window_first_line(line_num, context), (
                line_num, context, snippet.splitlines()[0])


# ── ensure_code_window records the start ──────────────────────────────────

def test_records_the_true_start_for_a_window_it_reads_itself(tree: Path):
    f = _finding()
    ensure_code_window([f], str(tree))
    assert f[CODE_SNIPPET_START] == 18            # line 20, context 2
    assert f["code_snippet"].startswith("18: code_on_file_line_18()")


def test_records_a_confirmed_start_for_a_snippet_a_skill_already_set(tree: Path):
    """99% of real findings take this branch; it may not go unnumbered."""
    lines = SOURCE.splitlines()
    f = _finding(code_snippet=extract_snippet(lines, 20))
    before = f["code_snippet"]
    ensure_code_window([f], str(tree))
    assert f["code_snippet"] == before            # still additive: not re-read
    assert f[CODE_SNIPPET_START] == 18


def test_refuses_a_start_the_file_does_not_corroborate(tree: Path):
    """A-3: the snippet's own text may CLAIM a coordinate, never supply one."""
    f = _finding(code_snippet="4: code_on_file_line_20()\n"
                              "5: code_on_file_line_21()")
    ensure_code_window([f], str(tree))
    assert CODE_SNIPPET_START not in f


def test_records_nothing_when_there_is_no_file_to_confirm_against(tree: Path):
    """Inherited / rollup / no-code-location findings: absent, not guessed."""
    f = _finding(file_path="", line_start=0,
                 code_snippet="1: something carried from elsewhere")
    ensure_code_window([f], str(tree))
    assert CODE_SNIPPET_START not in f


def test_every_row_s_own_number_is_checked_not_just_the_first(tree: Path):
    """A window shifted by one must fail on every row, not slip past on one.

    The rows are compared against the NUMBERED form of the file line, so each
    row's own `NN: ` prefix is corroborated too.
    """
    lines = SOURCE.splitlines()
    good = extract_snippet(lines, 20)
    assert confirmed_window_start(good, lines) == 18
    shifted = "\n".join(
        f"{int(r.split(':')[0]) + 1}:{r.split(':', 1)[1]}" for r in good.splitlines())
    assert confirmed_window_start(shifted, lines) == 0


def test_a_row_truncated_mid_prefix_still_confirms(tree: Path):
    """`max_chars` cuts the JOINED snippet, so the last row can be `"20"`.

    Measured on a whole-repo skills run: this shape accounts for most of the
    windows the first draft of the confirmation refused, and every one of them
    is a real, correctly-positioned window.
    """
    lines = SOURCE.splitlines()
    snippet = extract_snippet(lines, 20, context=2, max_chars=55)
    assert snippet.splitlines()[-1].isdigit(), snippet   # the shape in question
    assert confirmed_window_start(snippet, lines) == 18


def test_a_redacted_row_does_not_cost_the_window_its_coordinates(tree: Path):
    """`_redact_snippet` rewrites the secret, so the row cannot equal source.

    Refusing those would strip coordinates from exactly the secret-bearing
    findings a judge most wants to cite. The neighbours still have to match, so
    the position is still fixed by the file.
    """
    from shared.audit_runner import _REDACTION_PLACEHOLDER

    lines = SOURCE.splitlines()
    rows = extract_snippet(lines, 20).splitlines()
    rows[2] = f"20: {_REDACTION_PLACEHOLDER}"
    assert confirmed_window_start("\n".join(rows), lines) == 18
    # ...and the exemption is one row wide: shift the rest and it still fails.
    shifted = [rows[0], "99: nope()", rows[2], rows[3], rows[4]]
    assert confirmed_window_start("\n".join(shifted), lines) == 0


def test_the_redaction_marker_is_the_one_audit_runner_writes():
    """A leaf may not import `audit_runner`, so the constant is restated —
    and pinned equal here, or the exemption silently stops applying."""
    from shared.audit_runner import _REDACTION_PLACEHOLDER
    from shared.tools.window import _REDACTED

    assert _REDACTED == _REDACTION_PLACEHOLDER


def test_confirmed_window_start_needs_real_content_to_match():
    """A window of blank lines matches everywhere and so confirms nowhere."""
    lines = ("", "", "", "", "")
    assert confirmed_window_start("2: \n3: ", lines) == 0
    assert confirmed_window_start("", lines) == 0
    assert confirmed_window_start("no prefix at all", lines) == 0


# ── _format_code_window numbers from the recorded start ───────────────────

def test_numbers_from_the_recorded_start_not_from_line_start():
    out = _format_code_window("a()\nb()\nc()", snippet_start=40)
    assert out == "L40: a()\nL41: b()\nL42: c()"


def test_the_truncated_window_that_the_old_derivation_mis_numbered(tree: Path):
    """The measured defect, end to end, on a window `max_chars` cut short.

    BEFORE 4.2 `_format_code_window` derived `start = line_start - len // 2`.
    A 200-char cut leaves a 4-line window here, so the old start was
    `20 - 2 = 18` for a window that begins at 18 — right by luck. Cut it to 3
    lines and the old start becomes 19 for a window that still begins at 18:
    every number one too high, and nothing anywhere says so.
    """
    lines = SOURCE.splitlines()
    snippet = extract_snippet(lines, 20, context=2, max_chars=72)
    f = _finding(code_snippet=snippet)
    ensure_code_window([f], str(tree))

    rows = _format_code_window(f["code_snippet"], f[CODE_SNIPPET_START]).splitlines()
    assert len(rows) == 3, rows                    # the cut really happened
    assert rows[0].startswith("L18: ")
    # The number the model is shown on a row IS that row's file line. The last
    # row is where the character cut lands, so the shown text is a PREFIX of
    # the file's line rather than the whole of it.
    for row in rows:
        label, _, shown = row.partition(": ")
        n = int(label[1:])
        assert f"code_on_file_line_{n}()".startswith(shown), row
    # ...and the old derivation would have said 19.
    assert max(1, 20 - len(rows) // 2) == 19


def test_a_span_window_is_numbered_from_its_own_first_line(tree: Path):
    """A declared multi-line range moves the window's centre off `line_start`.

    The old derivation subtracted half the window from `line_start`, so a
    finding declaring lines 20-30 was shown numbers ~5 lines below the truth —
    the largest error class, and the one the archived scan's own -10/-11
    outliers came from.
    """
    f = _finding(line_start=20, line_end=30)
    ensure_code_window([f], str(tree))
    rows = _format_code_window(f["code_snippet"], f[CODE_SNIPPET_START]).splitlines()
    assert f[CODE_SNIPPET_START] == 18
    assert rows[0] == "L18: code_on_file_line_18()"
    assert max(1, 20 - len(rows) // 2) != 18       # the old start was wrong


def test_no_recorded_start_renders_unnumbered_rather_than_mis_numbered():
    """LLD §9.5: "render unnumbered rather than mis-numbered"."""
    out = _format_code_window("a()\nb()", snippet_start=None)
    assert out == "a()\nb()"
    assert "L" not in out


@pytest.mark.parametrize("bad", [0, -3, "12", 1.5, True])
def test_a_start_that_is_not_a_positive_int_renders_unnumbered(bad):
    """Fails closed: an unusable coordinate is no coordinate."""
    assert _format_code_window("a()\nb()", snippet_start=bad) == "a()\nb()"


def test_a3_still_holds_content_prefixes_are_stripped_and_never_believed():
    """The anti-spoofing property, restated for the new numbering source."""
    out = _format_code_window("99: evil()\n100: more()", snippet_start=7)
    assert out == "L7: evil()\nL8: more()"


# ── the whole user turn ───────────────────────────────────────────────────

def test_the_model_is_shown_the_finding_s_own_line_at_its_own_number(tree: Path):
    """The property the citation statistic depends on, driven through production."""
    f = _finding()
    ensure_code_window([f], str(tree))
    msg = _render_user_message("aud", [(0, f, "python")])
    assert "L20: code_on_file_line_20()" in msg
    assert "lines=20-20" in msg


# ── evidence_file reaches the verdict ─────────────────────────────────────

def test_coerce_verdict_admits_evidence_file():
    v = _coerce_verdict({"id": "F-1", "exploitable": 0.2,
                         "evidence_line": 31, "evidence_file": "svc/other.py"})
    assert v["evidence_file"] == "svc/other.py"
    assert v["evidence_line"] == 31


@pytest.mark.parametrize("bad", [None, 7, "", [], {"a": 1}, True])
def test_a_non_string_evidence_file_normalises_to_none(bad):
    v = _coerce_verdict({"id": "F-1", "exploitable": 0.2, "evidence_file": bad})
    assert v["evidence_file"] is None


def test_the_verdict_check_carries_the_file_alongside_the_line():
    """Persisted with the verdict, or the coordinate is only half recorded."""
    v = _coerce_verdict({"id": "F-1", "exploitable": 0.2, "evidence_line": 31,
                         "evidence_file": "svc/other.py"})
    check = _verdict_to_check(v, model="m", batch_id=0, language="python",
                              finding=_finding())
    assert check.extras["evidence_file"] == "svc/other.py"
    assert check.extras["evidence_line"] == 31


# ── citation_class, now that a citation can name another file ─────────────

def test_citation_class_unchanged_when_the_line_is_in_the_finding_s_file():
    f = _finding()
    assert _citation_class(None, f) == "missing"
    assert _citation_class(20, f) == "self_line"
    assert _citation_class(31, f) == "other_line"


def test_a_line_in_another_file_is_not_a_self_line():
    """`evidence_line == line_start` in a DIFFERENT file is a coincidence.

    Without this the new field silently corrupts the statistic the item is
    measured by: a tool-read citation at line 20 of a helper would be counted
    as the judge echoing the finding's own line 20.
    """
    f = _finding()
    assert _citation_class(20, f, evidence_file="svc/helper.py") == "other_file"
    assert _citation_class(31, f, evidence_file="svc/helper.py") == "other_file"
    # The finding's own file, however named, is not "another file": the tool
    # takes whatever path the model passed, the block prints what the finding
    # carries, and the two spellings routinely differ by a prefix.
    assert _citation_class(20, f, evidence_file="svc/q.py") == "self_line"
    assert _citation_class(20, f, evidence_file="./svc/q.py") == "self_line"
    assert _citation_class(20, f, evidence_file="/root/svc/q.py") == "self_line"
    assert _citation_class(20, f, evidence_file="q.py") == "self_line"
    # ...but the suffix has to fall on a path SEGMENT, or `q.py` and `y` agree.
    assert _citation_class(20, f, evidence_file="y") == "other_file"
    assert _citation_class(20, f, evidence_file="other/svcq.py") == "other_file"


def test_a_finding_with_no_path_of_its_own_is_never_elsewhere():
    """Nothing to disagree with; `other_file` would be an unfounded claim."""
    f = _finding(file_path="")
    assert _citation_class(20, f, evidence_file="anything.py") == "self_line"


# ── the cache may not serve verdicts produced under the old prompt ────────

def test_verdict_schema_version_moved_off_the_pre_4_2_value():
    from shared.validate.l5_cache import _VERDICT_SCHEMA_VERSION

    assert _VERDICT_SCHEMA_VERSION != "v5-tool-trigger", (
        "item 4.2 changes the judge prompt AND the verdict schema; a cached "
        "v5 verdict was produced under the two-coordinate-space prompt"
    )


def test_the_cache_round_trips_evidence_file(tmp_path, monkeypatch):
    """A replayed verdict must carry the whole coordinate, not half of it."""
    from shared.validate import l5_cache

    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "c.db"))
    l5_cache.reset_for_tests()
    try:
        key = l5_cache.cache_key(file_path="svc/q.py", line_start=20,
                                 line_end=20, check_id="c", model="m")
        l5_cache.store(key, exploitable=0.2, reasoning="r", model="m",
                       language="python", evidence_line=31,
                       evidence_file="svc/helper.py")
        got = l5_cache.lookup(key)
        assert got is not None
        assert got["evidence_line"] == 31
        assert got["evidence_file"] == "svc/helper.py"
    finally:
        l5_cache.reset_for_tests()


# ── nothing new egresses ──────────────────────────────────────────────────

def test_the_recorded_start_is_private_and_never_reaches_an_sse_finding(tree: Path):
    """`_public_view` drops underscore-prefixed stamps; this is why it is one.

    `emitter.finding_event(**_public_view(finding))` forwards `**extra`
    verbatim, and Go's `model.Finding` has no such column, so a PUBLIC name
    here would show one content live and another on replay — the hazard the
    seven `_anchor_*` stamps are underscore-prefixed for.
    """
    from shared.audit_runner import _public_view

    f = _finding()
    ensure_code_window([f], str(tree))
    assert CODE_SNIPPET_START.startswith("_")
    assert CODE_SNIPPET_START not in _public_view(f)
    assert CODE_SNIPPET_START not in json.dumps(_public_view(f))


def test_the_result_snapshot_carries_no_private_stamp_either(tree: Path):
    """The other emit. A private field reaching one and not the other is the
    "two contents depending on when you looked" hazard, just at a different
    seam: `_anchor_*` never gets here (the vote deletes it first) but
    `_code_snippet_start` must, so the result event filters like the finding
    event does.
    """
    from shared.transport.event_emitter import AgUiEventEmitter

    f = _finding()
    ensure_code_window([f], str(tree))
    assert f[CODE_SNIPPET_START] == 18                    # it IS on the finding
    from shared.audit_runner import _public_view

    event = AgUiEventEmitter("run").result_event(
        findings=[_public_view(f)], summary="s", score=1.0)
    assert CODE_SNIPPET_START not in event


def test_the_recorded_start_survives_the_provisional_vote_that_precedes_l5(tree: Path):
    """It must NOT be on `_PRIVATE_FIELDS`: L5 is its only consumer.

    `_apply_validation_to_finding` strips that roster before `_run_l5_phase`
    runs, which is exactly how the `_anchor_*` stamps would have been made
    inert had they been stripped at parse time. Same trap, other end.
    """
    from shared.audit_runner import _PRIVATE_FIELDS, _strip_private_fields

    f = _finding()
    ensure_code_window([f], str(tree))
    assert CODE_SNIPPET_START not in _PRIVATE_FIELDS
    _strip_private_fields(f)
    assert f[CODE_SNIPPET_START] == 18
