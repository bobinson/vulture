"""0076 §5.1 — the parser prerequisite: nothing code-bearing can cross the LLM
parse path until the parser stops being a regex.

WHY THIS FILE EXISTS. 0076 makes the model quote the code it accuses. The quote
is source text, and source text contains braces. `_LLM_JSON_BARE_RE`
(`audit_runner.py:57`) is `(\\[\\s*\\{.*?\\}\\s*\\])`: a non-greedy `}\\s*]` cannot
survive a string value that itself contains `}]`. Measured against the code as
shipped today, all three of these return `[]` — the WHOLE BATCH of findings is
lost, not one field of one row:

    _parse_llm_findings('[{"title":"a","evidence_quote":"const rows = [{ id: 1 }]"},'
                        '{"title":"b"}]')                       -> []   (AC1)
    _parse_llm_findings('[{"severity":"high","title":"Real"}, "not a dict", 42]')
                                                                -> []   (AC2)
    _parse_llm_findings('[{"title":"x","line_start":"55"}]')['line_start']
                                                                -> '55' (AC3, a str)

`[{ id: 1 }]` is an everyday TypeScript/JSX literal, so this is not a contrived
input — it is what a model quoting a `.ts` file writes. The last case is worse
than it looks: a string `line_start` reaches Go's `LineStart int` unmarshal and
`agui/finding_parse.go:33` drops the finding silently (B2).

THE RANKING TESTS ARE NOT DECORATION. The obvious replacement — return the FIRST
array that `raw_decode` accepts — introduces a whole-batch loss the regex never
had: a model that opens with prose containing `["a","b"]`, or whose quote holds
`[{ id: 1 }]`, has its real payload shadowed by a decoy. An earlier revision of
the plan then scored candidates `(len(rows), key_hits)`; under tuple comparison
row count wins first, so a three-row decoy carrying NO finding keys —
`[{"id":1},{"id":2},{"id":3}]`, an everyday example in model prose — outranks the
real one-row payload and the batch is lost again in a new shape. The contract is
that FINDING-KEY EVIDENCE DOMINATES ROW COUNT, and ties break to the LAST
candidate because a model that restates its answer puts the payload at the end.

AC26 IS A RECALL GUARD, AND IT IS THE SUBTLE ONE. Stripping the model's
`check_id` (B3/C7) is not free: `_dedup_key` (`:1159-1169`) PREFERS `check_id`
over the normalised title, so a strip RE-KEYS every structured-path row onto
`(normalised_title, path)` — and if a skill row in the same file already carries
that title, the LLM row becomes a duplicate and `_deduplicate_findings` DELETES
it. Verified against the code as shipped: the two rows of `_SKILL_ROW` /
`_MODEL_ROW` both key to `('sql injection', 'src/db.py')` once the model's
`check_id` is gone, and the LLM row's survival count goes 1 -> 0. In a feature
whose central commitment is that nothing is deleted, that is the defect. The
identity is therefore preserved as the private `_model_check_id` and `_dedup_key`
falls back to it, and AC26 pins the invariant: the strip changes the post-dedup
count by ZERO.

Every switch here is read at CALL TIME (D14). Each switch test flips it with
monkeypatch mid-test and observes the change with no module reload — a value
captured at import would pass a one-sided test and fail this one.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Shared inputs. One tree of fixtures, reused (DRY) — the ranking, tie-break and
# AC26 tests all need the same "real payload" and "decoy" shapes.
# ─────────────────────────────────────────────────────────────────────────────

# T1.1 / AC1, verbatim from the plan. The `}]` inside the quote is what truncates
# the regex match.
_BRACED_BATCH = '[{"title":"a","evidence_quote":"const rows = [{ id: 1 }]"},{"title":"b"}]'

# AC2 / D15: the array a model writes when it trails a comment or a count after
# its findings. The dict is a real finding and must not be thrown away with the
# junk around it.
_MIXED_ARRAY = '[{"severity": "high", "title": "Real"}, "not a dict", 42]'

# A findings-shaped payload: ONE row, all nine finding keys.
_REAL_PAYLOAD = (
    '[{"severity":"high","category":"cwe","title":"SQL injection",'
    '"description":"d","file_path":"src/db.py","line_start":42,"line_end":42,'
    '"recommendation":"r","evidence_quote":"cursor.execute(q + uid)"}]'
)

# The decoy that carries NO finding key at all — a TS example in model prose.
# `_score_array` must reject it outright; it can then never outrank anything.
_ZERO_KEY_DECOY = '[{"id":1},{"id":2},{"id":3}]'

# The decoy that carries ONE finding key per row across THREE rows. This is the
# one that exposes a `(len(rows), key_hits)` ordering: it beats the real payload
# on row count while carrying a third of its key evidence.
_WEAK_MULTI_ROW_DECOY = '[{"title":"a"},{"title":"b"},{"title":"c"}]'

# A response cut at VULTURE_LLM_MAX_OUTPUT_TOKENS: two whole objects, then a
# partial third. Today this is a total loss of the batch — there is no `]`
# anywhere, so neither pattern matches and the two complete findings are dropped.
_TRUNCATED_BATCH = (
    '[\n'
    '  {"severity":"high","title":"Missing timeout","file_path":"src/a.ts","line_start":10},\n'
    '  {"severity":"low","title":"Unbounded retry","file_path":"src/b.ts","line_start":20},\n'
    '  {"severity":"medium","title":"Partial ro'
)

# AC26: a skill row and a model row that share (normalised_title, file_path).
# The model row's `check_id` is the ONLY thing keeping the two keys apart today.
_SKILL_ROW = {
    "severity": "high",
    "title": "SQL injection in login handler",
    "file_path": "src/db.py",
}
_MODEL_ROW: dict[str, Any] = {
    "severity": "high",
    "title": "SQL injection in login handler",
    "file_path": "src/db.py",
    "line_start": 42,
    "line_end": 42,
    "check_id": "model.invented.sqli",
    "code_snippet": "cursor.execute('SELECT * FROM u WHERE id=' + uid)",
}


def _one(output: str) -> dict:
    """Parse `output` on the UNSTRUCTURED path and return its single finding."""
    from shared.audit_runner import _parse_llm_findings

    rows = _parse_llm_findings(output)
    assert len(rows) == 1, f"expected exactly one parsed finding, got {rows!r}"
    return rows[0]


def _titles(rows: list[dict] | None) -> list[str]:
    """Titles of a scan result, in order, so a ranking assertion reads plainly."""
    assert rows is not None, "the scan found no findings array at all"
    return [r.get("title", "") for r in rows]


def _structured_result(**fields: Any) -> Any:
    """An Agent SDK result whose `final_output` is a STRUCTURED `AuditOutput`."""
    from shared.audit_runner import AuditFinding, AuditOutput

    return SimpleNamespace(final_output=AuditOutput(findings=[AuditFinding(**fields)]))


def _parse_structured(monkeypatch, **fields: Any) -> dict:
    """Parse one model row on the STRUCTURED branch, endpoint pinned.

    D7: the structured path is off whenever `OPENAI_BASE_URL` is set, so a test
    that means to exercise it must say so rather than inherit the developer's
    shell. `OPENAI_BASE_URL` is not a `VULTURE_*` name, so the autouse isolation
    fixture does not remove it.
    """
    from shared.audit_runner import _parse_llm_result

    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    rows = _parse_llm_result(_structured_result(**fields))
    assert len(rows) == 1, f"the structured branch must yield the model's one row, got {rows!r}"
    return rows[0]


def _parse_unstructured(monkeypatch, output: str) -> list[dict]:
    """Parse raw model text on the UNSTRUCTURED branch, endpoint pinned (D7)."""
    from shared.audit_runner import _parse_llm_result

    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1")
    return _parse_llm_result(SimpleNamespace(final_output=output))


# ─────────────────────────────────────────────────────────────────────────────
# AC1 — a bare array whose string values contain `}]` must parse COMPLETELY
# ─────────────────────────────────────────────────────────────────────────────

def test_bare_array_with_a_braced_quote_still_parses():
    """T1.1 / AC1 — the keystone. Measured `[]` today: the whole batch is lost.

    The non-greedy `}\\s*]` in `_LLM_JSON_BARE_RE` stops inside the quote's
    `[{ id: 1 }]`, `json.loads` raises on the truncated text, and every finding
    in the batch is discarded. Both rows must come back — including the sloppy
    trailing `{"title":"b"}`, which scoring may ignore but the return must keep.
    """
    from shared.audit_runner import _parse_llm_findings

    rows = _parse_llm_findings(_BRACED_BATCH)
    assert len(rows) == 2, (
        "a quote containing `}]` must not truncate the batch; "
        f"got {len(rows)} finding(s): {rows!r}"
    )
    assert [r["title"] for r in rows] == ["a", "b"], (
        "both rows must survive, in order, including the key-poor trailing row"
    )


def test_scan_returns_every_dict_row_not_only_the_findings_shaped_ones():
    """`_scan_json_arrays` SCORES on findings-shaped rows but RETURNS all dicts.

    Ranking and recall are different jobs: a row is allowed to be sloppy without
    being deleted. `{"title":"b"}` carries one finding key, which is too little
    to make an array look like a payload on its own, and is still a finding.
    """
    from shared.audit_runner import _scan_json_arrays

    assert _titles(_scan_json_arrays(_BRACED_BATCH)) == ["a", "b"]


def test_json_scan_switch_is_read_at_call_time(monkeypatch):
    """`VULTURE_LLM_JSON_SCAN=false` restores `_LLM_JSON_BARE_RE` (§5.9).

    Flipped mid-test with no module reload: a value captured at import time
    would pass a one-sided test and fail here.
    """
    from shared.audit_runner import _parse_llm_findings

    assert len(_parse_llm_findings(_BRACED_BATCH)) == 2, "default must be the scan"

    monkeypatch.setenv("VULTURE_LLM_JSON_SCAN", "false")
    assert _parse_llm_findings(_BRACED_BATCH) == [], (
        "the rollback switch must restore the pre-0076 regex behaviour — losing "
        "the batch is exactly what it is reverting TO"
    )

    monkeypatch.setenv("VULTURE_LLM_JSON_SCAN", "true")
    assert len(_parse_llm_findings(_BRACED_BATCH)) == 2, (
        "the switch is read per call, so flipping it back must take effect "
        "without reimporting audit_runner"
    )


# ─────────────────────────────────────────────────────────────────────────────
# AC2 — a mixed array keeps its dict entries
# ─────────────────────────────────────────────────────────────────────────────

def test_mixed_array_keeps_the_dict_entries():
    """AC2 / D15 — `[{...}, "not a dict", 42]` must yield the one real finding.

    `test_mixed_array_not_matched_by_regex` (`test_audit_runner.py:180-185`)
    pins the opposite. Its own docstring describes the regex MECHANISM, not a
    business requirement, and the behaviour it pins DROPS A VALID FINDING. T1.7
    inverts and renames it in its own commit; this is the assertion that
    replaces it.
    """
    from shared.audit_runner import _parse_llm_findings

    rows = _parse_llm_findings(_MIXED_ARRAY)
    assert len(rows) == 1, f"the dict entry must survive its junk neighbours, got {rows!r}"
    assert rows[0]["title"] == "Real"
    assert rows[0]["severity"] == "high"


# ─────────────────────────────────────────────────────────────────────────────
# Ranking — key evidence dominates row count, and ties break to the LAST
# ─────────────────────────────────────────────────────────────────────────────

def test_score_array_returns_none_for_a_zero_finding_key_array():
    """A decoy carrying no finding key is not a candidate AT ALL.

    Returning `None` rather than a low score is the load-bearing part: it means
    no amount of row count can promote `[{"id":1},{"id":2},{"id":3}]` above a
    real payload, whatever the tuple ordering downstream turns out to be.
    """
    import json

    from shared.audit_runner import _score_array

    assert _score_array(json.loads(_ZERO_KEY_DECOY)) is None, (
        "an array of rows with no finding keys must not rank as a findings payload"
    )
    assert _score_array(["a", "b"]) is None, "a bare string array is not a payload"
    assert _score_array([]) is None, "an empty array is not a payload"


def test_key_evidence_dominates_row_count():
    """The ordering defect, stated as an inequality.

    Under the rejected `(len(rows), key_hits)` ordering the three-row decoy
    scores `(3, 3)` and the real one-row payload `(1, 9)`, so the decoy WINS and
    the batch is lost. Whatever tuple the scorer returns, the real payload must
    compare GREATER than a decoy with three times the rows and a third of the
    key evidence.
    """
    import json

    from shared.audit_runner import _score_array

    real = _score_array(json.loads(_REAL_PAYLOAD))
    weak = _score_array(json.loads(_WEAK_MULTI_ROW_DECOY))
    assert real is not None and weak is not None, "both arrays contain finding keys"
    assert real > weak, (
        f"finding-key evidence must dominate row count; real={real!r} weak={weak!r} "
        "— a (row_count, key_hits) ordering reintroduces the whole-batch loss"
    )


def test_a_decoy_before_the_payload_does_not_win():
    """RECALL, review recall-4: first-match scanning is a new whole-batch loss.

    A model that opens with a TS example, then answers, must not have its answer
    shadowed by the example.
    """
    from shared.audit_runner import _scan_json_arrays

    zero_key_first = f"For example: {_ZERO_KEY_DECOY}\n\n{_REAL_PAYLOAD}"
    weak_first = f"{_WEAK_MULTI_ROW_DECOY}\n\n{_REAL_PAYLOAD}"

    assert _titles(_scan_json_arrays(zero_key_first)) == ["SQL injection"], (
        "a zero-finding-key decoy appearing FIRST must not win"
    )
    assert _titles(_scan_json_arrays(weak_first)) == ["SQL injection"], (
        "a three-row decoy appearing FIRST must not outrank the real payload on row count"
    )


def test_the_payload_before_a_decoy_still_wins():
    """The other order — a payload followed by trailing prose that contains an
    array. Ties break to the LAST candidate, so the decoy must be rejected on
    its SCORE, not merely on its position; testing one order cannot tell those
    two mechanisms apart.
    """
    from shared.audit_runner import _scan_json_arrays

    zero_key_last = f"{_REAL_PAYLOAD}\n\nCompare with {_ZERO_KEY_DECOY}"
    weak_last = f"{_REAL_PAYLOAD}\n\n{_WEAK_MULTI_ROW_DECOY}"

    assert _titles(_scan_json_arrays(zero_key_last)) == ["SQL injection"]
    assert _titles(_scan_json_arrays(weak_last)) == ["SQL injection"], (
        "position must not rescue a decoy that scores below the payload"
    )


def test_ties_break_to_the_last_candidate():
    """Equal scores resolve to the LATER array: a model that restates its answer
    puts the real payload at the end, and the restatement is the corrected one.
    """
    from shared.audit_runner import _scan_json_arrays

    output = (
        '[{"title":"first","severity":"high","file_path":"a.ts"}]\n'
        'On reflection:\n'
        '[{"title":"second","severity":"high","file_path":"a.ts"}]'
    )
    assert _titles(_scan_json_arrays(output)) == ["second"], (
        "identically scored candidates must resolve to the LAST one"
    )


def test_scan_returns_none_when_there_is_no_findings_array():
    """`None` (not `[]`) is the "nothing here" signal, so the caller can fall
    through to salvage instead of treating a decoy-only response as an answer.
    """
    from shared.audit_runner import _scan_json_arrays

    assert _scan_json_arrays("I found no issues in the codebase.") is None
    assert _scan_json_arrays('I looked at ["a","b"] and found nothing.') is None
    assert _scan_json_arrays(_ZERO_KEY_DECOY) is None


def test_fenced_output_is_tried_first_and_unchanged():
    """T1.2 — REGRESSION LOCK, not a RED test.

    The fenced pattern (`:56`) is untouched, and it is attempted BEFORE the
    scan, so a compliant model's output is byte-for-byte unaffected. Pinned by
    construction: the bare array here scores far higher than the fenced one, so
    only "fenced first" can produce this result.
    """
    from shared.audit_runner import _parse_llm_findings

    output = (
        '```json\n[{"title":"fenced","severity":"high","file_path":"a.ts"}]\n```\n\n'
        f'Restated: {_REAL_PAYLOAD}'
    )
    rows = _parse_llm_findings(output)
    assert [r["title"] for r in rows] == ["fenced"], (
        "the fenced block must win outright; the scan is a FALLBACK, not a re-rank "
        "of a compliant model's answer"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Salvage — an array truncated at the output-token cap
# ─────────────────────────────────────────────────────────────────────────────

def test_truncated_array_recovers_whole_objects_and_discards_the_tail(monkeypatch):
    """A response cut at `VULTURE_LLM_MAX_OUTPUT_TOKENS` is a total loss today.

    There is no `]` in the output, so neither the fenced nor the bare pattern
    matches and both COMPLETE findings are thrown away with the partial third.
    Salvage keeps the whole objects and discards only the fragment.
    """
    from shared.audit_runner import _salvage_truncated_array

    monkeypatch.setenv("VULTURE_LLM_JSON_SALVAGE", "true")
    rows = _salvage_truncated_array(_TRUNCATED_BATCH)
    assert _titles(rows) == ["Missing timeout", "Unbounded retry"], (
        "both whole objects must be recovered and the partial tail dropped; "
        f"got {rows!r}"
    )


def test_parse_falls_through_to_salvage(monkeypatch):
    """Order of attempts: fenced -> scan -> salvage -> `[]`. Salvage is reached
    only when the first two fail, and it must be reached through the public
    parse entry point, not just as a helper nobody calls."""
    from shared.audit_runner import _parse_llm_findings

    monkeypatch.setenv("VULTURE_LLM_JSON_SALVAGE", "true")
    rows = _parse_llm_findings(_TRUNCATED_BATCH)
    assert [r["title"] for r in rows] == ["Missing timeout", "Unbounded retry"]


def test_salvage_switch_is_read_at_call_time(monkeypatch):
    """`VULTURE_LLM_JSON_SALVAGE` (default true) is a per-call read (§5.9)."""
    from shared.audit_runner import _parse_llm_findings

    assert len(_parse_llm_findings(_TRUNCATED_BATCH)) == 2, "salvage defaults ON"

    monkeypatch.setenv("VULTURE_LLM_JSON_SALVAGE", "false")
    assert _parse_llm_findings(_TRUNCATED_BATCH) == [], (
        "with salvage off, a truncated array is the pre-0076 total loss"
    )

    monkeypatch.setenv("VULTURE_LLM_JSON_SALVAGE", "true")
    assert len(_parse_llm_findings(_TRUNCATED_BATCH)) == 2, (
        "flipping the switch back must take effect with no module reload"
    )


# ─────────────────────────────────────────────────────────────────────────────
# AC3 — line fields leave the parser as non-negative, ordered ints
# ─────────────────────────────────────────────────────────────────────────────

def test_string_line_start_is_coerced_to_int():
    """T1.3 / AC3 / B2 — `"55"` reaches Go's `LineStart int` unmarshal today and
    `agui/finding_parse.go:33` DROPS the finding. The loss is silent, so the
    coercion is a recall fix, not a tidiness fix."""
    from shared.audit_runner import _coerce_line

    got = _coerce_line("55")
    assert got == 55, f"a string line number must become the int it names, got {got!r}"
    assert isinstance(got, int), f"must be an int, not {type(got).__name__}"
    assert _coerce_line(55) == 55, "an int passes through unchanged"


def test_coerce_line_falls_back_to_the_default_on_junk():
    """A model that writes prose where a number belongs must not crash the batch
    and must not invent a line: it gets the caller's default."""
    from shared.audit_runner import _coerce_line

    assert _coerce_line("not a line") == 0
    assert _coerce_line(None) == 0
    assert _coerce_line("") == 0
    assert _coerce_line("nope", default=7) == 7, "the caller's default must be honoured"


def test_line_end_is_clamped_at_or_above_line_start():
    """AC3 / B4 — `line_end` is requested and stored with no range validation
    today. An inverted range is a nonsense window for every downstream reader
    (`_attach_code_snippet`, the L5 window, the Go finding row)."""
    row = _one('[{"title":"t","file_path":"a.ts","line_start":"55","line_end":3}]')

    assert row["line_start"] == 55
    assert isinstance(row["line_start"], int) and isinstance(row["line_end"], int), (
        "AC3: neither field may leave the parser as a non-int"
    )
    assert row["line_end"] >= row["line_start"], (
        f"line_end must be clamped to at least line_start; got {row['line_end']} < 55"
    )


def test_line_numbers_are_never_negative():
    """AC3 / B4 — both fields are `>= 0`. A negative index silently addresses the
    END of a Python list, so a negative line would read the wrong code rather
    than fail."""
    row = _one('[{"title":"t","file_path":"a.ts","line_start":-5,"line_end":-9}]')

    assert row["line_start"] >= 0, f"line_start must be >= 0, got {row['line_start']}"
    assert row["line_end"] >= 0, f"line_end must be >= 0, got {row['line_end']}"
    assert row["line_end"] >= row["line_start"], "the clamp holds for negatives too"


def test_junk_line_start_becomes_the_default_not_a_dropped_row():
    """RECALL: an unparseable line number costs the LINE, never the FINDING."""
    row = _one('[{"title":"t","file_path":"a.ts","line_start":"somewhere near the top"}]')
    assert row["line_start"] == 0
    assert row["title"] == "t", "the row itself must survive its bad line number"


def test_coerce_lines_switch_is_read_at_call_time(monkeypatch):
    """`VULTURE_LLM_COERCE_LINES=false` restores the verbatim line copy (§5.9),
    read per call."""
    from shared.audit_runner import _parse_llm_findings

    output = '[{"title":"t","file_path":"a.ts","line_start":"55","line_end":3}]'

    assert _one(output)["line_start"] == 55, "coercion defaults ON"

    monkeypatch.setenv("VULTURE_LLM_COERCE_LINES", "false")
    reverted = _parse_llm_findings(output)
    assert len(reverted) == 1
    assert reverted[0]["line_start"] == "55", (
        "the rollback switch must restore the pre-0076 verbatim copy"
    )

    monkeypatch.setenv("VULTURE_LLM_COERCE_LINES", "true")
    assert _one(output)["line_start"] == 55, "no module reload may be required"


# ─────────────────────────────────────────────────────────────────────────────
# AC5 — a model-volunteered `code_snippet` is stripped on BOTH parse paths
# ─────────────────────────────────────────────────────────────────────────────

def test_model_authored_code_snippet_is_stripped_on_the_structured_path(monkeypatch):
    """T1.4 / AC5 / B3 — the A2/B3 asymmetry, structured half.

    `_parse_llm_result:2412-2416` calls `model_dump()` and bypasses
    `_normalize_finding` entirely, so on THIS branch a model-authored
    `code_snippet` survives — it displaces the source-read window, is fed to L5
    as if it were grounded evidence, and scores `+3` in the Go winner selection
    (`stream_handler.go:1040`). A model-authored string is currently
    indistinguishable from a file read.

    Endpoint pinned per D7: the structured branch is live only when
    `OPENAI_BASE_URL` is unset.
    """
    row = _parse_structured(monkeypatch, **_MODEL_ROW)

    assert not row.get("code_snippet"), (
        "a model-authored code_snippet must not survive the structured parse; "
        f"got {row.get('code_snippet')!r}"
    )
    assert not row.get("check_id"), (
        "a model-authored check_id must not survive the structured parse; "
        f"got {row.get('check_id')!r}"
    )
    assert row["title"] == _MODEL_ROW["title"], "the finding itself is not discarded"
    assert row["severity"] == "high"


def test_model_authored_code_snippet_is_stripped_on_the_unstructured_path(monkeypatch):
    """T1.4 / AC5 — the unstructured half, endpoint pinned the other way (D7).

    The snippet here embeds `[{ id: 1 }]` on purpose: the two defects compose,
    and this row is lost entirely today rather than merely leaking a field.
    """
    output = (
        '[{"title":"Injected row","file_path":"src/a.ts",'
        '"code_snippet":"const rows = [{ id: 1 }]",'
        '"check_id":"model.invented"}]'
    )
    rows = _parse_unstructured(monkeypatch, output)

    assert len(rows) == 1, f"the row must parse despite the braced snippet, got {rows!r}"
    assert not rows[0].get("code_snippet"), "no model-authored snippet on this path either"
    assert not rows[0].get("check_id"), "no model-authored check_id on this path either"


def test_trust_model_snippet_switch_is_read_at_call_time(monkeypatch):
    """`VULTURE_LLM_TRUST_MODEL_SNIPPET` (default false, truthy-set) restores the
    pre-0076 behaviour, per call (§5.9)."""
    assert not _parse_structured(monkeypatch, **_MODEL_ROW).get("code_snippet")

    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_SNIPPET", "true")
    restored = _parse_structured(monkeypatch, **_MODEL_ROW)
    assert restored.get("code_snippet") == _MODEL_ROW["code_snippet"], (
        "the rollback switch must return the model's own snippet"
    )

    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_SNIPPET", "false")
    assert not _parse_structured(monkeypatch, **_MODEL_ROW).get("code_snippet"), (
        "read at call time — flipping back must not need a module reload"
    )


def test_the_two_forbidden_field_sets_are_disjoint():
    """"TWO fields, TWO switches — they are not the same risk" (§5.1, recall-3).

    `code_snippet` is a fabricated-evidence risk; `check_id` is a DEDUP IDENTITY
    whose removal deletes rows (AC26). Collapsing them into one constant makes
    it impossible for an operator to reverse the dedup regression without also
    re-trusting model-authored evidence.
    """
    from shared.audit_runner import _MODEL_FORBIDDEN_CHECK_ID, _MODEL_FORBIDDEN_SNIPPET

    assert "code_snippet" in _MODEL_FORBIDDEN_SNIPPET
    assert "check_id" in _MODEL_FORBIDDEN_CHECK_ID
    assert "check_id" not in _MODEL_FORBIDDEN_SNIPPET, (
        "the snippet switch must not also govern check_id — they are separate reversals"
    )
    assert "code_snippet" not in _MODEL_FORBIDDEN_CHECK_ID, (
        "the check_id switch must not also govern code_snippet"
    )


def test_finding_keys_names_the_findings_shape_and_not_the_decoy_shape():
    """`_FINDING_KEYS` is the evidence the scorer weighs. `id` — the decoy's only
    key — must not be in it, or `[{"id":1},{"id":2},{"id":3}]` becomes a
    candidate and the ranking guard above is defeated at its source."""
    from shared.audit_runner import _FINDING_KEYS

    for key in (
        "title", "severity", "category", "file_path", "line_start",
        "line_end", "description", "recommendation", "evidence_quote",
    ):
        assert key in _FINDING_KEYS, f"{key} is part of the findings shape"
    assert "id" not in _FINDING_KEYS, (
        "an everyday non-finding key must never make an array look like a payload"
    )


# ─────────────────────────────────────────────────────────────────────────────
# AC26 — stripping `check_id` changes the post-dedup finding count by ZERO
# ─────────────────────────────────────────────────────────────────────────────

def test_a_naive_check_id_strip_would_delete_the_llm_row():
    """The defect AC26 exists to prevent, demonstrated on the real `_dedup_key`.

    This is a CONTROL, not a requirement on new code: it shows that a row which
    has lost its `check_id` and kept nothing in its place collides with the
    skill row and is deleted by `_deduplicate_findings`. Without this assertion
    the AC26 test below looks like it is proving something that was never at
    risk.
    """
    from shared.audit_runner import _dedup_key, _deduplicate_findings

    naively_stripped = {k: v for k, v in _MODEL_ROW.items() if k != "check_id"}

    assert _dedup_key(naively_stripped) == _dedup_key(_SKILL_ROW), (
        "the strip re-keys the LLM row onto the skill row's (title, path) key"
    )
    assert _deduplicate_findings([_SKILL_ROW], [naively_stripped], "") == [], (
        "and the LLM row is then dropped — a deletion, in a feature whose "
        "commitment is that nothing is deleted"
    )


def test_stripping_check_id_changes_no_finding_count(monkeypatch):
    """T1.10 / AC26 — the recall invariant, measured as a count.

    Same two rows as the control above, but the LLM row now goes through the
    real parse path. The strip must preserve the identity as `_model_check_id`
    and `_dedup_key` must fall back to it, so the survivor count is IDENTICAL to
    what it is with `VULTURE_LLM_TRUST_MODEL_CHECK_ID=true` (no strip at all).
    """
    from shared.audit_runner import _deduplicate_findings

    stripped = _parse_structured(monkeypatch, **_MODEL_ROW)
    stripped_survivors = _deduplicate_findings([_SKILL_ROW], [stripped], "")

    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_CHECK_ID", "true")
    trusted = _parse_structured(monkeypatch, **_MODEL_ROW)
    trusted_survivors = _deduplicate_findings([_SKILL_ROW], [trusted], "")

    assert len(stripped_survivors) == len(trusted_survivors) == 1, (
        "AC26: stripping the model's check_id must change the post-dedup count "
        f"by ZERO; stripped={len(stripped_survivors)} trusted={len(trusted_survivors)}"
    )


def test_the_stripped_identity_is_preserved_as_model_check_id(monkeypatch):
    """The mechanism behind AC26, asserted directly so a regression names itself.

    The model's string stops being trusted as a CATALOG id downstream (C7: it is
    never persisted anyway) while remaining the row's dedup identity.
    """
    from shared.audit_runner import _dedup_key

    row = _parse_structured(monkeypatch, **_MODEL_ROW)

    assert row.get("_model_check_id") == _MODEL_ROW["check_id"], (
        "the stripped value must be retained privately, not discarded"
    )
    assert _dedup_key(row)[0] == _MODEL_ROW["check_id"], (
        "_dedup_key must fall back to _model_check_id BEFORE the normalised title"
    )
    assert _dedup_key(row) != _dedup_key(_SKILL_ROW), (
        "so the row keeps the identity it had and does not collide with the skill row"
    )


def test_trust_model_check_id_restores_the_prior_keying(monkeypatch):
    """`VULTURE_LLM_TRUST_MODEL_CHECK_ID=true` (§5.9) reverses P1's strip on its
    own, read at call time."""
    from shared.audit_runner import _dedup_key

    assert not _parse_structured(monkeypatch, **_MODEL_ROW).get("check_id")

    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_CHECK_ID", "true")
    trusted = _parse_structured(monkeypatch, **_MODEL_ROW)
    assert trusted.get("check_id") == _MODEL_ROW["check_id"], (
        "the switch must restore the model-authored check_id verbatim"
    )
    assert _dedup_key(trusted)[0] == _MODEL_ROW["check_id"], "and with it the prior keying"

    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_CHECK_ID", "false")
    assert not _parse_structured(monkeypatch, **_MODEL_ROW).get("check_id"), (
        "flipping back must take effect with no module reload"
    )


def test_trust_model_check_id_does_not_also_restore_the_snippet(monkeypatch):
    """§5.1, stated as the reason the two switches are separate: an operator who
    hits a dedup regression can reverse exactly that "without also restoring
    model-authored snippets"."""
    monkeypatch.setenv("VULTURE_LLM_TRUST_MODEL_CHECK_ID", "true")
    row = _parse_structured(monkeypatch, **_MODEL_ROW)

    assert row.get("check_id") == _MODEL_ROW["check_id"]
    assert not row.get("code_snippet"), (
        "restoring the dedup identity must not re-open the fabricated-evidence channel"
    )
