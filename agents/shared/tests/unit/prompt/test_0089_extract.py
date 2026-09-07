"""Feature 0089 Phase 0.c — `shared.prompt.extract`, the SUPERSET extractor.

WHY THIS FILE EXISTS. Three separate parsers grew up around the same problem
("get the JSON out of a model's chat response"): `audit_runner`'s findings-array
chain (0076 §5.1), `prove_agent.llm_helper._extract_json`, and the L5 judge's
own object reader. §11.3 unifies them into ONE strategy list. A unification that
loses a single response shape is a coverage regression nobody would notice until
a scan came back thin, so the first test here is a REGRESSION GUARD, not a
feature test: every parser fixture found in `agents/shared/tests`,
`agents/prove/tests` and `agents/discover/tests` is replayed against the new
module and must produce what the shipped implementations produce today.

The expected values below were CAPTURED by running the pre-move implementations
(`shared.audit_runner._extract_finding_rows` and
`prove_agent.llm_helper._extract_json`) over these inputs, not hand-written.
They are the behaviour being preserved.

TWO DELIBERATE CHANGES, each pinned by its own test below, neither of which any
fixture in the superset table exercises:

  1. `_fenced_json_rows` returns `None`, not `[]`, when the fenced block parsed
     but held no dicts — so one throwaway fenced array before the real payload
     no longer stops the strategy chain at the first non-`None`.
  2. A new FIRST strategy strips `<think>` reasoning — closed blocks AND an
     unclosed leading `<think>` with no terminator, which is what a response
     truncated inside its reasoning looks like. Without it, an array the model
     drafted INSIDE its thinking is scored against the real answer and can win
     on key evidence.

The strip can never LOSE a finding: a strategy that yields nothing returns
`None` and the chain re-runs on the ORIGINAL text.

API NOTE. `extract_object` returns `dict | None` where prove's `_extract_json`
returns `{}` for both "an empty object" and "no object at all" — the caller
cannot tell those apart today. The superset assertions therefore compare
`extract_object(text) or {}`, which is exactly prove's contract.
"""

from __future__ import annotations

import json

import pytest

from shared.prompt.extract import _extract_finding_rows, extract_object, extract_rows

# ─────────────────────────────────────────────────────────────────────────────
# Superset fixtures — (input, output of the CURRENT shipped implementation).
# Findings-array shapes, gathered from tests/unit/test_0076_parser.py,
# tests/unit/test_audit_runner.py and tests/unit/test_0089_prereqs_runner.py.
# `None` there means "no strategy matched"; `extract_rows` flattens that to [].
# ─────────────────────────────────────────────────────────────────────────────

_REAL_PAYLOAD = (
    '[{"severity":"high","category":"cwe","title":"SQL injection",'
    '"description":"d","file_path":"src/db.py","line_start":42,"line_end":42,'
    '"recommendation":"r","evidence_quote":"cursor.execute(q + uid)"}]'
)
_REAL_ROW = {
    "severity": "high", "category": "cwe", "title": "SQL injection",
    "description": "d", "file_path": "src/db.py", "line_start": 42,
    "line_end": 42, "recommendation": "r",
    "evidence_quote": "cursor.execute(q + uid)",
}
_ZERO_KEY_DECOY = '[{"id":1},{"id":2},{"id":3}]'
_WEAK_MULTI_ROW_DECOY = '[{"title":"a"},{"title":"b"},{"title":"c"}]'

_ROW_FIXTURES: dict[str, tuple[str, list[dict]]] = {
    # AC1 — a quote containing `}]` must not truncate the batch.
    "braced_batch": (
        '[{"title":"a","evidence_quote":"const rows = [{ id: 1 }]"},{"title":"b"}]',
        [{"title": "a", "evidence_quote": "const rows = [{ id: 1 }]"}, {"title": "b"}],
    ),
    # AC2 — a dict entry survives its junk neighbours.
    "mixed_array": (
        '[{"severity": "high", "title": "Real"}, "not a dict", 42]',
        [{"severity": "high", "title": "Real"}],
    ),
    "real_payload": (_REAL_PAYLOAD, [_REAL_ROW]),
    # Scored to `None` — a decoy with no finding key is not a candidate.
    "zero_key_decoy": (_ZERO_KEY_DECOY, []),
    # Ranked but returned in full: sloppy rows are still findings.
    "weak_multi_row_decoy": (
        _WEAK_MULTI_ROW_DECOY,
        [{"title": "a"}, {"title": "b"}, {"title": "c"}],
    ),
    # Salvage: cut at VULTURE_LLM_MAX_OUTPUT_TOKENS, no `]` anywhere.
    "truncated_batch": (
        '[\n'
        '  {"severity":"high","title":"Missing timeout","file_path":"src/a.ts","line_start":10},\n'
        '  {"severity":"low","title":"Unbounded retry","file_path":"src/b.ts","line_start":20},\n'
        '  {"severity":"medium","title":"Partial ro',
        [
            {"severity": "high", "title": "Missing timeout",
             "file_path": "src/a.ts", "line_start": 10},
            {"severity": "low", "title": "Unbounded retry",
             "file_path": "src/b.ts", "line_start": 20},
        ],
    ),
    # The fenced block is tried FIRST: it wins although the bare array scores higher.
    "fenced_wins_over_bare": (
        '```json\n[{"title":"fenced","severity":"high","file_path":"a.ts"}]\n```\n\n'
        f'Restated: {_REAL_PAYLOAD}',
        [{"title": "fenced", "severity": "high", "file_path": "a.ts"}],
    ),
    "decoy_first_zero_key": (f"For example: {_ZERO_KEY_DECOY}\n\n{_REAL_PAYLOAD}", [_REAL_ROW]),
    "decoy_first_weak": (f"{_WEAK_MULTI_ROW_DECOY}\n\n{_REAL_PAYLOAD}", [_REAL_ROW]),
    "decoy_last_zero_key": (f"{_REAL_PAYLOAD}\n\nCompare with {_ZERO_KEY_DECOY}", [_REAL_ROW]),
    "decoy_last_weak": (f"{_REAL_PAYLOAD}\n\n{_WEAK_MULTI_ROW_DECOY}", [_REAL_ROW]),
    # Ties break to the LAST candidate — a restated answer is the corrected one.
    "restated_tie": (
        '[{"title":"first","severity":"high","file_path":"a.ts"}]\n'
        'On reflection:\n'
        '[{"title":"second","severity":"high","file_path":"a.ts"}]',
        [{"title": "second", "severity": "high", "file_path": "a.ts"}],
    ),
    "prose_only": ("I found no issues in the codebase.", []),
    "prose_with_string_array": ('I looked at ["a","b"] and found nothing.', []),
    "fenced_single": (
        '```json\n[{"severity": "high", "title": "SQL Injection", "category": "injection"}]\n```',
        [{"severity": "high", "title": "SQL Injection", "category": "injection"}],
    ),
    "bare_after_prose": (
        'I found: [{"severity": "medium", "title": "Debug Mode"}]',
        [{"severity": "medium", "title": "Debug Mode"}],
    ),
    "malformed_fence": ('```json\n[{"broken json\n```', []),
    "fenced_multi": (
        '```json\n[\n'
        '  {"severity": "high", "title": "Finding 1"},\n'
        '  {"severity": "low", "title": "Finding 2"},\n'
        '  {"severity": "critical", "title": "Finding 3"}\n'
        ']\n```',
        [
            {"severity": "high", "title": "Finding 1"},
            {"severity": "low", "title": "Finding 2"},
            {"severity": "critical", "title": "Finding 3"},
        ],
    ),
    # The compliant "nothing found", in each shape a model actually writes.
    "empty_bare": ("[]", []),
    "empty_spaced": ("[ ]", []),
    "empty_newline": ("[\n]", []),
    "empty_unlabelled_fence": ("```\n[]\n```", []),
    "wrapped_empty_bare": ('{"findings": []}', []),
    "wrapped_empty_fenced": ('```json\n{"findings": []}\n```', []),
    "wrapped_rows": (
        '{"findings": [{"severity":"high","title":"x","file_path":"a.py"}]}',
        [{"severity": "high", "title": "x", "file_path": "a.py"}],
    ),
    # Bounds on the last-resort strategy: not any old JSON is an answer.
    "not_a_findings_object": ('{"status": "ok"}', []),
    "json_string": ('"a string"', []),
    "json_null": ("null", []),
    "json_number": ("42", []),
    "ts_literal_prose": ('const rows = [{"id":1}]', []),
    "empty_text": ("", []),
    "whitespace_text": ("   \n  ", []),
}

# Single-object shapes, gathered from agents/prove/tests/unit/test_llm_helper.py
# (`_extract_json`). agents/discover/tests has no LLM-response parser fixtures —
# discover's JSON reads are of its own learning store, not of model output.
_OBJECT_FIXTURES: dict[str, tuple[str, dict]] = {
    "plain_json": (
        '{"url_path": "/api/test", "method": "GET"}',
        {"url_path": "/api/test", "method": "GET"},
    ),
    "empty_object": ("{}", {}),
    "nested_object": (
        '{"headers": {"Content-Type": "application/json"}, "method": "POST"}',
        {"headers": {"Content-Type": "application/json"}, "method": "POST"},
    ),
    "empty_string": ("", {}),
    "think_tags": (
        '<think>Let me think about this...</think>{"url_path": "/login"}',
        {"url_path": "/login"},
    ),
    "multiline_think": (
        "<think>\nStep 1: Analyze the finding\nStep 2: Build the request\n</think>\n"
        '{"url_path": "/api/users", "method": "POST"}',
        {"url_path": "/api/users", "method": "POST"},
    ),
    "output_tags": ('<output>{"url_path": "/test"}</output>', {"url_path": "/test"}),
    "thinking_process_preamble": (
        "Thinking Process:\n\n1. **Analyze the Request:**\n"
        "   * Role: Security Tester.\n   * Task: Create an HTTP request.\n\n"
        '{"url_path": "/api/login", "method": "POST", "description": "Test SQL injection"}',
        {"url_path": "/api/login", "method": "POST", "description": "Test SQL injection"},
    ),
    "analysis_preamble": (
        "Analysis:\nThe finding describes a hardcoded credential.\n\n"
        '{"url_path": "/api/auth", "method": "GET"}',
        {"url_path": "/api/auth", "method": "GET"},
    ),
    "reasoning_preamble": (
        'Reasoning: I need to test this endpoint.\n{"url_path": "/health"}',
        {"url_path": "/health"},
    ),
    "let_me_preamble": (
        'Let me analyze this security finding...\n{"verdict": "confirmed"}',
        {"verdict": "confirmed"},
    ),
    "step_by_step_preamble": (
        'Step-by-Step analysis:\n1. Check the endpoint\n{"url_path": "/test"}',
        {"url_path": "/test"},
    ),
    "json_code_fence": ('```json\n{"url_path": "/api/test"}\n```', {"url_path": "/api/test"}),
    "plain_code_fence": ('```\n{"method": "POST"}\n```', {"method": "POST"}),
    "preamble_plus_code_fence": (
        'Here is the JSON:\n```json\n{"url_path": "/login"}\n```',
        {"url_path": "/login"},
    ),
    "deeply_nested": (
        'Some text before\n{"headers": {"Authorization": "Bearer token", '
        '"X-Custom": {"nested": true}}, "method": "GET"}',
        {"headers": {"Authorization": "Bearer token", "X-Custom": {"nested": True}},
         "method": "GET"},
    ),
    "braces_in_strings": (
        '{"description": "Test {injection} payload", "url_path": "/api"}',
        {"description": "Test {injection} payload", "url_path": "/api"},
    ),
    "json_after_garbage": ('Not JSON at all. Random text.\n{"found": true}', {"found": True}),
    "no_json_at_all": ("This is just plain text with no braces.", {}),
    "truncated_json": ('{"url_path": "/api/test", "headers": {"Auth', {}),
}


@pytest.mark.parametrize("name", sorted(_ROW_FIXTURES))
def test_extract_superset(name):
    """THE regression guard: every known response shape, unchanged.

    Split per fixture so a failure names the shape that regressed rather than
    the first one in an all-at-once loop.
    """
    text, expected = _ROW_FIXTURES[name]
    assert extract_rows(text) == expected, (
        f"row fixture {name!r} must extract exactly what the shipped "
        f"audit_runner chain extracts today"
    )


@pytest.mark.parametrize("name", sorted(_OBJECT_FIXTURES))
def test_extract_superset_objects(name):
    """The same guard for the single-object path prove and discover need."""
    text, expected = _OBJECT_FIXTURES[name]
    assert (extract_object(text) or {}) == expected, (
        f"object fixture {name!r} must extract exactly what prove's "
        f"_extract_json extracts today"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Change 2 — `<think>` reasoning is stripped BEFORE anything is ranked
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_think_block_does_not_outrank_real_answer():
    """A draft array inside `<think>` must never beat the answer outside it.

    The drafted row carries all nine finding keys and the real answer carries
    three, so `_score_array` prefers the DRAFT: key evidence dominates row
    count, and the thinking block is where a model writes its most complete
    JSON. Measured against the shipped chain, this input returns the draft and
    the real finding is lost.
    """
    output = (
        "<think>\nLet me draft the finding first:\n"
        f"{_REAL_PAYLOAD}\n"
        "On reflection the path was wrong.\n</think>\n\n"
        '[{"title":"real","severity":"high","file_path":"src/actual.py"}]'
    )
    assert extract_rows(output) == [
        {"title": "real", "severity": "high", "file_path": "src/actual.py"},
    ], "the answer after </think> is the answer; the draft inside it is not"


def test_extract_unclosed_think_is_stripped():
    """A response truncated inside its reasoning never emits `</think>`.

    Nothing closes the tag, so a `</think>`-only strip leaves the whole draft
    in play and it outranks the answer exactly as above. The unclosed opener
    must be dropped together with the reasoning prose that follows it.
    """
    output = (
        "<think>\nFirst pass, probably wrong:\n"
        f"{_REAL_PAYLOAD}\n"
        "Actually the vulnerable call is elsewhere.\n\n"
        '[{"title":"real","severity":"high","file_path":"src/actual.py"}]'
    )
    assert extract_rows(output) == [
        {"title": "real", "severity": "high", "file_path": "src/actual.py"},
    ], "an unclosed <think> is still reasoning, not the answer"


def test_extract_think_strip_never_loses_the_only_answer():
    """The safety property that makes stripping admissible at all.

    When the ONLY findings array is inside the reasoning, the strip yields
    nothing, that strategy returns `None`, and the chain re-runs on the
    original text — so the finding still comes back. A strip that could delete
    the sole answer would be a coverage regression, not a fix.
    """
    output = f"<think>\nThe issue is:\n{_REAL_PAYLOAD}\n</think>\n\nI am done."
    assert extract_rows(output) == [_REAL_ROW], (
        "stripping reasoning must re-rank candidates, never remove the last one"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Change 1 — an empty fenced array must not stop the strategy chain
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_empty_fenced_array_does_not_stop_the_chain():
    """`_extract_finding_rows` stops at the first NON-`None` strategy.

    A fenced block that parsed to zero dicts returned `[]` today, which is
    "answered, nothing found" — so a throwaway fenced array printed before the
    real payload discarded the real findings, whole batch. "The fence held no
    findings" and "there are no findings" are different answers.
    """
    output = (
        "Here is the schema I was given:\n```json\n[]\n```\n\n"
        f"And the findings:\n{_REAL_PAYLOAD}"
    )
    assert extract_rows(output) == [_REAL_ROW], (
        "an empty fenced array is not an answer; the chain must continue"
    )


def test_extract_a_fenced_array_of_non_dicts_also_continues():
    """The same rule for the other zero-dict shape: a fenced list of strings.

    `_only_dicts` empties it, and an emptied list is indistinguishable from a
    compliant `[]` — both must fall through rather than shadow the payload.
    """
    output = f'```json\n["src/a.py", "src/b.py"]\n```\n\n{_REAL_PAYLOAD}'
    assert extract_rows(output) == [_REAL_ROW]


def test_extract_a_lone_empty_fenced_array_is_still_nothing_found():
    """And the bound on change 1: falling through must not invent a finding.

    A fence holding only `[]`, with nothing after it, still extracts zero rows
    — the last-resort empty-array strategy answers it. Change 1 moves WHICH
    strategy answers, never the answer.
    """
    assert extract_rows("```json\n[]\n```") == []


# ─────────────────────────────────────────────────────────────────────────────
# Change 1's blind spot — found by the 0.c check pass, and the reason
# `_empty_array_answer` cannot stay anchored to the WHOLE response
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_fenced_empty_array_in_prose_is_still_an_answer():
    """"Nothing found" must survive one sentence of prose around the fence.

    Change 1 turned a fenced zero-dict array from "answered, nothing found"
    into "no strategy matched", and `_empty_array_answer` — the strategy that
    was supposed to catch the fallout — only recognises a fence that IS the
    whole response (`_ANY_FENCE_RE` is `^`/`$` anchored). So the everyday clean
    answer

        Here are the results:
        ```json
        []
        ```

    parsed to `[]` before change 1 and to `None` after it. `None` is a CONTRACT
    breach: `_unparsed_error` turns it into an `error`, three of them in a row
    abort the sweep, and the remaining batches are never analysed — the exact
    17-of-20-batch loss `_empty_array_answer` was written to prevent, re-opened
    in a narrower shape.

    `_extract_finding_rows`, not `extract_rows`, because the two answers this
    is about — `[]` and `None` — both flatten to `[]` for the row-only caller.
    """
    for text in (
        "Here are the results:\n```json\n[]\n```",
        "```json\n[]\n```\n\nNo issues in this batch.",
        "Schema:\n```json\n[]\n```\n\nAnd nothing to report.",
        '```json\n["src/a.py", "src/b.py"]\n```\n\nNone of those had issues.',
    ):
        assert _extract_finding_rows(text) == [], (
            f"a fenced empty array is an ANSWER, not an unparseable response: {text!r}"
        )


def test_extract_fenced_empty_array_in_prose_does_not_trip_the_p5_abort():
    """The same defect at the boundary that pays for it (0089 P5).

    `_parse_llm_findings` books `parsed=False` on a `None` extraction, and
    `_unparsed_error` turns that into the non-empty `error` string that
    `VULTURE_LLM_MAX_CONSECUTIVE_FAILURES` counts. A clean batch must not be
    counted as a failed one.
    """
    from shared import audit_runner

    outcome = audit_runner._parse_llm_findings("Here are the results:\n```json\n[]\n```")
    assert outcome.rows == []
    assert outcome.parsed is True, "a prose-wrapped empty array is a clean batch"
    assert audit_runner._unparsed_error(outcome) is None


def test_extract_think_strip_does_not_mangle_a_quote_that_contains_the_tag():
    """Change 2's blind spot: `<think>` inside the PAYLOAD, not around it.

    0076 makes `evidence_quote` VERBATIM SOURCE, and this repo's own source
    contains `re.sub(r"<think>.*?</think>", ...)` — `prove_agent/llm_helper.py`
    line 260, the very code change 2 extends. An unconditional string transform
    over the whole response therefore reaches INSIDE the JSON string of a real
    finding and empties it. The array still decodes, so nothing raises: the
    finding is kept and its evidence is silently replaced by
    `re.sub(r"", "", ...)`.

    That is worse than losing the row. 0076's anchor verifier searches the cited
    file for the quote, so a mangled quote turns status `exact` into `absent` —
    and with `VULTURE_LLM_QUOTE_DEMOTE_ABSENT=true` `absent` carries weight
    -1.0, driving a TRUE finding's confidence to 0.0.

    A `<think>` opener inside a JSON payload is always mid-line: a JSON string
    cannot contain a raw newline, so no line inside a decoded payload can begin
    with the tag. Anchoring the strip at a line start is therefore enough, and
    still covers every shape a reasoning model actually emits.
    """
    quote = 'text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)'
    payload = json.dumps([{
        "severity": "low", "category": "cwe", "title": "Unbounded regex",
        "file_path": "prove_agent/llm_helper.py", "line_start": 260,
        "line_end": 260, "description": "d", "recommendation": "r",
        "evidence_quote": quote,
    }])

    for text in (payload, f"```json\n{payload}\n```"):
        rows = extract_rows(text)
        assert len(rows) == 1, f"the finding itself must survive: {text[:40]!r}"
        assert rows[0]["evidence_quote"] == quote, (
            "the reasoning strip must not reach inside a payload string"
        )


def test_extract_think_strip_still_wins_when_the_tag_opens_a_line():
    """The bound on the fix: change 2 must keep working where it matters.

    Every shape a reasoning model actually emits opens the block at the start of
    a line — either the first character of the response or its own line — so
    line-anchoring costs change 2 nothing.
    """
    real = '[{"title":"real","severity":"high","file_path":"src/actual.py"}]'
    expected = [{"title": "real", "severity": "high", "file_path": "src/actual.py"}]

    own_line = f"<think>\nDraft:\n{_REAL_PAYLOAD}\nWrong path.\n</think>\n\n{real}"
    indented = f"  <think>\nDraft:\n{_REAL_PAYLOAD}\n</think>\n\n{real}"
    inline_close = f"<think>Draft: {_REAL_PAYLOAD} — wrong.</think>\n{real}"

    for name, text in (
        ("own_line", own_line), ("indented", indented), ("inline_close", inline_close),
    ):
        assert extract_rows(text) == expected, f"{name}: the draft must not win"
