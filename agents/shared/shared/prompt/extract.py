"""Superset extractor for LLM chat responses — feature 0089 §11.3.

ONE strategy list, replacing three that grew up independently around the same
problem: `audit_runner`'s findings-array chain (feature 0076 §5.1),
`prove_agent.llm_helper._extract_json`, and the L5 judge's object reader. The
findings chain is MOVED here verbatim — every ranking, tie-break, salvage and
empty-answer decision it encodes was paid for in measured whole-batch losses,
and re-deriving them would re-lose them.

Two things changed in the move, each because it costs findings today:

1. `_fenced_json_rows` returns `None`, not `[]`, when the fenced block parsed
   but held no dicts. `_extract_finding_rows` stops at the first non-`None`, so
   `[]` meant "answered, nothing found" and one throwaway fenced array printed
   before the real payload discarded the whole batch. `_fenced_empty_array_answer`
   runs DEAD LAST to catch the fallout: with no payload anywhere else, a fenced
   empty array is still the answer "nothing found", one sentence of surrounding
   prose included.

2. `_think_stripped_rows` runs FIRST. A reasoning model drafts its most
   complete JSON inside `<think>`, and key evidence dominates row count, so an
   abandoned draft outranks the real answer. Both shapes are stripped: the
   closed block, and an unclosed leading `<think>` with no terminator, which is
   what a response truncated inside its reasoning looks like.

The strip cannot lose a finding. A strategy that yields nothing returns `None`
and the chain re-runs on the ORIGINAL text, so when the only array is inside
the reasoning it is still extracted.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Generator
from typing import Any

from shared.env import env_flag

logger = logging.getLogger(__name__)

# Pre-compiled patterns for _parse_llm_findings (avoid per-call re.compile).
# The BARE pattern is no longer part of the default attempt order (feature 0076
# B1): a non-greedy ``}\s*]`` cannot survive a string value that itself contains
# ``}]``, and ``[{ id: 1 }]`` is an everyday TS/JSX literal — so a model quoting
# such a line loses the WHOLE batch. ``_scan_json_arrays`` replaces it;
# ``VULTURE_LLM_JSON_SCAN=false`` puts the regex back.
_LLM_JSON_FENCED_RE = re.compile(r"```json\s*(\[.*?\])\s*```", re.DOTALL)
_LLM_JSON_BARE_RE = re.compile(r"(\[\s*\{.*?\}\s*\])", re.DOTALL)

# A whole-response code fence, label optional — see `_strip_code_fence`.
_ANY_FENCE_RE = re.compile(r"^```[A-Za-z0-9_+-]*\s*(.*?)\s*```$", re.DOTALL)

# The keys that make a decoded array look like a findings payload. `id` is
# deliberately absent: it is the only key of the everyday decoy
# ``[{"id":1},{"id":2},{"id":3}]``, and admitting it would let a three-row TS
# example in model prose outrank the real one-row answer.
_FINDING_KEYS = frozenset({
    "title", "severity", "category", "file_path", "line_start",
    "line_end", "description", "recommendation", "evidence_quote",
})



def _extract_finding_rows(output: str) -> list[dict] | None:
    """The first attempt that produces a row list wins; ``None`` when none does.

    ``None`` rather than ``[]`` because a strategy that succeeds with zero rows
    (``[]`` from a compliant model) and no strategy matching at all are opposite
    outcomes for :class:`ParseOutcome`.

    0089 §11.3 prepends `_think_stripped_rows` to the order and leaves the rest
    of it untouched — the reasoning strip can only replace the candidate the
    reasoning supplied, so a response with no `<think>` in it is unaffected.
    """
    return _first_match(output, _ROW_STRATEGIES)


def _empty_array_answer(output: str) -> list[dict] | None:
    """LAST resort: a response that IS an empty JSON array — "nothing found".

    ``_score_array`` rejects a zero-hit array so a prose decoy cannot shadow a
    real payload, and ``[]`` has zero hits — so the compliant empty answer left
    ``_extract_finding_rows`` as "no strategy matched", which P5 now reads as an
    LLM contract FAILURE. Measured: a 20-batch sweep over a clean tree, model
    answering a bare ``[]``, aborted at batch 3/20 and lost 17 batches. Only the
    ```` ```json ```` fence was covered; a bare or unlabelled-fence ``[]`` was not.

    Runs last and yields only ``[]``, so it can neither add nor drop a finding:
    it decides ``parsed``, nothing else.
    """
    body = _strip_code_fence(output.strip())
    return [] if _is_empty_payload(_try_decode(body, 0)) else None


def _fenced_empty_array_answer(output: str) -> list[dict] | None:
    """Change 1's other half: a fenced array that held no dict, ANYWHERE.

    `_empty_array_answer` only recognises a fence that IS the whole response —
    `_ANY_FENCE_RE` is `^`/`$` anchored — so once change 1 stopped
    `_fenced_json_rows` answering `[]`, the everyday clean answer

        Here are the results:
        ```json
        []
        ```

    stopped being an answer at all and became `None`. `None` is a CONTRACT
    breach: `_unparsed_error` turns it into the `error` string that
    `VULTURE_LLM_MAX_CONSECUTIVE_FAILURES` counts, three clean batches in a row
    abort the sweep, and the rest of the tree is never analysed — the 17-of-20
    batch loss `_empty_array_answer` exists to prevent, re-opened in a narrower
    shape.

    Runs DEAD LAST, after the scan and the salvage, so change 1 keeps its point:
    a real payload elsewhere in the response still wins. Like
    `_empty_array_answer` it yields only ``[]``, so it can neither add nor drop
    a finding — it decides ``parsed``, nothing else.
    """
    match = _LLM_JSON_FENCED_RE.search(output)
    if match is None:
        return None
    return [] if _dict_rows(_loads_list(match.group(1))) == [] else None


def _is_empty_payload(value: Any) -> bool:
    """Does this decoded response carry a findings array, and is it empty?

    The wrapper arm exists because the two halves of ``{"findings": [...]}`` are
    treated OPPOSITELY today: with rows, ``_scan_json_arrays`` reaches the inner
    array and parses; with none, the zero-hit score rejects it. A model that
    always wraps then works on dirty batches and fails on clean ones.

    Deliberately NOT "any well-formed JSON is an answer": the response must
    actually contain an empty array, or the contract-failure signal P5 exists
    for is gone.
    """
    if isinstance(value, list):
        return not value
    if isinstance(value, dict):
        return any(item == [] for item in value.values())
    return False


def _strip_code_fence(body: str) -> str:
    """The inside of a whole-response code fence, labelled or not; *body* as-is
    when it is not fenced. ``_fenced_json_rows`` only knows the ```` ```json ````
    label, and a model that omits it is not thereby unparseable."""
    match = _ANY_FENCE_RE.match(body)
    return match.group(1).strip() if match is not None else body


def _loads_list(text: str | None) -> list | None:
    """``json.loads`` restricted to arrays; ``None`` on absent or invalid input."""
    if text is None:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, list) else None


def _only_dicts(value: list) -> list[dict]:
    """Every dict entry of a decoded array — RECALL, not ranking: a sloppy row
    such as ``{"title": "b"}`` is too key-poor to make an array look like a
    payload and is still a finding."""
    return [row for row in value if isinstance(row, dict)]


def _dict_rows(value: list | None) -> list[dict] | None:
    """:func:`_only_dicts`, tolerant of the "nothing decoded" signal."""
    if value is None:
        return None
    return _only_dicts(value)


def _fenced_json_rows(output: str) -> list[dict] | None:
    """The ```` ```json ... ``` ```` block — tried first, before any ranking.

    0089 §11.3 change 1: ``None`` when the block parsed but carried no dict, so
    the chain CONTINUES. ``_extract_finding_rows`` stops at the first non-
    ``None``, and a fenced block emptied by ``_only_dicts`` is indistinguishable
    from the compliant ``[]`` — so a model that fences a schema, an example or a
    list of file names before its real answer had the whole batch discarded. The
    lone fenced ``[]`` still reads as "nothing found": ``_empty_array_answer``
    answers it last (it fence-strips too), so change 1 moves which strategy
    answers, never the answer.
    """
    match = _LLM_JSON_FENCED_RE.search(output)
    if match is None:
        return None
    return _dict_rows(_loads_list(match.group(1))) or None


def _scanned_json_rows(output: str) -> list[dict] | None:
    """The brace-safe scan, or the pre-0076 regex under the rollback switch."""
    if _json_scan_enabled():
        return _scan_json_arrays(output)
    match = _LLM_JSON_BARE_RE.search(output)
    return _dict_rows(_loads_list(match.group(1) if match else None))


def _json_scan_enabled() -> bool:
    """``VULTURE_LLM_JSON_SCAN`` — default TRUE, read at call time (D14)."""
    return env_flag("VULTURE_LLM_JSON_SCAN", True)


def _json_salvage_enabled() -> bool:
    """``VULTURE_LLM_JSON_SALVAGE`` — default TRUE, read at call time (D14)."""
    return env_flag("VULTURE_LLM_JSON_SALVAGE", True)


def _try_decode(output: str, index: int) -> Any:
    """``raw_decode`` at *index*, or ``None`` when nothing valid starts there."""
    try:
        value, _end = json.JSONDecoder().raw_decode(output, index)
    except ValueError:
        return None
    return value


def _score_array(value: list) -> tuple[int, int, int] | None:
    """Rank a decoded array as a findings payload, or ``None`` if it is not one.

    KEY EVIDENCE DOMINATES ROW COUNT, and the ordering is load-bearing. Scored
    ``(len(rows), hits)`` instead, tuple comparison puts row count first and the
    three-row decoy ``[{"id":1},{"id":2},{"id":3}]`` — an everyday TS example in
    model prose, scoring ``(3, 3)`` — outranks the real one-row payload
    ``(1, 9)``, losing the whole batch in a new shape. Returning ``None`` for a
    zero-hit array is the other half: a decoy that carries no finding key is not
    a candidate at all, whatever the ordering downstream turns out to be.
    """
    hits = [_key_hits(row) for row in value]
    if not any(hits):
        return None
    return (_strong_rows(hits), sum(hits), len(_only_dicts(value)))


def _key_hits(row: Any) -> int:
    """Finding-shaped keys carried by one decoded entry; ``0`` for a non-dict."""
    if not isinstance(row, dict):
        return 0
    return len(_FINDING_KEYS & set(row))


def _strong_rows(hits: list[int]) -> int:
    """Rows carrying at least two finding keys — the DOMINANT evidence term."""
    return sum(1 for count in hits if count >= 2)


def _decoded_arrays(output: str) -> Generator[list, None, None]:
    """Every JSON array that decodes from a ``[`` in *output*, in order.

    Exact where the regex was heuristic. Scanning EVERY ``[`` rather than
    returning the first that decodes is a recall requirement: a model that opens
    with prose containing ``["a","b"]``, or whose quote holds ``[{ id: 1 }]``,
    would otherwise have its real payload shadowed by the decoy.
    """
    for index, char in enumerate(output):
        if char != "[":
            continue
        value = _try_decode(output, index)
        if isinstance(value, list):
            yield value


def _better_candidate(
    best: tuple[tuple[int, int, int], list[dict]] | None, value: list,
) -> tuple[tuple[int, int, int], list[dict]] | None:
    """Keep the higher-scoring array; ties take the LATER one, because a model
    that restates its answer puts the corrected payload at the end."""
    score = _score_array(value)
    if score is None:
        return best
    if best is not None and score < best[0]:
        return best
    return (score, _only_dicts(value))


def _scan_json_arrays(output: str) -> list[dict] | None:
    """Find the BEST JSON array of findings in *output*, brace-safely.

    ``None`` — not ``[]`` — is the "nothing here" signal, so the caller can fall
    through to salvage instead of treating a decoy-only response as an answer.
    """
    best: tuple[tuple[int, int, int], list[dict]] | None = None
    for value in _decoded_arrays(output):
        best = _better_candidate(best, value)
    return None if best is None else best[1]


def _unclosed_array_start(output: str) -> int | None:
    """Index of the FIRST ``[`` that does not decode — the truncated array.

    It must be the first, not the last. A truncated payload's opening bracket
    fails to decode because nothing closes it, but so does every ``[`` inside a
    string value after it — and 0076 makes those the common case, because
    ``evidence_quote`` is VERBATIM SOURCE and `m[key]`, `x[i]`, `map[string]int`
    are everyday code. Taking the last match started the salvage in the middle
    of a string literal, recovered nothing, and lost the whole truncated batch:
    the exact recall failure salvage exists to prevent.
    """
    for index, char in enumerate(output):
        if char == "[" and _try_decode(output, index) is None:
            return index
    return None


def _whole_objects_from(output: str, start: int) -> list[dict]:
    """Decode successive whole objects after ``output[start] == '['``.

    Stops at the first fragment, which is the partial tail the output-token cap
    cut off. Linear: ``raw_decode`` returns the index it stopped at, so each
    character is consumed once.
    """
    rows: list[dict] = []
    index = start + 1
    decoder = json.JSONDecoder()
    while index < len(output):
        index = _skip_separators(output, index)
        try:
            value, index = decoder.raw_decode(output, index)
        except ValueError:
            return rows
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _skip_separators(output: str, index: int) -> int:
    """Advance past commas and whitespace between two array elements."""
    while index < len(output) and output[index] in ", \t\r\n":
        index += 1
    return index


def _salvage_truncated_array(output: str) -> list[dict] | None:
    """Recover rows from an array the model never closed.

    A response cut at ``VULTURE_LLM_MAX_OUTPUT_TOKENS`` ends mid-array; without
    this the whole batch is lost because neither pattern can match text with no
    ``]``. Gated by ``VULTURE_LLM_JSON_SALVAGE`` (default true) and never silent:
    the recovered row count is logged as ``llm_json_salvaged``.
    """
    if not _json_salvage_enabled():
        return None
    start = _unclosed_array_start(output)
    if start is None:
        return None
    rows = _whole_objects_from(output, start)
    if not rows:
        return None
    logger.warning("llm_json_salvaged rows=%d", len(rows))
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Reasoning strip — the FIRST strategy (feature 0089 §11.3, change 2)
# ─────────────────────────────────────────────────────────────────────────────

# The closed block. Non-greedy so several blocks in one response are each
# removed rather than everything between the first `<think>` and the last
# `</think>` — the text BETWEEN two thinking blocks is answer, not reasoning.
#
# The opener is anchored at a LINE START (MULTILINE `^`, leading indent allowed)
# because 0076 makes `evidence_quote` VERBATIM SOURCE, and source that handles
# reasoning tags contains the literal pair — `prove_agent/llm_helper.py:260` is
# `re.sub(r"<think>.*?</think>", ...)`. Unanchored, the strip reaches INSIDE the
# JSON string of a real finding and empties it: the array still decodes, so the
# row is kept with `re.sub(r"", "", ...)` as its evidence, and 0076's anchor
# verifier then cannot find the quote in the file — status `exact` becomes
# `absent`, which under `VULTURE_LLM_QUOTE_DEMOTE_ABSENT` weighs -1.0 against a
# TRUE finding. The anchor is sufficient, not a heuristic: a JSON string cannot
# contain a raw newline, so no line inside a decoded payload can BEGIN with the
# tag — while every shape a reasoning model emits opens the block at a line
# start (the first character of the response, or its own line).
_THINK_BLOCK_RE = re.compile(r"^[ \t]*<think>.*?</think>", re.DOTALL | re.MULTILINE)

# Where a payload plausibly begins: a line whose first non-blank character opens
# a JSON array or object, or a code fence. Used only to decide where an
# UNCLOSED reasoning block ends, and only as a hypothesis — see
# `_think_stripped_rows`, which discards the hypothesis when it yields nothing.
_PAYLOAD_LINE_RE = re.compile(r"^[ \t]*(?:```|\[|\{)", re.MULTILINE)

_THINK_OPEN = "<think>"
_THINK_CLOSE = "</think>"

# `<output>...</output>`, a wrapper some models add around the real answer. Only
# the tags are removed; the answer between them is kept.
_OUTPUT_TAG_RE = re.compile(r"</?output>")

# Text-based thinking preambles (no XML tags) — moved verbatim from
# `prove_agent/llm_helper.py:41`, where it guards the object path.
_THINKING_PREAMBLE_RE = re.compile(
    r"^.*?(?:Thinking Process|Analysis|Reasoning|Thought|Step[- ]by[- ]Step|Let me)"
    r".*?(?=\{)",
    re.DOTALL,
)


def strip_reasoning(text: str) -> str:
    """*text* with closed `<think>` blocks and `<output>` wrapper tags removed.

    Extends `prove_agent/llm_helper.py:260-262`, which does the same two subs.
    One deliberate narrowing: the `<think>` opener must begin a line (see
    `_THINK_BLOCK_RE`), so the strip cannot reach into a payload string that
    quotes the tag. Prove's version is unanchored and CAN; every response shape
    in `agents/prove/tests/unit/test_llm_helper.py` extracts identically either
    way, because a reasoning model opens the block at a line start.

    The UNCLOSED opener is not a string transform — see
    `_unclosed_think_bodies` — because where such a block ends is a guess, and a
    guess must stay a candidate rather than become the text.
    """
    return _OUTPUT_TAG_RE.sub("", _THINK_BLOCK_RE.sub("", text))


def _unclosed_think_bodies(text: str) -> list[str]:
    """Readings of *text* after a leading `<think>` that never closes, BEST FIRST.

    A response cut at the output-token cap, or a model that simply omits the
    terminator, leaves the opener and every draft it wrote in play — and a draft
    is where a reasoning model writes its most complete JSON, so it outranks the
    real answer on key evidence. With no terminator, where the reasoning ends is
    undecidable; the working hypothesis is that the answer is the LAST payload
    the model emitted and everything before it is reasoning. Every earlier
    payload start is kept as a weaker candidate (a closing fence, for one, looks
    like a payload start and yields nothing), tried in reverse document order.

    Empty for any other text, including a `<think>` that DOES close — that one
    is `strip_reasoning`'s job and needs no guessing.
    """
    head = text.lstrip()
    if not head.startswith(_THINK_OPEN) or _THINK_CLOSE in head:
        return []
    body = head[len(_THINK_OPEN):]
    return [body[m.start():] for m in reversed(list(_PAYLOAD_LINE_RE.finditer(body)))]


def _think_stripped_rows(output: str) -> list[dict] | None:
    """Re-run the core strategies on *output* with its reasoning removed.

    `None` — the chain then continues on the ORIGINAL text — whenever there was
    no reasoning to strip or the remainder carries no findings array. That
    fallback is the whole safety argument: stripping can only ever REPLACE a
    candidate the reasoning supplied, never remove the last one.
    """
    closed = strip_reasoning(output)
    rows = _first_match(closed, _CORE_ROW_STRATEGIES) if closed != output else None
    return rows if rows is not None else _unclosed_think_rows(closed)


def _unclosed_think_rows(text: str) -> list[dict] | None:
    """The best unclosed-`<think>` reading that actually yields rows.

    Non-EMPTY rows, deliberately: an anchor is a guess about where reasoning
    ended, and a guess that lands on `[]` must not answer "nothing found" over
    a real payload the original text still holds.
    """
    for candidate in _unclosed_think_bodies(text):
        rows = _first_match(candidate, _CORE_ROW_STRATEGIES)
        if rows:
            return rows
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Single-object strategies — the PROVE / DISCOVER path (`_extract_json`)
# ─────────────────────────────────────────────────────────────────────────────

def _direct_object(text: str) -> dict | None:
    """The compliant answer: the whole response IS the object."""
    value = _try_decode(text.strip(), 0)
    return value if isinstance(value, dict) else None


def _preamble_object(text: str) -> dict | None:
    """An object after a prose preamble ("Thinking Process:", "Analysis:")."""
    body = text.strip()
    if not _THINKING_PREAMBLE_RE.match(body) or "{" not in body:
        return None
    return _direct_object(body[body.index("{"):])


def _fenced_object(text: str) -> dict | None:
    """The object inside markdown code fences, label optional."""
    body = text.strip()
    if "```" not in body:
        return None
    return _direct_object(_fenced_lines(body))


def _fenced_lines(text: str) -> str:
    """The content between fence markers; *text* itself when none was captured.

    Moved from `prove_agent/llm_helper.py:297` (`_strip_markdown_fences`).
    """
    captured: list[str] = []
    in_fence = False
    for line in text.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            captured.append(line)
    return "\n".join(captured).strip() if captured else text


def _balanced_object(text: str) -> dict | None:
    """The first balanced `{...}` anywhere in *text*, brace-counted.

    Moved from `prove_agent/llm_helper.py:314` (`_find_balanced_json`): handles
    arbitrary nesting, which a regex cannot, and skips braces inside strings.
    """
    start = text.find("{")
    return None if start == -1 else _balanced_from(text, start)


def _balanced_from(text: str, start: int) -> dict | None:
    """`_balanced_object`, anchored at a known `{`; retries at the next one."""
    end = _matching_brace(text, start)
    if end is None:
        return None
    value = _try_decode(text[start:end + 1], 0)
    if isinstance(value, dict):
        return value
    nxt = text.find("{", start + 1)
    return _balanced_from(text, nxt) if 0 <= nxt < end else None


_BRACE_DEPTH = {"{": 1, "}": -1}


def _matching_brace(text: str, start: int) -> int | None:
    """Index of the `}` closing `text[start]`, or `None` when nothing does.

    `char == "}"` is part of the exit test, not redundant with `depth == 0`:
    depth is 0 before the opening brace too, and only the closing one is an
    answer.
    """
    depth = 0
    for index, char in _unquoted_chars(text, start):
        depth += _BRACE_DEPTH.get(char, 0)
        if depth == 0 and char == "}":
            return index
    return None


def _unquoted_chars(text: str, start: int) -> Generator[tuple[int, str], None, None]:
    """`(index, char)` from *start* for every character OUTSIDE a JSON string.

    Braces inside a string value are not structure: `{"description": "Test
    {injection} payload"}` is ONE object, and a depth count that cannot see
    that closes it in the wrong place. Escapes are consumed as a pair, so a
    `\\"` inside a string does not end it.
    """
    in_string = False
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            in_string = not in_string
        elif not in_string:
            yield index, char
        index += 1


def _think_stripped_object(text: str) -> dict | None:
    """The object path's FIRST strategy — the reasoning strip (change 2).

    Same shape as `_think_stripped_rows`, and for the same reason: a reasoning
    model drafts the object it is asked for inside `<think>`, and
    `_balanced_object` would happily return the FIRST such draft.
    """
    closed = strip_reasoning(text)
    found = _first_match(closed, _CORE_OBJECT_STRATEGIES) if closed != text else None
    return found if found is not None else _unclosed_think_object(closed)


def _unclosed_think_object(text: str) -> dict | None:
    """The best unclosed-`<think>` reading that actually yields an object.

    Non-EMPTY, mirroring `_unclosed_think_rows`: a guessed anchor landing on
    `{}` must not answer for a real object the original text still holds.
    """
    for candidate in _unclosed_think_bodies(text):
        found = _first_match(candidate, _CORE_OBJECT_STRATEGIES)
        if found:
            return found
    return None


# ─────────────────────────────────────────────────────────────────────────────
# The strategy lists, and the public API
# ─────────────────────────────────────────────────────────────────────────────

# Order is load-bearing on both lists: the compliant shape is tried first so a
# well-behaved model's answer is unaffected, and each later strategy is a
# strictly more permissive guess about a less well-behaved one.
_CORE_ROW_STRATEGIES = (
    _fenced_json_rows, _scanned_json_rows, _salvage_truncated_array,
    _empty_array_answer, _fenced_empty_array_answer,
)
_ROW_STRATEGIES = (_think_stripped_rows, *_CORE_ROW_STRATEGIES)

_CORE_OBJECT_STRATEGIES = (
    _direct_object, _preamble_object, _fenced_object, _balanced_object,
)
_OBJECT_STRATEGIES = (_think_stripped_object, *_CORE_OBJECT_STRATEGIES)


def _first_match(text: str, strategies: tuple) -> Any:
    """The first strategy's result that is not `None`; `None` when none matched.

    Shared by both paths and by the two reasoning strategies, which re-run the
    CORE list (never themselves) on the stripped text.
    """
    for strategy in strategies:
        result = strategy(text)
        if result is not None:
            return result
    return None


def extract_rows(text: str) -> list[dict]:
    """Findings rows from a model response; `[]` when there are none.

    `_extract_finding_rows` keeps the `None` signal, because `ParseOutcome`
    needs "no strategy matched" (a CONTRACT failure) and "answered, nothing
    found" to stay distinguishable. Callers that only want the rows use this.
    """
    return _extract_finding_rows(text) or []


def extract_object(text: str) -> dict | None:
    """The single JSON object a model was asked for, or `None` if there is none.

    `None` rather than `{}`, which `prove_agent._extract_json` returns for both
    "an empty object" and "no object at all" — a caller cannot tell a model that
    answered `{}` from one that answered prose.
    """
    return _first_match(text, _OBJECT_STRATEGIES)
