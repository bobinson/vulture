"""0076 section 5.3 — the verifier. A model claim must be checkable without a model.

The business contract of feature 0076 is a property of ``shared/anchor.py``, not of
any LLM: *a claim whose quote cannot be located in the file it accuses does not reach
a consumer as-cited.* That sentence is decidable from ``(claim, file)`` with zero model
involvement, which is the only reason this feature can satisfy the E2E-tests-first rule
at all. Every test in this module is therefore Tier V (plan section 5.8): hand-authored
model output plus an on-disk fixture tree under ``tests/fixtures/anchor/``, no network,
no sleeps, no sampling.

WHY THE VERIFIER IS SHAPED THE WAY IT IS. The naive design — "search the file for the
quote; if it is not there the finding is fabricated" — over-refutes, and on this
population over-refutation deletes real defects. Four narrowings were adopted against
it, each pinned here:

  * the signal floor          a 20-char paraphrase is `unquoted`, never `absent` (AC7)
  * `near_miss`               Jaccard >= 0.6 against any window is non-demoting
  * `found_elsewhere`         a match in a sibling of the same batch is non-demoting
  * the oversize hard clamp   a truncated needle can never resolve to `absent` (AC28)

Measured context for the floor: among floor-satisfying windows that occur more than
once in a file (n = 77,795 adjacent-occurrence pairs) the median gap between adjacent
occurrences is 29 lines, p10 = 10 — which is where RADIUS 25 comes from — and 91% of
sub-floor lines such as ``});`` are non-unique inside a single file. A needle that
small cannot discriminate a location, so it must not be allowed to refute one.

THE OTHER DIRECTION MATTERS JUST AS MUCH. No anchor status may PROMOTE (AC27). On the
adjudicated population the validation layer's promotion signal is anti-correlated with
truth: `guard_present` (26 of 108) and `wrong_claim` (22 of 108) are precisely the rows
that quote real code accurately and accuse it falsely. Weighting `exact` positively
would raise the confidence of the best-quoting false positives, so the positive seat is
declined and this module locks it shut.

PUBLIC SURFACE THIS MODULE PINS (plan section 5.3, D17 — ``shared/anchor.py`` is a LEAF
that takes an already-RESOLVED ``Path``, never resolves, never writes, never calls a
model and never raises):

    AnchorResult(status, reason, new_line, delta, candidates, other_path,
                 quote_chars, quote_tokens)
    verify_anchor(finding: dict, file_path: Path | None, *, mode: str,
                  batch_paths: Sequence[Path] | None = None) -> AnchorResult
    collapse_ws, normalise, tokens, key, windows, distance
    STATUSES          — the nine-status vocabulary, as a container of str
    anchor_weight(status: str) -> float   — the ONE authority for the weight the
                                            `anchor` ValidationCheck carries; reads
                                            VULTURE_LLM_QUOTE_DEMOTE_ABSENT at CALL
                                            time (D14), so run_l1 never re-derives it

Three of those names are not spelled out in the plan's prose and are fixed here because
the tests are the contract: the keyword ``batch_paths`` (the plan says only "another
file rendered in the same batch"), ``STATUSES``, and ``anchor_weight``. The last two
belong in the verifier because section 5.3 calls it "one authority"; duplicating the
weight table into ``context_heuristics.run_l1`` would be the non-DRY alternative.

TWO CONTRACT READINGS RESOLVED HERE, so the implementer does not have to guess:

  1. `oversize` is a TERMINAL status, not a relabelling of the truncated outcome. The
     plan's status table describes truncation under the *actuator* columns ("effect at
     observe" / "effect at enforce"), exactly as the `exact` row's columns describe an
     actuator; and ``_ANCHOR_QUALITY`` (section 5.4(6)) ranks `oversize` at 1 alongside
     `unquoted`, which is only meaningful if `oversize` is returnable. So a quote that
     breaches MAX_LINES/MAX_CHARS is whole-line truncated, the truncated form is
     evaluated to fill ``new_line``/``delta``/``candidates``, and the STATUS is
     `oversize` — except for the two cases the plan names explicitly, which are
     `unquoted`: reason ``line_too_long`` and reason ``oversize_truncated``.
  2. The status is a fact about ``(claim, file)``, so it is invariant between
     ``mode="observe"`` and ``mode="enforce"``. Modes gate actuators (line rewriting,
     weights), never classification — that is what makes AC10's "observe changes
     nothing" checkable at all.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

# tests/unit/test_0076_anchor.py -> tests/fixtures/anchor/
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "anchor"

# The nine, written out rather than imported, so a module that quietly drops one
# still fails. AC12 requires every one of them to be producible with no model.
THE_NINE = frozenset({
    "exact", "reanchored", "ambiguous", "near_miss", "found_elsewhere",
    "absent", "unquoted", "unreadable", "oversize",
})

# AC8 + AC31: the statuses that may never contribute a demotion, in any
# configuration, in any mode.
NON_DEMOTING = ("exact", "reanchored", "ambiguous", "near_miss",
                "found_elsewhere", "unquoted", "unreadable", "oversize")

_FIXTURE_TREE = (
    "exact.ts", "signature.ts", "paraphrase.ts", "dupe3.ts", "ambig.ts",
    "near.ts", "floor.ts", "elided.ts", "fabricated.ts", "nearmiss.ts",
    "longline.ts", "elsewhere/cited.ts", "elsewhere/sibling.ts",
    "unreadable.json", "brace.json", "mixed.json", "stringline.json",
    "dupe_status.json",
)


# ── shared helpers (no import of the module under test: that happens per test) ─

def _fx(name: str) -> Path:
    """A resolved fixture Path — what the caller at :2602 hands the leaf verifier."""
    return _FIXTURES / name


def _lines_of(name: str) -> list[str]:
    return _fx(name).read_text(encoding="utf-8").splitlines()


def _quote_from(name: str, first: int, last: int) -> str:
    """The model copying file lines `first`..`last` (1-based, inclusive) verbatim."""
    return "\n".join(_lines_of(name)[first - 1:last])


def _claim(quote: str | None, line_start: int, name: str = "sample.ts",
           line_end: int | None = None) -> dict:
    """One parsed LLM finding, shaped as ``_parse_llm_result`` leaves it.

    ``file_path`` is the model's own string. The verifier is handed the resolved
    Path separately (D17) and must never write this field back (AC31).
    """
    row = {
        "title": "Missing authorisation check",
        "severity": "high",
        "category": "CWE-862",
        "file_path": name,
        "line_start": line_start,
        "line_end": line_start if line_end is None else line_end,
        "description": "synthetic model output",
        "recommendation": "synthetic model output",
    }
    if quote is not None:
        row["evidence_quote"] = quote
    return row


# Reused quotes, named so the intent is readable at every call site.
_EXACT_LINE3 = '  const raw = readFileSync(path, "utf8");'
_PARAPHRASE = "!property === userId"                       # 20 chars, 2 tokens
_PUNCTUATION_ONLY = "}); }); }); }); }); }); }"             # 25 chars, 0 tokens
_INVENTED = "const adminBypass = grantRootAccess(sessionCookie);"
_INVENTED_BLOCK = "\n".join([
    _INVENTED,
    "if (adminBypass) { return elevatePrivileges(sessionCookie); }",
    'logAudit("bypass granted", sessionCookie);',
    "return null;",
])
_ELIDED_MARKER_QUOTE = (
    "6:   const client = new Client(opts.dsn, opts.timeoutMs);\n"
    "...\n"
    "9:   return client.connect();"
)
_ELIDED_BLANKS_DROPPED = (
    "  const client = new Client(opts.dsn, opts.timeoutMs);\n"
    "  return client.connect();"
)
_SIBLING_LINE3 = '  return db.query("SELECT * FROM users WHERE id = " + sql);'


def _armed(weight_of, statuses) -> dict[str, float]:
    """The statuses carrying a non-zero weight — the set AC27 keeps nearly empty.

    Reported as a mapping rather than a bool so a failure names the offender and its
    weight instead of only saying that one exists.
    """
    return {s: weight_of(s) for s in sorted(statuses) if weight_of(s) != 0.0}


def _non_demoting_case(status: str) -> tuple[dict, Path, list[Path] | None]:
    """(finding, resolved path, batch) producing one of AC31's two statuses.

    One helper because both the weight cross-product and the path-rewrite guard need
    the same two claims, and a second copy would let them drift apart.
    """
    cited, sibling = _fx("elsewhere/cited.ts"), _fx("elsewhere/sibling.ts")
    if status == "found_elsewhere":
        return (_claim(_SIBLING_LINE3, 5, "elsewhere/cited.ts"), cited,
                [cited, sibling])
    return (_claim("const t = readFileSync(p);", 7, "nearmiss.ts"),
            _fx("nearmiss.ts"), None)


# ══ the five primitives (plan section 5.3, "the review found unspecified") ═════

def test_collapse_ws_folds_every_whitespace_run_into_one_space():
    """Indentation-only differences must be a match.

    The model copies from a listing whose ``"NN: "`` prefix has ALREADY shifted the
    column, so byte-comparing indentation would refute a perfect copy.
    """
    from shared.anchor import collapse_ws

    assert collapse_ws("  a\t\t b \r\n c  ") == "a b c", (
        "a tab/space/CR mix must collapse to single spaces and strip at the ends"
    )
    assert collapse_ws("") == ""


def test_normalise_strips_the_line_number_prefix_and_collapses_space():
    """``normalise`` is ``collapse_ws(strip_line_number(line))`` — nothing more."""
    from shared.anchor import normalise

    assert normalise("  30:   const  x = 1;  ") == "const x = 1;"
    assert normalise("const x = 1;") == "const x = 1;", (
        "strip_line_number must return an unprefixed line unchanged, so normalise "
        "is safe to apply unconditionally to any presented line"
    )
    assert normalise("Foo") != normalise("foo"), (
        "normalise is NOT case-folded: an accusation about an identifier must match "
        "on its literal text"
    )


def test_normalise_does_not_blank_strings_or_comments():
    """THE reason ``line_context.strip_strings_and_comments`` is not reused here.

    Blanking literals would make ``password = "hunter2"`` match ``password = ""`` and
    turn a real hardcoded-credential finding into a false `exact` — a verifier that
    confirms the wrong line is worse than one that confirms nothing.
    """
    from shared.anchor import normalise

    assert normalise('password = "hunter2"') != normalise('password = ""'), (
        "string literals must survive normalisation; blanking them manufactures "
        "an `exact` match against the wrong line"
    )
    assert normalise("// TODO: fix auth") == "// TODO: fix auth", (
        "comment text must survive: an accusation can be ABOUT the comment"
    )


def test_tokens_scores_punctuation_as_zero_tokens():
    """``});`` must score 0 tokens so MIN_TOKENS rejects it (fixture floor.ts).

    Punctuation is deliberately not a token. This is the whole mechanism by which the
    floor refuses a needle that 91% of the time is non-unique inside one file.
    """
    from shared.anchor import tokens

    assert tokens("});") == []
    assert tokens("  }  )  ;  ") == []
    assert tokens(_PUNCTUATION_ONLY) == [], (
        "25 characters of punctuation is still zero signal; MIN_CHARS alone must "
        "not be able to admit it"
    )


def test_tokens_takes_identifier_runs_and_integer_literals():
    from shared.anchor import tokens

    assert tokens('const raw = readFileSync(path, "utf8");') == [
        "const", "raw", "readFileSync", "path", "utf8",
    ]
    assert tokens("x1 = 42") == ["x1", "42"], (
        "integer literals are tokens; an identifier may carry digits after the first "
        "character but may not start with one"
    )


def test_key_drops_blanks_elision_markers_and_block_headers():
    """``key`` is the comparable form of a multi-line window.

    Blank lines, the bare ``...`` that ``audit_runner`` joins windows with, and the
    ``--- path ---`` block header (including 0075's ``(lines a-b omitted)`` suffix)
    are all presentation, not code. Dropping rather than preserving them is what lets
    a quote whose blank line the model omitted still match.
    """
    from shared.anchor import key

    assert key([
        "  30:   const x = 1;",
        "",
        "...",
        "--- src/a.ts ---",
        "--- src/a.ts (lines 1-9, 31-89 omitted) ---",
        "  return x;",
    ]) == "const x = 1;\nreturn x;"
    assert key([]) == ""


def test_windows_skips_blank_lines_and_anchors_on_the_first_non_blank():
    """A window is n NON-BLANK lines, anchored at the 1-based line of its first.

    Blank lines inside a window do not count toward n, matching ``key``'s own
    blank-dropping. Without that symmetry a quote whose blank the model dropped could
    never match a window that kept it.
    """
    from shared.anchor import windows

    assert list(windows(["a", "", "b", "c"], 2)) == [(1, "a\nb"), (3, "b\nc")]
    assert list(windows(["a", "", "b", "c"], 1)) == [(1, "a"), (3, "b"), (4, "c")]
    assert list(windows(["a", "b"], 3)) == [], (
        "a file with fewer non-blank lines than n yields no windows, never a "
        "short one"
    )


def test_distance_is_token_jaccard_and_is_used_only_to_classify():
    """Jaccard over ``tokens()``, 0.0-1.0. It NEVER selects a candidate.

    Selection is exact-match only; a fuzzy anchor that rewrites a line is precisely
    the over-refutation the paraphrase case warns about. `distance` exists solely to
    separate `near_miss` from `absent`.
    """
    from shared.anchor import distance

    assert (distance("a b", "a b"),
            distance("a b", "c d"),
            distance("a b", "b a")) == (1.0, 0.0, 1.0), (
        "identical -> 1.0, disjoint -> 0.0, reordered -> 1.0 (a token SET, not a "
        "sequence)"
    )
    # nearmiss.ts line 7 against the model's retyped copy: 4 shared of 5 united.
    assert distance('const t = readFileSync(p, "utf8");',
                    "const t = readFileSync(p);") == pytest.approx(0.8)


# ══ AC7 — the single most important verifier test ═════════════════════════════

@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_a_paraphrase_of_a_real_defect_is_unquoted_never_absent(mode):
    """AC7, RECALL. The defect on paraphrase.ts:5 is REAL; the quote is a paraphrase.

    Real line   ``if(!issues_by_pk?.creatorId === userId) {``
    Model quote ``!property === userId``

    The model did not copy — it summarised the shape of the bug. A verifier that
    equates "I could not find this text" with "the model made this up" refutes a true
    finding, and this codebase has already lost real findings to a narrowing.

    THIS TEST FAILS THE NAIVE DESIGN. A verifier with no signal floor searches the
    file, misses, and returns `absent` — which at full enforcement demotes the row to
    `likely_fp`. The floor is what stops it: 20 normalised characters is below
    MIN_CHARS 24, so the quote is not admissible EVIDENCE at all, and a claim without
    admissible evidence is `unquoted` (the model failed to comply) — never `absent`
    (the model fabricated). Those are different accusations and only one has teeth.
    """
    from shared.anchor import anchor_weight, verify_anchor

    result = verify_anchor(_claim(_PARAPHRASE, 5, "paraphrase.ts"),
                           _fx("paraphrase.ts"), mode=mode)
    assert result.status != "absent", (
        f"mode={mode}: a paraphrase of a REAL defect must never be labelled "
        f"fabricated; got {result.status!r} reason={result.reason!r}"
    )
    assert result.status == "unquoted", (
        f"mode={mode}: a quote below the signal floor is a COMPLIANCE failure, not "
        f"a fabrication; got {result.status!r}"
    )
    assert anchor_weight(result.status) == 0.0, (
        "an unquoted row must not lose confidence for the model's non-compliance"
    )


def test_the_paraphrase_is_refused_on_min_chars_not_on_min_tokens():
    """AC7's mechanism, pinned so a future knob change cannot silently break it.

    ``!property === userId`` is 20 normalised characters carrying 2 tokens: it clears
    MIN_TOKENS 2 and fails MIN_CHARS 24. If MIN_CHARS were ever lowered below 20 this
    quote becomes admissible evidence, the search misses, and AC7's fixture starts
    returning `absent` — a real finding refuted. That is the coupling, stated.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim(_PARAPHRASE, 5, "paraphrase.ts"),
                           _fx("paraphrase.ts"), mode="observe")
    assert (result.reason, result.quote_chars, result.quote_tokens) == (
        "below_floor", 20, 2), (
        "the reason must name the floor (so the unquoted rate stays splittable into "
        "'no field' vs 'too small to check'), and the measurements must show it was "
        f"MIN_CHARS that refused it; got {result.reason!r} chars={result.quote_chars}"
        f" tokens={result.quote_tokens}"
    )


# ══ AC12 — one test per status, all nine, no model ════════════════════════════

def test_status_exact_when_the_quote_matches_at_the_cited_line():
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim(_EXACT_LINE3, 3, "exact.ts"),
                           _fx("exact.ts"), mode="observe")
    assert result.status == "exact"
    assert result.new_line == 3 and result.delta == 0, (
        "an exact hit records the line it was found at and a zero delta, so the "
        "anchor_delta distribution has one origin"
    )
    assert result.other_path is None


def test_status_reanchored_for_a_single_candidate_elsewhere_in_the_file():
    """signature.ts — the measured signupCompletionChecker.ts case.

    The model cites the function SIGNATURE (54) and quotes the BODY (55-56). One
    candidate anywhere in the file re-anchors regardless of RADIUS; RADIUS only
    arbitrates between competing candidates.
    """
    from shared.anchor import verify_anchor

    quote = _quote_from("signature.ts", 55, 56)
    result = verify_anchor(_claim(quote, 54, "signature.ts", line_end=54),
                           _fx("signature.ts"), mode="observe")
    assert result.status == "reanchored"
    assert (result.new_line, result.delta, result.candidates) == (55, 1, 1), (
        "the new line is an ABSOLUTE file position (never snippet-relative), "
        "anchor_delta = new_line - claimed_line (the feature's headline metric), and "
        f"exactly one candidate was found; got {result}"
    )


def test_status_ambiguous_on_an_exact_tie_outside_the_radius():
    """ambig.ts — the same 3-line window at 20-22 and 120-122, claim at 70.

    Both candidates sit exactly 50 lines away. The operative rule is the STRICT
    tie-break, not the radius: two occurrences equidistant from the claim yield
    `ambiguous` regardless of how wide RADIUS is. A verifier that re-anchors to
    "the nearest match" unconditionally fails here by picking arbitrarily.
    """
    from shared.anchor import verify_anchor

    quote = _quote_from("ambig.ts", 20, 22)
    result = verify_anchor(_claim(quote, 70, "ambig.ts", line_end=72),
                           _fx("ambig.ts"), mode="observe")
    assert result.status == "ambiguous"
    assert result.candidates == 2
    assert result.new_line is None, "an ambiguous claim must not be moved anywhere"


def test_status_near_miss_when_the_model_retyped_from_memory():
    """nearmiss.ts — the real line is ``const t = readFileSync(p, "utf8");`` and the
    quote drops the encoding argument. Jaccard 0.8 >= NEAR_MISS_MIN 0.6.

    This discriminates a model that retyped from memory from one that fabricated, and
    it is NON-DEMOTING: it exists to narrow `absent`'s entry condition.
    """
    from shared.anchor import anchor_weight, verify_anchor

    result = verify_anchor(_claim("const t = readFileSync(p);", 7, "nearmiss.ts"),
                           _fx("nearmiss.ts"), mode="enforce")
    assert result.status == "near_miss"
    assert result.new_line is None, "near_miss records; it never relocates"
    assert anchor_weight(result.status) == 0.0


def test_status_found_elsewhere_for_a_quote_that_lives_in_a_sibling():
    """elsewhere/ — the quote is real code from the sibling, not the cited file.

    "Not in the file you named" is a WRONG PATH, not a fabrication, and this feature
    ships no path actuator (section 5.6 declines it on the evidence: n = 2). The
    candidate is recorded and nothing consumes it.
    """
    from shared.anchor import anchor_weight, verify_anchor

    cited, sibling = _fx("elsewhere/cited.ts"), _fx("elsewhere/sibling.ts")
    result = verify_anchor(_claim(_SIBLING_LINE3, 5, "elsewhere/cited.ts"),
                           cited, mode="enforce", batch_paths=[cited, sibling])
    assert result.status == "found_elsewhere"
    assert result.other_path == str(sibling), (
        "the sibling that actually contains the quote is RECORDED, in other_path"
    )
    assert anchor_weight(result.status) == 0.0


def test_status_absent_only_for_a_quote_in_no_file_of_the_batch():
    """fabricated.ts — the sole `absent` fixture, and the sole demoting status.

    It replaces the draft's ``gone.ts``, which quoted a DIFFERENT file and so would
    have canonised demoting a cross-file mislocation. `absent` means: clears the
    floor, is not a near_miss, and matches nowhere in the cited file NOR in any other
    file of the batch.
    """
    from shared.anchor import verify_anchor

    batch = [_fx("fabricated.ts"), _fx("exact.ts"), _fx("nearmiss.ts")]
    result = verify_anchor(_claim(_INVENTED, 5, "fabricated.ts"),
                           _fx("fabricated.ts"), mode="observe", batch_paths=batch)
    assert result.status == "absent"
    assert result.new_line is None and result.other_path is None


def test_status_unquoted_when_the_field_is_missing_or_empty():
    """The compliance metric. The model may simply not have complied (C3)."""
    from shared.anchor import verify_anchor

    for quote in (None, "", "   \n\t "):
        result = verify_anchor(_claim(quote, 3, "exact.ts"),
                               _fx("exact.ts"), mode="enforce")
        assert result.status == "unquoted", (
            f"a missing or blank evidence_quote ({quote!r}) is non-compliance, not "
            f"fabrication; got {result.status!r}"
        )
        assert result.quote_chars == 0 and result.quote_tokens == 0


def test_status_unquoted_below_the_floor_on_chars_and_on_tokens():
    """floor.ts — ``});``. Both halves of the floor are load-bearing and separable."""
    from shared.anchor import verify_anchor

    tiny = verify_anchor(_claim("});", 6, "floor.ts"), _fx("floor.ts"),
                         mode="enforce")
    assert (tiny.status, tiny.reason, tiny.quote_chars, tiny.quote_tokens) == (
        "unquoted", "below_floor", 3, 0), f"`}});` must fail both halves; got {tiny}"

    # 25 characters clears MIN_CHARS but carries zero tokens: MIN_TOKENS must reject
    # it on its own, or a wall of punctuation becomes admissible evidence.
    wall = verify_anchor(_claim(_PUNCTUATION_ONLY, 6, "floor.ts"), _fx("floor.ts"),
                         mode="enforce")
    assert (wall.status, wall.reason, wall.quote_tokens) == (
        "unquoted", "below_floor", 0), (
        "MIN_TOKENS must reject a long punctuation run that MIN_CHARS admits; got "
        f"{wall}"
    )


def test_status_unreadable_when_the_caller_resolved_no_path():
    """D17: the caller owns resolution and passes ``None`` when it fails.

    No second demotion is stacked here — L1's own ``_path_check`` already emits a
    verdict for this exact fact, and a second one double-counts in an additive vote.
    """
    from shared.anchor import anchor_weight, verify_anchor

    unresolved = verify_anchor(_claim(_EXACT_LINE3, 12, "../../../etc/passwd"),
                               None, mode="enforce")
    assert unresolved.status == "unreadable"
    assert anchor_weight(unresolved.status) == 0.0

    missing = verify_anchor(_claim(_EXACT_LINE3, 3, "nope.ts"),
                            _fx("does_not_exist.ts"), mode="enforce")
    assert missing.status == "unreadable", (
        "a path that resolves but cannot be read is the same fact as no path at all"
    )


def test_status_oversize_when_the_quote_breaches_max_lines():
    """A four-line quote against MAX_LINES 3.

    Truncation is whole-line: the first three lines are kept and evaluated, which is
    what fills new_line/delta. The recorded STATUS is `oversize` — see this module's
    docstring for why that is terminal rather than a relabelling of `exact`.
    """
    from shared.anchor import anchor_weight, verify_anchor

    quote = _quote_from("exact.ts", 2, 5)          # 4 lines > MAX_LINES 3
    result = verify_anchor(_claim(quote, 2, "exact.ts", line_end=5),
                           _fx("exact.ts"), mode="enforce")
    assert result.status == "oversize"
    assert result.new_line == 2 and result.delta == 0, (
        "the truncated form still locates, and the located line is recorded"
    )
    assert anchor_weight(result.status) == 0.0


def test_every_one_of_the_nine_statuses_is_reachable_without_a_model():
    """AC12 — exhaustiveness, asserted as a set rather than trusted per test.

    If a status is unreachable it cannot be measured, and this feature ships as a
    measurement feature. The roll-up also pins the module's own vocabulary against
    the nine written out at the top of this file.
    """
    from shared.anchor import STATUSES, verify_anchor

    cited, sibling = _fx("elsewhere/cited.ts"), _fx("elsewhere/sibling.ts")
    cases = (
        (_claim(_EXACT_LINE3, 3, "exact.ts"), _fx("exact.ts"), None),
        (_claim(_quote_from("signature.ts", 55, 56), 54, "signature.ts"),
         _fx("signature.ts"), None),
        (_claim(_quote_from("ambig.ts", 20, 22), 70, "ambig.ts"),
         _fx("ambig.ts"), None),
        (_claim("const t = readFileSync(p);", 7, "nearmiss.ts"),
         _fx("nearmiss.ts"), None),
        (_claim(_SIBLING_LINE3, 5, "elsewhere/cited.ts"), cited, [cited, sibling]),
        (_claim(_INVENTED, 5, "fabricated.ts"), _fx("fabricated.ts"), None),
        (_claim(None, 3, "exact.ts"), _fx("exact.ts"), None),
        (_claim(_EXACT_LINE3, 12, "outside"), None, None),
        (_claim(_quote_from("exact.ts", 2, 5), 2, "exact.ts"), _fx("exact.ts"), None),
    )
    seen = {
        verify_anchor(row, path, mode="observe", batch_paths=batch).status
        for row, path, batch in cases
    }
    assert seen == THE_NINE, f"missing: {sorted(THE_NINE - seen)}; extra: {sorted(seen - THE_NINE)}"
    assert set(STATUSES) == THE_NINE, (
        "the module's declared vocabulary must be exactly the nine; a tenth status "
        "would carry no weight rule and no quality rank"
    )


# ══ T3.3 — normalisation of what the model actually copies ════════════════════

def test_quote_carrying_the_numbered_prefix_matches():
    """0075 presents every line as ``"NN: code"``; models copy the prefix with it.

    Refusing a quote for carrying the prefix WE added would make the compliance
    metric measure our own presentation instead of the model's behaviour.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(
        _claim('3:   const raw = readFileSync(path, "utf8");', 3, "exact.ts"),
        _fx("exact.ts"), mode="observe")
    assert result.status == "exact" and result.new_line == 3


def test_quote_spanning_an_elision_marker_matches():
    """elided.ts — the model copied two rendered lines and the bare ``...`` between.

    ``audit_runner`` joins windows with a lone ``...``; here it stands in for a
    blank-only gap (file lines 7-8). key() drops the marker AND the blanks, windows()
    skips the blanks, so the two code lines are adjacent on both sides of the compare.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim(_ELIDED_MARKER_QUOTE, 6, "elided.ts", line_end=9),
                           _fx("elided.ts"), mode="observe")
    assert result.status == "exact", (
        "a quote spanning an elision marker must normalise to a match, not to a "
        f"fabrication; got {result.status!r} reason={result.reason!r}"
    )
    assert result.new_line == 6


def test_quote_whose_blank_lines_the_model_dropped_matches():
    """Measured: models routinely drop the blank lines out of what they copy.

    This is the reason key() DROPS blanks rather than preserving them.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim(_ELIDED_BLANKS_DROPPED, 6, "elided.ts", line_end=9),
                           _fx("elided.ts"), mode="observe")
    assert result.status == "exact" and result.new_line == 6


def test_lines_are_absolute_file_positions_not_snippet_relative():
    """signature.ts:55-56 quoted with an ABSOLUTE claim of 55 is `exact`.

    A verifier that treated line_start as an offset into a rendered snippet would
    report `reanchored` (or worse) for a claim that is exactly right, and the
    anchor_delta distribution — the feature's headline metric — would measure the
    presenter's offset instead of the model's error.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(
        _claim(_quote_from("signature.ts", 55, 56), 55, "signature.ts", line_end=56),
        _fx("signature.ts"), mode="observe")
    assert result.status == "exact"
    assert result.new_line == 55 and result.delta == 0


# ══ candidate selection: exact-match only, strict tie-break, bounded ══════════

def test_reanchor_needs_the_nearest_to_be_strictly_nearer_than_the_runner_up():
    """near.ts — the same window at 20-21 and 46-47, claim at 22.

    Nearest is 2 away, runner-up 24: strictly nearer and inside RADIUS 25. This is
    the p10=10 / median=29 regime the radius was derived for.
    """
    from shared.anchor import verify_anchor

    quote = _quote_from("near.ts", 20, 21)
    result = verify_anchor(_claim(quote, 22, "near.ts", line_end=23),
                           _fx("near.ts"), mode="observe")
    assert result.status == "reanchored"
    assert result.new_line == 20 and result.delta == -2
    assert result.candidates == 2


def test_a_single_candidate_reanchors_regardless_of_the_radius(monkeypatch):
    """RADIUS arbitrates BETWEEN candidates; it does not gate a lone one.

    Read at call time (D14): the knob is flipped inside the test, with no reload and
    no module re-import. A knob captured at import would silently ignore this.
    """
    from shared.anchor import verify_anchor

    monkeypatch.setenv("VULTURE_LLM_QUOTE_RADIUS", "1")
    result = verify_anchor(_claim(_quote_from("signature.ts", 55, 56), 54,
                                  "signature.ts"),
                           _fx("signature.ts"), mode="observe")
    assert result.status == "reanchored", (
        "one candidate anywhere in the file re-anchors; RADIUS only decides between "
        f"competing occurrences. got {result.status!r}"
    )
    assert result.candidates == 1


def test_radius_bounds_a_multi_candidate_reanchor_and_is_read_at_call_time(monkeypatch):
    """near.ts with RADIUS 1: the nearest candidate is 2 away, so nothing moves."""
    from shared.anchor import verify_anchor

    monkeypatch.setenv("VULTURE_LLM_QUOTE_RADIUS", "1")
    result = verify_anchor(_claim(_quote_from("near.ts", 20, 21), 22, "near.ts"),
                           _fx("near.ts"), mode="observe")
    assert result.status == "ambiguous"
    assert result.candidates == 2 and result.new_line is None


def test_max_delta_keeps_a_distant_single_candidate_ambiguous(monkeypatch):
    """A candidate far from the claim is a DIFFERENT CONSTRUCT, not a mislocation.

    MAX_DELTA is an absolute ceiling on top of the tie-break: a candidate 900 lines
    away in a 1,000-line file stays `ambiguous`. Exercised at MAX_DELTA 0 so the
    fixture stays small; the property is the ceiling, not its default value.
    """
    from shared.anchor import verify_anchor

    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_DELTA", "0")
    result = verify_anchor(
        _claim(_quote_from("signature.ts", 55, 56), 54, "signature.ts"),
        _fx("signature.ts"), mode="observe")
    assert result.status == "ambiguous", (
        "|delta| 1 exceeds MAX_DELTA 0, so the claim must not be relocated; got "
        f"{result.status!r}"
    )
    assert result.new_line is None


def test_candidate_selection_is_exact_match_only_and_never_fuzzy():
    """A 0.8-Jaccard window is a `near_miss`, NOT a re-anchor target.

    Selecting on similarity is how a verifier starts rewriting correct lines to wrong
    ones — the over-refutation this feature exists to avoid. nearmiss.ts has exactly
    one strong fuzzy neighbour and no exact one, so a fuzzy selector is visible here
    as a `reanchored` with new_line 7.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim("const t = readFileSync(p);", 3, "nearmiss.ts"),
                           _fx("nearmiss.ts"), mode="enforce")
    assert result.status == "near_miss", (
        f"a 0.8-similar window must classify, never select; got {result.status!r}"
    )
    assert result.new_line is None and result.delta is None


def test_dupe3_claim_reanchors_onto_the_one_real_defect_line():
    """dupe3.ts — one defect at line 15; the model claims 18.

    The duplicate-claim residue is measured by claim_probe's ``intra_file_duplicate``
    label, never deleted (intra-file title-similarity dedup is a deletion mechanism
    and section 5.6 refuses it). All this verifier owes is the correct line.
    """
    from shared.anchor import verify_anchor

    quote = _quote_from("dupe3.ts", 15, 15)
    result = verify_anchor(_claim(quote, 18, "dupe3.ts"), _fx("dupe3.ts"),
                           mode="observe")
    assert result.status == "reanchored"
    assert result.new_line == 15 and result.delta == -3
    assert result.candidates == 1


# ══ AC28 — `oversize` can never manufacture `absent` ══════════════════════════

def _oversize_inputs() -> list[tuple[str, dict, str]]:
    """Generated over-cap quotes: (id, finding, fixture name).

    Covers all three breaches AC28 names — MAX_LINES, MAX_CHARS (via the 900-char
    line, which also breaches the per-line cap), and one line over MAX_LINE_CHARS
    inside an otherwise ordinary quote.
    """
    long_line = _quote_from("longline.ts", 4, 4)
    return [
        ("four_real_lines",
         _claim(_quote_from("exact.ts", 2, 5), 2, "exact.ts", line_end=5),
         "exact.ts"),
        ("five_real_lines",
         _claim(_quote_from("signature.ts", 54, 58), 54, "signature.ts", line_end=58),
         "signature.ts"),
        ("four_invented_lines",
         _claim(_INVENTED_BLOCK, 4, "fabricated.ts", line_end=7),
         "fabricated.ts"),
        ("single_900_char_line",
         _claim(long_line, 4, "longline.ts"), "longline.ts"),
        ("mixed_one_line_over_the_per_line_cap",
         _claim(_quote_from("exact.ts", 2, 4) + "\n" + long_line, 2, "exact.ts",
                line_end=5),
         "exact.ts"),
        ("whole_file_plus_padding",
         _claim("\n".join(_lines_of("floor.ts") + [long_line]), 1, "floor.ts",
                line_end=7),
         "floor.ts"),
    ]


@pytest.mark.parametrize("demote", ["true", "false"])
@pytest.mark.parametrize("case_id,finding,fixture", _oversize_inputs())
def test_oversize_never_yields_absent(monkeypatch, demote, case_id, finding, fixture):
    """AC28 — the hard clamp, asserted as a property over generated quotes.

    Truncating a quote MID-LINE creates a needle that exists nowhere, which is a
    fabricated `absent` produced by a perfectly compliant model. Three rules close
    it: truncation is whole-line only; a line over MAX_LINE_CHARS yields
    ``unquoted(line_too_long)``; and any truncated evaluation that would return
    `absent` is clamped to ``unquoted(oversize_truncated)``.

    The clamp must hold for EVERY input, in both demotion configurations — a clamp
    that only holds with the actuator off is not a clamp.
    """
    from shared.anchor import anchor_weight, verify_anchor

    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", demote)
    result = verify_anchor(finding, _fx(fixture), mode="enforce")
    assert result.status != "absent", (
        f"{case_id}: an over-cap quote was truncated into a needle and then refuted "
        f"as fabricated; reason={result.reason!r}"
    )
    assert result.status in THE_NINE
    assert anchor_weight(result.status) == 0.0, (
        f"{case_id}: no truncation outcome may carry a demoting weight, got "
        f"{anchor_weight(result.status)} for status {result.status!r}"
    )


def test_an_over_long_single_line_is_unquoted_line_too_long():
    """longline.ts — one 900-char minified line against MAX_LINE_CHARS 400.

    Whole-line truncation cannot shorten a single line, so the only alternatives are
    a mid-line cut (which manufactures `absent`) or refusing the quote as evidence.
    The plan chooses the refusal, explicitly and by name.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim(_quote_from("longline.ts", 4, 4), 4, "longline.ts"),
                           _fx("longline.ts"), mode="enforce")
    assert result.status == "unquoted"
    assert result.reason == "line_too_long", (
        "the reason must name the per-line cap so oversize refusals stay separable "
        f"from below-floor refusals in the compliance metric; got {result.reason!r}"
    )


def test_a_truncated_needle_matching_nowhere_is_clamped_to_unquoted():
    """The clamp itself: truncated evaluation says `absent`, the answer says otherwise.

    Four invented lines against fabricated.ts. The first three survive truncation and
    match nothing — which is exactly the fabricated `absent` the clamp exists to
    prevent, because the model may have quoted correctly in the lines we discarded.
    """
    from shared.anchor import verify_anchor

    result = verify_anchor(_claim(_INVENTED_BLOCK, 4, "fabricated.ts", line_end=7),
                           _fx("fabricated.ts"), mode="enforce")
    assert result.status == "unquoted"
    assert result.reason == "oversize_truncated", (
        "the reason must record that truncation, not the model, is why this could "
        f"not be located; got {result.reason!r}"
    )


def test_truncation_is_whole_line_only(monkeypatch):
    """MAX_CHARS lowered to 40: the two-line quote loses its SECOND LINE, not 22 bytes.

    Cutting at a character offset would leave ``const raw = readFileSync(path, "ut``
    — a needle that exists in no file on earth. Dropping the trailing whole line
    leaves line 3 intact, and it still locates.
    """
    from shared.anchor import verify_anchor

    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_CHARS", "40")
    result = verify_anchor(
        _claim(_quote_from("exact.ts", 3, 4), 3, "exact.ts", line_end=4),
        _fx("exact.ts"), mode="enforce")
    assert result.status == "oversize"
    assert result.new_line == 3 and result.delta == 0, (
        "the surviving whole line must still locate; a mid-line cut would have "
        f"located nothing. got new_line={result.new_line}"
    )


# ══ AC27 / AC8 / AC31 — the weight table, locked ══════════════════════════════

@pytest.mark.parametrize("demote", [None, "", "false", "true", "TRUE", "1"])
def test_no_anchor_status_carries_a_positive_weight(monkeypatch, demote):
    """AC27, a regression lock over all nine statuses.

    An earlier draft gave `exact` +0.10 and `reanchored` +0.05. That is unsafe on
    this population: `guard_present` (26 of 108) and `wrong_claim` (22 of 108) are
    the rows that quote real code ACCURATELY and accuse it falsely, so promoting on
    `exact` would raise the confidence of the best-quoting false positives. A LOCATED
    claim is not a TRUE one, and this assertion is the only thing standing between
    the two.
    """
    from shared.anchor import anchor_weight

    if demote is not None:
        monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", demote)
    for status in sorted(THE_NINE):
        assert anchor_weight(status) <= 0.0, (
            f"DEMOTE_ABSENT={demote!r}: status {status!r} carries a positive weight "
            f"({anchor_weight(status)}); no anchor status may promote"
        )


def test_the_ship_default_leaves_every_status_inert():
    """0076 ships as a MEASUREMENT feature: FP reduction on defaults is exactly zero.

    ``VULTURE_LLM_QUOTE_VERIFY=observe`` and ``VULTURE_LLM_QUOTE_DEMOTE_ABSENT``
    unset. If any status carried weight out of the box, the feature would be changing
    confidences before its own instrument (M3/M7) had ever been run.
    """
    from shared.anchor import anchor_weight

    assert not _armed(anchor_weight, THE_NINE), (
        "statuses armed with no switch set: "
        f"{_armed(anchor_weight, THE_NINE)}"
    )


def test_demote_absent_false_sets_the_weight_to_zero_not_minus_one(monkeypatch):
    """AC34. Gating only the AUTHORITATIVE_CHECKS membership is not enough.

    Leaving -1.0 applied while withholding the membership demotes through the
    ADDITIVE path instead: ``clamp(0.5 + (-1.0)) = 0.0`` and
    ``_classify(0.0, demoting_count=1) -> "suspicious"``. The row is not dismissed —
    `likely_fp` needs two demoting checks — but `high_confidence` (>= 0.55) has become
    unreachable for it. That is exactly the outcome the switch exists to prevent, and
    it is invisible, because no authoritative check appears in the validation blob.
    """
    from shared.anchor import anchor_weight

    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", "false")
    assert anchor_weight("absent") == 0.0, (
        "with the demotion switch off the WEIGHT must be 0.0, not -1.0; got "
        f"{anchor_weight('absent')}"
    )


def test_demote_absent_true_arms_absent_and_nothing_else(monkeypatch):
    """The demotion side is the only actuator in this feature with teeth."""
    from shared.anchor import anchor_weight

    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", "true")
    assert anchor_weight("absent") == -1.0
    others = _armed(anchor_weight, THE_NINE - {"absent"})
    assert not others, (
        f"only `absent` may be armed by the switch; these were too: {others}"
    )


def test_authoritative_positive_is_unmodified_by_this_feature():
    """AC27's second half. The PROMOTING seat is declined, not taken.

    ``voter.py:81`` reserves ``AUTHORITATIVE_POSITIVE`` for human ground truth. If
    M3/M6 later show anchor_status is discriminating, taking the seat is a one-line
    change in a later feature backed by data — strictly better than taking it now on
    an assumption.
    """
    from shared.validate.voter import AUTHORITATIVE_POSITIVE

    assert AUTHORITATIVE_POSITIVE == frozenset({"memory"}), (
        "0076 must not add `anchor` (or anything else) to the promoting seat; got "
        f"{sorted(AUTHORITATIVE_POSITIVE)}"
    )


@pytest.mark.parametrize("demote", ["true", "false"])
@pytest.mark.parametrize("status", NON_DEMOTING)
def test_non_demoting_statuses_are_zero_in_every_configuration(monkeypatch, demote,
                                                               status):
    """AC8 + AC31 as a cross product.

    `unquoted` and `oversize` are compliance/size facts about the MODEL's output;
    `unreadable` is already covered by L1's own path check and a second demotion
    double-counts in an additive vote; `near_miss` and `found_elsewhere` exist
    specifically to narrow `absent`, so weighting them would undo the narrowing.
    """
    from shared.anchor import anchor_weight

    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", demote)
    assert anchor_weight(status) == 0.0, (
        f"DEMOTE_ABSENT={demote}: {status!r} must never contribute a demotion"
    )


@pytest.mark.parametrize("demote", ["true", "false"])
@pytest.mark.parametrize("mode", ["observe", "enforce"])
@pytest.mark.parametrize("expected", ["near_miss", "found_elsewhere"])
def test_near_miss_and_found_elsewhere_are_non_demoting_in_every_mode(
        monkeypatch, demote, mode, expected):
    """AC31 end-to-end through verify_anchor: both modes x both switch settings.

    These two statuses exist for exactly one purpose — narrowing `absent`'s entry
    condition so it stops catching paraphrases and cross-file mislocations. Giving
    either of them weight would undo the narrowing while leaving the vocabulary
    looking intact.
    """
    from shared.anchor import anchor_weight, verify_anchor

    monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", demote)
    finding, path, batch = _non_demoting_case(expected)
    result = verify_anchor(finding, path, mode=mode, batch_paths=batch)
    assert result.status == expected, (
        f"mode={mode} demote={demote}: classification must not depend on the "
        f"actuator configuration; got {result.status!r}"
    )
    assert anchor_weight(result.status) == 0.0


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_found_elsewhere_never_rewrites_file_path(mode):
    """AC31 — the candidate is RECORDED, and no actuator consumes it.

    The recall review asked for a path rewrite under its own switch. Declined and
    recorded rather than justified: there is no measurement of how often a quote
    matching in another rendered file means a wrong path versus a coincidental match
    (the only adjacent datum is n = 2). A path rewrite changes the Go dedup key's
    path component AND the file the L5 window is read from — a larger actuator than a
    line rewrite, on no evidence.
    """
    from shared.anchor import verify_anchor

    finding, cited, batch = _non_demoting_case("found_elsewhere")
    result = verify_anchor(finding, cited, mode=mode, batch_paths=batch)
    assert result.status == "found_elsewhere"
    assert (finding["file_path"], result.new_line, result.other_path) == (
        "elsewhere/cited.ts", None, str(_fx("elsewhere/sibling.ts"))), (
        f"mode={mode}: the cited file_path must be untouched, no line may be adopted "
        "from another file (it is meaningless against the cited path), and the "
        f"sibling must be recorded in other_path; got {result} and "
        f"file_path={finding['file_path']!r}"
    )


def test_the_cross_file_search_is_scoped_to_the_batch():
    """`found_elsewhere` requires the sibling to be IN the batch; otherwise `absent`.

    This pins that the cross-file search is a real, bounded search over the files
    rendered in the same request — not a repository-wide grep, and not a blanket
    refusal to ever say `absent`.
    """
    from shared.anchor import verify_anchor

    cited = _fx("elsewhere/cited.ts")
    finding = _claim(_SIBLING_LINE3, 5, "elsewhere/cited.ts")
    assert verify_anchor(finding, cited, mode="observe").status == "absent"
    assert verify_anchor(finding, cited, mode="observe",
                         batch_paths=[cited]).status == "absent"


# ══ leaf-purity properties (D17: never resolves, never writes, never raises) ══

def test_verify_anchor_never_mutates_the_finding():
    """The verifier REPORTS. Every actuator lives at the call site (section 5.4).

    A verifier that edits line_start in place would make AC10 ("observe changes
    nothing") impossible to honour, because observe and enforce would share one
    mutation path.
    """
    from shared.anchor import verify_anchor

    cited, sibling = _fx("elsewhere/cited.ts"), _fx("elsewhere/sibling.ts")
    cases = (
        (_claim(_EXACT_LINE3, 3, "exact.ts"), _fx("exact.ts"), None),
        (_claim(_quote_from("signature.ts", 55, 56), 54, "signature.ts"),
         _fx("signature.ts"), None),
        (_claim(_INVENTED, 5, "fabricated.ts"), _fx("fabricated.ts"), None),
        (_claim(_SIBLING_LINE3, 5, "elsewhere/cited.ts"), cited, [cited, sibling]),
    )
    for finding, path, batch in cases:
        before = copy.deepcopy(finding)
        for mode in ("observe", "enforce"):
            verify_anchor(finding, path, mode=mode, batch_paths=batch)
        assert finding == before, (
            "verify_anchor must be pure with respect to the finding it inspects; "
            f"it changed {finding.get('title')!r}"
        )


def test_verify_anchor_never_raises_and_always_returns_one_of_the_nine():
    """"Never raises" is part of the contract: this runs on the audit-producer thread
    and an exception there loses a whole batch of findings, which is a deletion."""
    from shared.anchor import verify_anchor

    hostile = (
        (_claim(_EXACT_LINE3, 3, "exact.ts"), _FIXTURES),          # a DIRECTORY
        (_claim(_EXACT_LINE3, -5, "exact.ts"), _fx("exact.ts")),   # negative line
        (_claim(_EXACT_LINE3, 10_000, "exact.ts"), _fx("exact.ts")),  # past EOF
        (_claim("\x00\x01\x02 binary noise here", 1, "exact.ts"), _fx("exact.ts")),
        ({"title": "no line fields at all",
          "evidence_quote": _EXACT_LINE3}, _fx("exact.ts")),
    )
    for finding, path in hostile:
        result = verify_anchor(finding, path, mode="enforce")
        assert result.status in THE_NINE, (
            f"hostile input produced status {result.status!r}, which is not one of "
            "the nine"
        )


def test_the_status_is_invariant_between_observe_and_enforce():
    """AC10's precondition. Modes gate ACTUATORS; classification is a fact about
    ``(claim, file)`` and cannot depend on how loudly we intend to act on it."""
    from shared.anchor import verify_anchor

    cited, sibling = _fx("elsewhere/cited.ts"), _fx("elsewhere/sibling.ts")
    cases = (
        (_claim(_EXACT_LINE3, 3, "exact.ts"), _fx("exact.ts"), None),
        (_claim(_quote_from("near.ts", 20, 21), 22, "near.ts"), _fx("near.ts"), None),
        (_claim(_quote_from("ambig.ts", 20, 22), 70, "ambig.ts"),
         _fx("ambig.ts"), None),
        (_claim(_PARAPHRASE, 5, "paraphrase.ts"), _fx("paraphrase.ts"), None),
        (_claim(_INVENTED, 5, "fabricated.ts"), _fx("fabricated.ts"), None),
        (_claim(_SIBLING_LINE3, 5, "elsewhere/cited.ts"), cited, [cited, sibling]),
    )
    for finding, path, batch in cases:
        observed = verify_anchor(finding, path, mode="observe", batch_paths=batch)
        enforced = verify_anchor(finding, path, mode="enforce", batch_paths=batch)
        assert observed.status == enforced.status, (
            f"{finding['title']!r} on {path}: observe said {observed.status!r} and "
            f"enforce said {enforced.status!r}"
        )
        assert observed.new_line == enforced.new_line


def test_the_fixture_tree_is_complete():
    """Section 8's committed, synthetic, self-contained set.

    Acceptance must never depend on an external target, so the tree is part of the
    contract. It is asserted here rather than discovered as a confusing collection
    error in whichever test happens to run first.
    """
    missing = [name for name in _FIXTURE_TREE if not _fx(name).is_file()]
    assert not missing, f"missing 0076 anchor fixtures: {missing}"


# ── the truncated outcome must survive as evidence, even though the STATUS does not ──
#
# Found by dogfooding 0076 on togetherapp: 5 of 19 LLM rows (26%) came back
# `oversize`, and THREE of them carried `delta=0` — i.e. the truncated 3-line
# prefix matched EXACTLY at the cited line. They verified. But `_size_status`
# does `replace(outcome, status="oversize")`, so the histogram cannot tell a
# truncated quote that landed perfectly from one that landed nowhere, and a
# quarter of the tier reads as failure when much of it is success.
#
# `oversize` stays TERMINAL — this module's header resolves that deliberately
# (`_ANCHOR_QUALITY` ranks it, so it must be returnable). The fix is additive:
# carry the underlying verdict in `reason` so the measurement is decomposable.

def test_oversize_records_the_verdict_the_truncated_quote_actually_earned():
    """A truncated quote that matched exactly must say so in `reason`."""
    import tempfile
    from pathlib import Path

    from shared import anchor

    root = Path(tempfile.mkdtemp())
    src = root / "h.ts"
    body = ["export function handler(req, res) {",
            "  const token = req.headers.authorization;",
            "  const user = verifyToken(token);",
            "  return db.execute(buildQuery(req.query.id));",
            "}"]
    src.write_text("\n".join(body) + "\n")

    # four verbatim lines: truncated to three, and those three match at line 1
    result = anchor.verify_anchor(
        {"file_path": str(src), "line_start": 1, "evidence_quote": "\n".join(body[:4])},
        src, mode="observe")

    assert result.status == "oversize", "the status contract is unchanged"
    assert result.delta == 0, "the truncated prefix located at the cited line"
    assert "exact" in (result.reason or ""), (
        "the truncated quote earned `exact` and the reason must record it, or the "
        f"oversize bucket is undecomposable; got reason={result.reason!r}"
    )


def test_oversize_reason_distinguishes_a_located_quote_from_a_lost_one():
    """The two oversize outcomes must not look identical."""
    import tempfile
    from pathlib import Path

    from shared import anchor

    root = Path(tempfile.mkdtemp())
    src = root / "h.ts"
    src.write_text("\n".join([
        "export function handler(req, res) {",
        "  const token = req.headers.authorization;",
        "  const user = verifyToken(token);",
        "  return db.execute(buildQuery(req.query.id));",
        "}"]) + "\n")

    located = anchor.verify_anchor(
        {"file_path": str(src), "line_start": 1,
         "evidence_quote": "export function handler(req, res) {\n"
                           "  const token = req.headers.authorization;\n"
                           "  const user = verifyToken(token);\n"
                           "  return db.execute(buildQuery(req.query.id));"},
        src, mode="observe")

    lost = anchor.verify_anchor(
        {"file_path": str(src), "line_start": 1,
         "evidence_quote": "const alpha = totallyUnrelatedFunction(ctx);\n"
                           "const beta = alsoNotInThisFile(ctx);\n"
                           "const gamma = norIsThisOne(ctx);\n"
                           "const delta = northisone(ctx);"},
        src, mode="observe")

    assert located.reason != lost.reason, (
        "a truncated quote that located and one that did not must be "
        f"distinguishable; both reported reason={located.reason!r}"
    )
