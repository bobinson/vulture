"""0076 — enforcement and dedup: the actuators must be inert until switched on,
and switching one on must never delete or downgrade a finding by accident.

Feature 0076 asks the model to quote the code it accuses and then checks the
quote against the file with no model in the loop. The check produces one of nine
statuses. This module owns the two places where that status becomes an ACTION:

  * the voter — an `absent` status may demote a finding, and nothing else may;
  * Python dedup — a re-anchored line and a merged anchor status must not change
    which rows survive.

WHY THESE TESTS EXIST, defect by defect. Each was a real hole in the design, not
a hypothetical:

  1. `absent` was going to be gated by putting `"anchor"` into
     AUTHORITATIVE_CHECKS behind VULTURE_LLM_QUOTE_DEMOTE_ABSENT while leaving
     the -1.0 WEIGHT applied unconditionally at `VERIFY=enforce`. That gates the
     wrong half. voter.py:126-132 is ADDITIVE: a solo -1.0 gives
     confidence = clamp(0.5 - 1.0) = 0.0, and `_classify(0.0, demoting=1)`
     returns "suspicious" because `likely_fp` needs demoting_count >= 2. So a
     finding whose quote merely failed to locate loses `high_confidence` with the
     demotion switch OFF, and it loses it invisibly — no authoritative check
     appears in the blob to explain the drop. `test_demote_absent_false_leaves_
     the_vote_untouched` fails against that design by construction: it compares
     the scored row against the SAME row with no anchor check at all.

  2. `absent` was described as "a label, not a deletion", which understated it.
     The row does still ship and still persist — and it must stay L5-ELIGIBLE,
     because L5 is the only mechanism that could overturn the demotion.
     `_l5_candidate_provisional` (llm_judge.py:755-769) skips only at
     `conf < 0.30 AND demoting >= 2`, and a solo authoritative demotion is ONE
     check, so eligibility survives — but that is a property of arithmetic, and
     arithmetic is exactly what regresses silently. It is asserted here.

  3. `_deduplicate_findings` keeps the FIRST-SEEN row for a key
     (audit_runner.py:1197, `unique.append(f)`), and first-seen is arbitrary with
     respect to anchor quality. A batch can raise an `absent` row at index 0 and
     an `exact` row for the same key at index 3; the survivor would carry
     `absent` and manufacture a demotion for a finding that WAS correctly quoted.
     The survivor must adopt the BEST status among the rows collapsing onto its
     key, and the finding COUNT must be unchanged — it is a field merge among
     rows that already collapse today, never a new collapse.

  4. Re-anchoring rewrites a line, and a line rewrite is the classic way to lose
     a finding to a dedup collision. On the Python side it cannot: `_dedup_key`
     (audit_runner.py:1159-1169) has no line component. That is a recall
     GUARANTEE and it is asserted as one rather than assumed.

  5. `unreadable` must not demote, because L1's own `_path_check`
     (context_heuristics.py:189) already emits a verdict about the same fact. A
     second demotion double-counts it in an additive vote, and two demoting
     checks at low confidence is precisely the `likely_fp` threshold.

Tier V per the plan's testability split: synthetic model output plus in-memory
findings, no model, no network, no sleeps. Every symbol under construction is
imported INSIDE a test (or inside a helper the test calls) so one missing name
cannot error-collect the module.

TWO CONTRACT CHOICES THIS FILE MAKES EXPLICIT, because the plan's prose left them
implicit and a later reader must not have to guess:

  * the anchor status is carried in the check's `result` field — the same place
    every other L1 check carries its outcome label (`path` -> "neutral",
    `sanitizer` -> "absent", `obligation` -> "discharged"). `extras` is for the
    numeric provenance (delta, candidates, other_path).
  * the survivor's adopted fields keep the private, underscore-prefixed names
    from the `_PRIVATE_FIELDS` strip list (`_anchor_status`, `_anchor_delta`,
    `_anchor_candidates`, `_anchor_other_path`) — plain `anchor_*` names would
    reach the SSE payload verbatim via `finding_event(**finding)` while being
    dropped at the Go boundary, making the live stream and its replay differ.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

# The nine statuses `verify_anchor` may return, in the total-quality order of
# the feature's own table. Kept as a module constant so every regression lock
# below sweeps the same set and a tenth status cannot be added untested.
_STATUSES: tuple[str, ...] = (
    "exact", "reanchored", "near_miss", "found_elsewhere", "ambiguous",
    "unquoted", "oversize", "unreadable", "absent",
)

# The total order a dedup survivor resolves against. `unquoted`/`oversize` and
# `unreadable`/`absent` deliberately share a rank: neither pair carries
# information the other lacks, and a survivor may pick either.
_EXPECTED_QUALITY: dict[str, int] = {
    "exact": 6, "reanchored": 5, "near_miss": 4, "found_elsewhere": 3,
    "ambiguous": 2, "unquoted": 1, "oversize": 1, "unreadable": 0, "absent": 0,
}


# ── helpers ──────────────────────────────────────────────────────────────────


def _finding(**over: Any) -> dict[str, Any]:
    """One LLM-provenance finding on a neutral path.

    `src/app/session.ts` is chosen so neither `_DEMOTING_PATH_RE` nor
    `_PROMOTING_PATH_RE` (context_heuristics.py:24, :62) matches: the L1 `path`
    check lands at weight 0.0 and every arithmetic assertion below is about the
    anchor check alone. No `check_id`, so `_dedup_key` falls through to the
    normalised title and the dedup fixtures collapse on title+path.
    """
    base: dict[str, Any] = {
        "title": "Hardcoded credential in the session bootstrap",
        "category": "CWE-798",
        "severity": "high",
        "file_path": "src/app/session.ts",
        "line_start": 30,
        "line_end": 30,
        "provenance": "llm",
        "code_snippet": '30: const token = "hunter2";',
        "description": "A literal credential is assigned at module scope.",
    }
    base.update(over)
    return base


def _l1(finding: dict[str, Any]) -> list[Any]:
    """Run L1 over one finding and return its check list.

    Imported here rather than at module scope so that the anchor check's absence
    is a FAILURE inside each test, not a collection error for the whole file.
    """
    from shared.validate.context_heuristics import clear_l1_cache, run_l1

    clear_l1_cache()
    return run_l1([finding])[0]


def _check(checks: list[Any], check_id: str) -> Any:
    """The single check with `check_id`, or None. Asserts there is at most one:
    a duplicated check is itself a double-count defect."""
    hits = [c for c in checks if c.id == check_id]
    assert len(hits) <= 1, f"{check_id} emitted {len(hits)} times; it must be one check"
    return hits[0] if hits else None


def _demoting(checks: list[Any]) -> int:
    return sum(1 for c in checks if c.weight < 0)


def _operator_confirmation() -> list[Any]:
    """A human's own `real bug` label — AUTHORITATIVE_POSITIVE (voter.py:81).

    Used to lift the baseline finding to `high_confidence` so the silent
    downgrade of recall-2 is OBSERVABLE. Without a promoter the baseline sits at
    0.5, which `_classify` already calls "suspicious", and the very defect under
    test would leave no trace.
    """
    from shared.validate.types import ValidationCheck

    return [ValidationCheck(
        id="memory", result="user_confirmed_real", weight=0.40,
        reason="operator marked this finding real",
    )]


def _enforce(monkeypatch, *, demote_absent: str | None) -> None:
    """Put the verifier in `enforce` and set the demotion switch explicitly.

    Both are read at CALL time (D14), so setting them inside the test body with
    no module reload is itself part of the contract.
    """
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "enforce")
    if demote_absent is None:
        monkeypatch.delenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", raising=False)
    else:
        monkeypatch.setenv("VULTURE_LLM_QUOTE_DEMOTE_ABSENT", demote_absent)


def _locate(symbol: str, *module_names: str) -> Any:
    """Fetch `symbol` from the first of `module_names` that exports it.

    The plan pins the quality table's CONTENT but not its home — it is presented
    in the wiring section (`audit_runner`) while belonging to the anchor domain
    (`shared.anchor`). The property under test is the ordering, not the module,
    so both are accepted and neither is silently allowed to be missing.
    """
    for name in module_names:
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError:
            continue
        found = getattr(module, symbol, None)
        if found is not None:
            return found
    raise AssertionError(f"0076 must export `{symbol}` from one of {module_names}")


def _dupe_rows(stamped: bool = True) -> list[dict[str, Any]]:
    """The `dupe_status.json` shape: four LLM rows, of which index 0 and index 3
    collapse onto ONE dedup key (same normalised title, same path).

    Index 0 is the `absent` claim at line 18; index 3 is the `exact` claim at
    line 15. Under first-seen-wins the survivor is index 0's dict, so every
    assertion about "the survivor" reads position 0 of the output.
    """
    rows = [
        _finding(title="Hardcoded credential in the session bootstrap",
                 line_start=18, line_end=18,
                 _anchor_status="absent", _anchor_delta=None,
                 _anchor_candidates=0, _anchor_other_path=None),
        _finding(title="Missing rate limit on the login route",
                 line_start=40, line_end=41,
                 _anchor_status="unquoted", _anchor_delta=None,
                 _anchor_candidates=0, _anchor_other_path=None),
        _finding(title="Unpinned dependency in the lockfile",
                 line_start=7, line_end=7,
                 _anchor_status="near_miss", _anchor_delta=None,
                 _anchor_candidates=0, _anchor_other_path=None),
        _finding(title="Hardcoded credential in the session bootstrap",
                 line_start=15, line_end=16,
                 _anchor_status="exact", _anchor_delta=-3,
                 _anchor_candidates=1, _anchor_other_path=None),
    ]
    if stamped:
        return rows
    return [
        {k: v for k, v in row.items() if not k.startswith("_anchor")}
        for row in rows
    ]


def _dedup(base: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from shared.audit_runner import _deduplicate_findings

    return _deduplicate_findings(base, new, "")


# ── AC34 / T4.13 — the switch gates the WEIGHT, not just the membership ──────


def test_demote_absent_false_leaves_the_vote_untouched(monkeypatch):
    """AC34. With VULTURE_LLM_QUOTE_DEMOTE_ABSENT=false, an `absent` row's
    (validation_status, confidence) must be IDENTICAL to the same row scored
    with no anchor check at all.

    THE DEFECT THIS FAILS AGAINST: gating only the AUTHORITATIVE_CHECKS
    membership and leaving the weight at -1.0 whenever VERIFY=enforce. The
    voter is additive (voter.py:126-132):

        confidence = clamp(0.5 + 0.40 - 1.0, 0, 1.0) = 0.0
        _classify(0.0, demoting_count=1) -> "suspicious"

    `likely_fp` needs demoting_count >= 2, so the row is not dismissed — but
    `high_confidence` has become unreachable for it with the demotion switch
    OFF, and nothing in the persisted blob explains why. The weight must be
    0.0, not -1.0.

    The equality is asserted against a control that is the same finding minus
    the private `_anchor_status` field, so it cannot be satisfied by tuning a
    constant: it can only be satisfied by the anchor contributing nothing.
    """
    from shared.validate.voter import vote

    _enforce(monkeypatch, demote_absent="false")
    scored = _l1(_finding(_anchor_status="absent"))
    control = _l1(_finding())
    ground = _operator_confirmation()

    anchor = _check(scored, "anchor")
    assert anchor is not None, (
        "the status must still be RECORDED with the switch off — `observe` and "
        "`enforce` both record; only the actuator is gated"
    )
    assert _check(control, "anchor") is None, (
        "the control must carry no anchor check, or the comparison is vacuous"
    )
    assert anchor.weight == 0.0, (
        "DEMOTE_ABSENT=false must set the anchor weight to 0.0, not -1.0 — a "
        "solo -1.0 demotes through the ADDITIVE path with the switch off"
    )

    baseline = vote(control + ground)
    assert baseline[0] == "high_confidence", (
        "the control must be high_confidence or the silent downgrade this test "
        "exists to catch would leave no observable trace"
    )
    assert vote(scored + ground) == baseline, (
        "with DEMOTE_ABSENT=false an `absent` row must score identically to the "
        "same row with no anchor check at all"
    )


def test_absent_row_records_its_status_even_while_inert(monkeypatch):
    """The switch gates the ACTUATOR, never the observation. `observe` is the
    shipping default precisely so the population can be measured before anything
    acts on it; a build that records nothing until enforcement is on has no data
    with which to justify turning enforcement on."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    checks = _l1(_finding(_anchor_status="absent"))

    anchor = _check(checks, "anchor")
    assert anchor is not None, "observe mode must still emit the anchor check"
    assert anchor.result == "absent", (
        "the status is the check's outcome label, like every other L1 check"
    )
    assert anchor.weight == 0.0, "observe mode carries no weight, by definition"


# ── T4.5 — only `absent` may demote, and only with the switch on ─────────────


def _assert_inert(anchor: Any, voted: tuple[str, float]) -> None:
    assert anchor.weight == 0.0, "an unswitched actuator must weigh nothing"
    assert voted[0] == "high_confidence", (
        "with the switch off the row keeps the label its other evidence earned"
    )


def _assert_demoted(anchor: Any, checks: list[Any], voted: tuple[str, float]) -> None:
    assert anchor.weight < 0.0, "the switch must give the check a negative weight"
    assert _demoting(checks) == 1, (
        "the demotion must be SOLO — that is what the authoritative seat buys, "
        "and it is what keeps the row L5-eligible (AC33)"
    )
    assert voted == ("likely_fp", pytest.approx(0.0, abs=0.05)), (
        "one authoritative demotion must reach likely_fp without a second "
        "demoting check, bypassing the >= 2 floor"
    )


@pytest.mark.parametrize("switch,expect_demotion", [
    (None, False),      # unset — the shipping default
    ("false", False),
    ("true", True),
])
def test_absent_forces_likely_fp_only_when_demote_absent_is_true(
    monkeypatch, switch, expect_demotion,
):
    """T4.5. `absent` is the ONLY status with teeth, and the teeth are switched
    off on ship.

    When the switch is on, one anchor check must be enough: `absent` takes the
    authoritative seat voter.py:92 reserved, so `likely_fp` is reached with a
    demoting_count of exactly ONE — which is the whole point of an authoritative
    check and is not reachable through the additive path.
    """
    from shared.validate.voter import vote

    _enforce(monkeypatch, demote_absent=switch)
    checks = _l1(_finding(_anchor_status="absent"))
    anchor = _check(checks, "anchor")
    assert anchor is not None, "enforce mode must emit the anchor check"

    voted = vote(checks + _operator_confirmation())
    if expect_demotion:
        _assert_demoted(anchor, checks, voted)
    else:
        _assert_inert(anchor, voted)


def test_unquoted_never_demotes(monkeypatch):
    """T4.5 / AC8. `unquoted` is the COMPLIANCE metric, not a verdict.

    A missing or below-floor quote says the model did not comply with the
    obligation; it says nothing about whether the finding is real. Demoting on
    it would make the prompt itself a suppression mechanism, outside every
    switch this feature ships. Asserted with the demotion switch turned ON, so
    the test proves `unquoted` is excluded from the actuator rather than merely
    riding the default.
    """
    from shared.validate.voter import vote

    _enforce(monkeypatch, demote_absent="true")
    scored = _l1(_finding(_anchor_status="unquoted"))
    control = _l1(_finding())
    ground = _operator_confirmation()

    anchor = _check(scored, "anchor")
    assert anchor is not None
    assert anchor.result == "unquoted"
    assert anchor.weight == 0.0, "a non-compliant model must not demote its own finding"
    assert vote(scored + ground) == vote(control + ground), (
        "`unquoted` must leave the vote byte-identical even with DEMOTE_ABSENT=true"
    )


def test_unreadable_does_not_double_count_against_the_path_check(monkeypatch):
    """C5. `unreadable` records a fact L1 already reports, so it must not be
    charged twice.

    `_path_check` (context_heuristics.py:189) already emits its own verdict
    about the finding's path; on a test/vendor path that verdict is -0.20. If
    the anchor check ALSO demoted for the unresolvable path, the row would carry
    TWO demoting checks — and two demoting checks at low confidence is exactly
    the `likely_fp` threshold of `_classify`. One unreadable path would then
    dismiss a finding, which is a deletion mechanism nobody designed.

    The finding here sits on `tests/unit/session.ts` so the path check really is
    demoting and the double-count is arithmetically reachable.
    """
    from shared.validate.voter import vote

    _enforce(monkeypatch, demote_absent="true")
    checks = _l1(_finding(file_path="tests/unit/session.ts",
                          _anchor_status="unreadable"))

    path = _check(checks, "path")
    assert path is not None and path.weight < 0.0, (
        "fixture guard: the path check must be demoting or the double-count "
        "this test targets cannot occur"
    )
    anchor = _check(checks, "anchor")
    assert anchor is not None and anchor.weight == 0.0, (
        "`unreadable` must carry weight 0.0 — the path check already priced it"
    )
    assert _demoting(checks) == 1, (
        "an unresolvable path must be charged ONCE, by L1's path check"
    )
    assert vote(checks)[0] != "likely_fp", (
        "a second demotion for the same fact would push this row over the "
        "two-demoting-checks floor and dismiss it"
    )


# ── T4.9 / AC27 — no status promotes, one demotes ────────────────────────────


@pytest.mark.parametrize("status", _STATUSES)
def test_no_anchor_status_carries_a_positive_weight(monkeypatch, status):
    """AC27, a regression lock over all nine statuses.

    An earlier draft gave `exact` +0.10 and `reanchored` +0.05. That is unsafe
    on this population: `guard_present` (26 of 108) and `wrong_claim` (22 of
    108) are exactly the rows that quote real code ACCURATELY and accuse it
    falsely, so promoting on `exact` would raise the confidence of the
    best-quoting false positives. A located claim is not a true claim.

    Every status therefore resolves to exactly 0.0, and only `absent` may go
    negative — and only with its switch on.
    """
    _enforce(monkeypatch, demote_absent="true")
    anchor = _check(_l1(_finding(_anchor_status=status)), "anchor")

    assert anchor is not None, f"enforce mode must emit an anchor check for {status}"
    assert anchor.result == status, "the status is the check's outcome label"
    assert anchor.weight <= 0.0, f"{status} must never promote a finding"
    if status != "absent":
        assert anchor.weight == 0.0, (
            f"{status} must be exactly neutral; only `absent` is an actuator"
        )


def test_the_promoting_authoritative_seat_is_untouched():
    """AC27's second half. 0076 declines `AUTHORITATIVE_POSITIVE` (voter.py:81).

    That set is human ground truth — an operator's own label. Adding a machine
    status to it would let the verifier override the confidence ceiling reserved
    for a person's judgement. If a later feature shows `anchor_status` is
    discriminating, taking the seat is a one-line change BACKED BY DATA; this
    lock exists so it cannot happen by drift.
    """
    from shared.validate.voter import AUTHORITATIVE_POSITIVE

    assert AUTHORITATIVE_POSITIVE == frozenset({"memory"}), (
        "0076 must not add any anchor status to the promoting authoritative set"
    )


# ── AC16 — the check is born in run_l1 and survives the overwrite ────────────


def test_anchor_check_is_produced_in_run_l1_and_survives_the_overwrite(monkeypatch):
    """AC16 / C2. The check must be produced INSIDE `run_l1`.

    `_apply_validation_to_finding` (validate/__init__.py:194-198) does
    `new_f["validation"] = v.to_json()` — it OVERWRITES the blob wholesale. A
    check stamped onto the finding earlier in the LLM phase is therefore
    destroyed the moment the voter runs, silently and with no error. The only
    place a check can be born and survive is inside the L1 producer whose output
    the voter consumes.

    The pre-stamped sentinel below is the proof: it must be GONE from the
    persisted blob (the overwrite is real, not hypothetical) while the anchor
    check must be PRESENT (it came from `run_l1`, not from a pre-stamp).
    """
    from shared.validate import _apply_validation_to_finding
    from shared.validate.types import ValidateConfig

    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    finding = _finding(_anchor_status="exact")
    finding["validation"] = {
        "status": "high_confidence", "confidence": 0.9,
        "checks": [{"id": "pre_stamped_anchor", "result": "exact",
                    "weight": 0.0, "reason": "", "extras": {}}],
    }

    checks = _l1(finding)
    assert _check(checks, "anchor") is not None, (
        "run_l1 must read the private `_anchor_status` and emit the check itself"
    )

    out = _apply_validation_to_finding(finding, checks, ValidateConfig())
    ids = [c["id"] for c in out["validation"]["checks"]]
    assert "pre_stamped_anchor" not in ids, (
        "control: _apply_validation_to_finding really does overwrite the blob"
    )
    assert "anchor" in ids, (
        "the anchor check must reach the persisted validation blob — that blob "
        "is the feature's ONLY egress path, with zero Go and zero SQL change"
    )


def test_the_anchor_status_egresses_through_the_validation_blob_only(monkeypatch):
    """§5.4(2)+(4). The status travels in the persisted `validation` blob; the
    quote and the private stamps never egress at all.

    `emitter.finding_event(**finding)` forwards every key verbatim into the SSE
    payload, so a plain `anchor_status` field would reach the live stream and
    then be dropped at Go's fixed `model.Finding` boundary — making a finding
    differ between the live stream and its replay for no benefit. The private
    names exist so that cannot happen.
    """
    from shared.validate import validate

    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    finding = _finding(_anchor_status="exact",
                       evidence_quote='const token = "hunter2";')

    out = validate([finding])
    assert len(out.findings) == 1
    row = out.findings[0]

    checks = row["validation"]["checks"]
    assert any(c["id"] == "anchor" and c["result"] == "exact" for c in checks), (
        "the status must be readable from the persisted blob"
    )
    assert "evidence_quote" not in row, (
        "the quote is model-copied source and may contain a live credential; it "
        "must never reach SSE, the DB or the L5 prompt"
    )
    assert "_anchor_status" not in row, (
        "the private stamp is consumed by run_l1 and stripped before egress"
    )


# ── AC33 / T4.12 — a demoted row still ships, still persists, still reaches L5 ─


def test_absent_row_still_ships_and_stays_l5_eligible(monkeypatch):
    """AC33. `absent` demotes a LABEL. It must not remove the row, and it must
    not remove the row's chance to be overturned.

    L5 is the only mechanism that can reverse a demotion, so eligibility is the
    thing that matters. `_l5_candidate_provisional` (llm_judge.py:755-769) skips
    only at `conf < 0.30 AND demoting >= 2`. A solo authoritative demotion is
    ONE check, so the row stays eligible at confidence 0.0 — but that is an
    arithmetic accident of the current thresholds, and arithmetic accidents are
    exactly what regress silently. Pinned here as a requirement.

    The row's emission and persistence are pinned by the companion test below;
    this one owns the eligibility half.
    """
    from shared.validate.llm_judge import _l5_candidate_provisional
    from shared.validate.voter import vote

    _enforce(monkeypatch, demote_absent="true")
    checks = _l1(_finding(_anchor_status="absent"))

    anchor = _check(checks, "anchor")
    assert anchor is not None and anchor.weight < 0.0, (
        "fixture guard: the demotion must be live or the rest is vacuous"
    )
    assert vote(checks) == ("likely_fp", pytest.approx(0.0, abs=0.05)), (
        "the authoritative seat dismisses the LABEL"
    )

    provisional = _l5_candidate_provisional(checks)
    assert provisional is not None, (
        "an absent-demoted row must remain L5-eligible — L5 is the only thing "
        "that can overturn the demotion, and skipping it makes the demotion final"
    )
    assert provisional == (pytest.approx(0.0), 1), (
        "the V7 likely_fp skip needs demoting >= 2; a solo demotion is 1, which "
        "is exactly why eligibility survives a confidence of 0.0"
    )


def test_absent_row_is_still_emitted_and_still_persisted(monkeypatch):
    """AC33's other two thirds. Nothing in 0076 deletes a finding.

    `validate` is contractually demote-never-drop (V6), and the demotion must be
    AUDITABLE from the persisted row: a `likely_fp` label with no recorded
    reason cannot be reviewed, and cannot be reversed by the operator whose
    recall it costs.
    """
    from shared.validate import validate

    _enforce(monkeypatch, demote_absent="true")
    out = validate([_finding(_anchor_status="absent")])

    assert len(out.findings) == 1, (
        "V6: validate demotes, never drops — 0076 adds no deletion mechanism"
    )
    row = out.findings[0]
    assert row["validation_status"] == "likely_fp"
    assert any(c["id"] == "anchor" and c["result"] == "absent"
               for c in row["validation"]["checks"]), (
        "the demotion must be auditable from the persisted row"
    )


def test_an_absent_demotion_does_not_cost_the_row_its_l5_selection(monkeypatch):
    """AC33's known-consequence half, asserted against the CODE rather than
    against prose.

    The plan's recall note says a confidence of 0.0 "sinks it to the bottom of
    the L5 priority queue where the top_n budget cuts it". That is backwards for
    this codebase and the correction belongs in a test, not a footnote:
    `_l5_priority` is `rank * max(1.0 - confidence, 0.0)` and
    `_classify_selection` sorts DESCENDING, so a demoted row's collapsed
    confidence RAISES its priority. Uncertainty is what L5 is budgeted for.

    So the recall-safe property is the stronger one, and it is the one pinned:
    under a binding `top_n=1`, the absent-demoted row is selected AHEAD of an
    otherwise identical undemoted row. A future change that inverts this — for
    instance by ranking on confidence directly — would quietly make every
    demotion final, and must fail here.
    """
    from shared.validate.llm_judge import _classify_selection

    _enforce(monkeypatch, demote_absent="true")
    demoted = _finding(_anchor_status="absent")
    plain = _finding(title="Missing rate limit on the login route")

    demoted_checks = _l1(demoted)
    plain_checks = _l1(plain)
    assert _check(demoted_checks, "anchor").weight < 0.0, (
        "fixture guard: the demotion must be live"
    )

    selected, skips = _classify_selection(
        [demoted, plain], [demoted_checks, plain_checks], top_n=1,
    )
    assert selected == [0], (
        "the demoted row must still win a binding L5 budget — losing it would "
        "remove the only mechanism that can overturn the demotion"
    )
    assert 0 not in skips, "the demoted row must not be recorded as skipped"


# ── AC14 / T4.3 — re-anchoring cannot change the surviving count ─────────────


def test_the_python_dedup_key_has_no_line_component():
    """AC14 / D3, stated as the recall guarantee it is.

    Re-anchoring rewrites `line_start`/`line_end`. The classic way that deletes
    a finding is by moving it onto another row's dedup key. On the Python side
    it cannot, because `_dedup_key` (audit_runner.py:1159-1169) is
    `(check_id or normalised_title, normalised_path)` — no line. This is the
    property the whole re-anchoring actuator rests on, so it is asserted rather
    than re-derived by reading the function every time someone edits it.

    A regression lock, and labelled as one: it holds before the actuator exists
    and must keep holding after.
    """
    from shared.audit_runner import _dedup_key

    base = _finding()
    reference = _dedup_key(base, "")
    for line in (1, 15, 18, 54, 4242):
        moved = dict(base, line_start=line, line_end=line + 2)
        assert _dedup_key(moved, "") == reference, (
            f"moving the line to {line} changed the dedup key; re-anchoring "
            "could then collide a re-located row onto another key and delete it"
        )


def test_reanchor_never_changes_the_python_finding_count():
    """AC14. The count surviving Python dedup is invariant under any line
    rewrite, for any input.

    Exercised on both dedup branches at once — a `base` list (the accumulated
    skill findings) and a `new` list (the LLM batch), since `_deduplicate_
    findings` seeds `seen` from the former and also dedups the latter against
    itself (`seen.add(key)` inside the `for f in new` loop).

    A regression lock today; load-bearing the moment REANCHOR can be turned on.
    """
    base = [_finding(title="Unpinned dependency in the lockfile", line_start=7)]
    new = _dupe_rows(stamped=False)

    reference = len(_dedup(base, new))
    for shift in (-13, -1, 0, 1, 200, 9999):
        moved_base = [dict(f, line_start=max(1, f["line_start"] + shift)) for f in base]
        moved_new = [dict(f, line_start=max(1, f["line_start"] + shift)) for f in new]
        assert len(_dedup(moved_base, moved_new)) == reference, (
            f"shifting every line by {shift} changed the surviving count; "
            "re-anchoring must be count-neutral in Python"
        )


# ── AC30 / T3.11 — the survivor adopts the best status ───────────────────────


def test_the_anchor_quality_order_is_the_published_total_order():
    """AC30's ordering half. The table is the contract, so it is pinned whole.

    A partial assertion (`exact` beats `absent`) would pass against an order
    that, say, ranked `found_elsewhere` above `near_miss` — and the survivor
    merge is only as trustworthy as the order it resolves against.
    """
    quality = _locate("_ANCHOR_QUALITY", "shared.audit_runner", "shared.anchor")

    assert dict(quality) == _EXPECTED_QUALITY, (
        "the dedup survivor's status order must match the published table"
    )
    assert set(quality) == set(_STATUSES), (
        "every status verify_anchor can return must have a rank, or a survivor "
        "merge silently falls back to first-seen for the missing one"
    )


def test_dedup_survivor_adopts_the_best_anchor_status():
    """AC30 / T3.11. First-seen-wins is arbitrary with respect to anchor quality.

    `_deduplicate_findings` keeps the first-seen row for a key
    (audit_runner.py:1197). A batch can raise an `absent` claim at index 0 and
    an `exact` claim for the same key at index 3 — the survivor would then carry
    `absent` and MANUFACTURE a demotion for a finding that was correctly quoted.
    That is the survivor merge's whole purpose: it prevents a loss, it does not
    create one.

    The count is the other half of the assertion and matters just as much: this
    is a FIELD merge among rows that already collapse today, never a new
    collapse.
    """
    stamped = _dedup([], _dupe_rows())
    control = _dedup([], _dupe_rows(stamped=False))

    assert len(stamped) == len(control) == 3, (
        "the survivor merge must not change how many rows survive"
    )
    survivor = stamped[0]
    assert survivor["title"] == "Hardcoded credential in the session bootstrap"
    assert survivor["_anchor_status"] == "exact", (
        "the survivor must adopt the BEST status among the rows collapsing onto "
        "its key — an arbitrary first-seen `absent` demotes a correctly quoted "
        "finding"
    )
    assert survivor["_anchor_delta"] == -3, (
        "the adopted status must bring its own provenance; a status without its "
        "delta cannot be audited or re-measured"
    )
    assert survivor["_anchor_candidates"] == 1


def test_dedup_survivor_keeps_its_own_line_while_reanchor_is_off():
    """T4.4. At ship, `reanchored` records and rewrites nothing.

    The status half of the merge is always safe — it can only ever upgrade a
    row's evidence label. The LINE half is an actuator, and every actuator in
    this feature is inert on ship. Asserted three ways so a default read from
    the wrong place (unset vs literal "false" vs enforce-implies-reanchor) is
    caught rather than averaged over.
    """
    survivor = _dedup([], _dupe_rows())[0]
    assert survivor["_anchor_status"] == "exact"
    assert (survivor["line_start"], survivor["line_end"]) == (18, 18), (
        "with REANCHOR unset the survivor must keep the line it was cited at"
    )


@pytest.mark.parametrize("env", [
    {},
    {"VULTURE_LLM_QUOTE_REANCHOR": "false"},
    {"VULTURE_LLM_QUOTE_VERIFY": "enforce"},
])
def test_reanchor_default_is_off(monkeypatch, env):
    """T4.4. `enforce` does NOT imply re-anchoring.

    The third case is the one that earns this test: `VULTURE_LLM_QUOTE_REANCHOR`
    is a separate switch that "requires enforce" — requiring it is not the same
    as being implied by it, and reading the mode string where the actuator
    switch was meant is an easy and invisible mistake.
    """
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    survivor = _dedup([], _dupe_rows())[0]
    assert survivor["line_start"] == 18, (
        f"the line actuator must stay inert under {env or 'the bare defaults'}"
    )


def test_dedup_survivor_adopts_the_verified_line_when_reanchor_is_on(monkeypatch):
    """AC30's REANCHOR=true half.

    Adopting `exact` is pointless if the survivor keeps the line the `absent`
    row claimed — the whole reason to prefer that row's status is that its line
    was the one actually verified. The count stays invariant here too: turning
    the actuator on must not turn a field merge into a collapse.
    """
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "enforce")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", "true")

    out = _dedup([], _dupe_rows())
    assert len(out) == 3, "the actuator must not change the surviving count"

    survivor = out[0]
    assert survivor["_anchor_status"] == "exact"
    assert (survivor["line_start"], survivor["line_end"]) == (15, 16), (
        "under REANCHOR the survivor must take the line the adopted status "
        "verified, not the line the losing row claimed"
    )


def test_survivor_merge_never_downgrades_a_better_first_seen_status():
    """The merge is a MAX, not a last-write-wins.

    The mirror image of the defect above: with the `exact` row first and the
    `absent` row later, a merge implemented as "the last row for a key wins"
    would introduce exactly the demotion the merge exists to prevent — and the
    ordered fixture above would still pass. Reversing the order is the only way
    to tell a maximum from an overwrite.
    """
    rows = list(reversed(_dupe_rows()))
    out = _dedup([], rows)

    assert len(out) == 3
    survivor = next(f for f in out
                    if f["title"] == "Hardcoded credential in the session bootstrap")
    assert survivor["_anchor_status"] == "exact", (
        "a later `absent` row must never overwrite an earlier `exact` one"
    )
    assert survivor["line_start"] == 15, (
        "the survivor is the first-seen row, which here is the exact one; its "
        "own line stands untouched"
    )


# ── T4.3: the DIRECT re-anchor actuator ──────────────────────────────────────
#
# Added during the simplify pass. The RED team covered AC30 (a dedup SURVIVOR
# adopting a better row's line) but not T4.3 (a row correcting its OWN line from
# what the verifier computed), so the actuator was never implemented: `new_line`
# was written by anchor.py and read by nothing. A `reanchored` finding with no
# dedup partner — the common case — kept its wrong line at `enforce` with
# REANCHOR on, which is precisely the mislocated class the feature exists to fix.

def _run_l1(findings, source_root):
    from shared.validate.context_heuristics import run_l1
    return run_l1(findings, source_root=str(source_root))


def _reanchor_env(monkeypatch) -> None:
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "enforce")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", "true")


def test_reanchor_rewrites_line_start_and_retains_claimed_line(monkeypatch, tmp_path):
    """T4.3 — the row's OWN line is corrected to the verified location."""
    from shared import audit_runner as ar

    src = tmp_path / "app.ts"
    body = [f"const a{i} = {i};" for i in range(40)]
    body[26] = "const parsed = eval(userInput);"
    src.write_text("\n".join(body) + "\n")

    _reanchor_env(monkeypatch)
    finding = {"file_path": str(src), "line_start": 12, "line_end": 12,
               "title": "eval", "evidence_quote": "const parsed = eval(userInput);"}
    ar._verify_and_strip([finding], str(tmp_path))

    assert finding["line_start"] == 27, (
        f"the verified line must be adopted; got {finding['line_start']} "
        f"(status={finding.get('validation', {})}, the verifier found it at 27)"
    )
    assert finding["line_end"] >= finding["line_start"]
    # The rewrite must stay auditable back to what the model actually said.
    # Omitting this assertion is why the stamp-ordering defect survived review:
    # `_claimed_line` was read AFTER the actuator and recorded 27, so the row
    # claimed the model had been right and `claimed + delta` pointed nowhere.
    (checks,) = _run_l1([finding], tmp_path)
    extras = next(dict(c.extras or {}) for c in checks if c.id == "anchor")
    assert extras["claimed_line"] == 12, (
        f"claimed_line must be the MODEL's line (12), not the verified one; "
        f"got {extras['claimed_line']}"
    )
    assert extras["claimed_line"] + extras["delta"] == finding["line_start"], (
        "claimed_line + delta must reconstruct the final line, or the "
        "provenance is self-contradictory"
    )


def test_reanchor_off_leaves_the_claimed_line_untouched(monkeypatch, tmp_path):
    """The actuator is switched, and `observe` must change no line (AC10)."""
    from shared import audit_runner as ar

    src = tmp_path / "app.ts"
    body = [f"const a{i} = {i};" for i in range(40)]
    body[26] = "const parsed = eval(userInput);"
    src.write_text("\n".join(body) + "\n")

    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    finding = {"file_path": str(src), "line_start": 12, "line_end": 12,
               "title": "eval", "evidence_quote": "const parsed = eval(userInput);"}
    ar._verify_and_strip([finding], str(tmp_path))
    assert finding["line_start"] == 12, "observe mode must not move a line"


def test_reanchor_refuses_a_move_beyond_max_delta(monkeypatch, tmp_path):
    """§5.3: a candidate further than MAX_DELTA is a different construct, not a
    mislocation. The absolute ceiling bounds how far one row's line can travel."""
    from shared import audit_runner as ar

    src = tmp_path / "big.ts"
    body = [f"const a{i} = {i};" for i in range(600)]
    body[500] = "const parsed = eval(userInput);"
    src.write_text("\n".join(body) + "\n")

    _reanchor_env(monkeypatch)
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_DELTA", "50")
    finding = {"file_path": str(src), "line_start": 3, "line_end": 3,
               "title": "eval", "evidence_quote": "const parsed = eval(userInput);"}
    ar._verify_and_strip([finding], str(tmp_path))
    assert finding["line_start"] == 3, (
        "a move of 498 lines exceeds MAX_DELTA=50 and must be refused"
    )
