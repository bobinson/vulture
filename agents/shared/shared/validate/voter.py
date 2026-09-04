# ╔══════════════════════════════════════════════════════════════╗
# ║  voter rules — PARITY-CRITICAL                              ║
# ║                                                              ║
# ║  If you modify this file, you MUST modify                    ║
# ║  backend/internal/service/validation_voter.go in the same    ║
# ║  PR. The cross-language parity test                          ║
# ║  (test_voter_parity.py + validation_voter_parity_test.go)    ║
# ║  consumes the same JSON fixture and asserts identical        ║
# ║  outputs.                                                    ║
# ║                                                              ║
# ║  Both tests existed only in these headers until feature      ║
# ║  0072 built them; this one claimed CI enforced a test that   ║
# ║  had never been written. Real now — fixture at               ║
# ║  backend/internal/service/testdata/voter_parity_cases.json.  ║
# ╚══════════════════════════════════════════════════════════════╝

"""Validate voter (V7) — collapses L1+L2+L3+L4+L5 checks into one
`(status, confidence)` per finding.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from .types import ValidationCheck

__all__ = [
    "AUTHORITATIVE_CHECKS",
    "AUTHORITATIVE_POSITIVE",
    "CONFIDENCE_CEILING_UNVERIFIED",
    "JUDGE_CITED",
    "JUDGE_UNCITED",
    "JUDGE_UNDECIDED",
    "OBLIGATION_DISCHARGED",
    "OBLIGATION_ID",
    "OBLIGATION_REFUTED",
    "OBLIGATION_UNKNOWN",
    "vote",
]


# Single-check ids that can demote a finding to `likely_fp` solo,
# bypassing the ≥2-demoting-checks floor of V7. These represent
# explicit operator overrides (a `# nosec` etc.) and, since feature 0076,
# one MECHANICAL verification: an `anchor` check whose evidence quote was
# located nowhere in the accused file nor in any sibling of its batch.
#
# Membership alone demotes nothing — `_has_authoritative_demotion` also
# requires a NEGATIVE weight, and `shared.anchor.anchor_weight` returns 0.0
# for every status but `absent`, and for `absent` too unless
# VULTURE_LLM_QUOTE_DEMOTE_ABSENT is on. That is deliberate: the weight and
# the seat must be gated by the SAME switch. Gating only the membership
# leaves −1.0 running through the ADDITIVE path — clamp(0.5 − 1.0) = 0.0 and
# `_classify(0.0, 1)` = "suspicious" — which silently costs a finding its
# `high_confidence` label with the demotion switch off (0076 AC34).
#
# This is the seat the ceiling note below reserved for "a future
# mechanical-verification check id"; the PROMOTING seat
# (AUTHORITATIVE_POSITIVE) is deliberately NOT taken — on the adjudicated
# population a located quote is not a true claim, so no anchor status
# promotes (0076 AC27).
AUTHORITATIVE_CHECKS: frozenset[str] = frozenset({"suppression", "anchor"})

# Secret-presence check (see context_heuristics._secret_value_check). `absent`
# means the cited line was read and assigns no value at all.
SECRET_VALUE_ID = "secret_value"
SECRET_VALUE_ABSENT = "absent"

INPUT_VALIDATION_ID = "input_validation"
INPUT_VALIDATION_GUARDED = "guarded"

# ── Feature 0072: obligations ────────────────────────────────────────
# An obligation is emitted as its OWN check, carrying its state in the
# existing `result` field. That is deliberate: ValidationCheck is rebuilt
# by hand at ~21 sites with no use of dataclasses.replace, so a new field
# would be dropped silently and a False default would fail OPEN. `result`
# is already serialised and already crosses the SSE boundary.
#
# PARITY: these literals are duplicated in validation_voter.go and asserted
# by the shared fixture. If they drift, the gate silently disables.
OBLIGATION_ID: str = "obligation"
OBLIGATION_UNKNOWN: str = "unknown"
OBLIGATION_DISCHARGED: str = "discharged"
OBLIGATION_REFUTED: str = "refuted"

# A promoting llm_judge verdict carries its own admissibility in `result`,
# decided at ingestion where the source is readable. The voter stays pure:
# it compares a string and never touches a file.
JUDGE_CITED: str = "real_bug"           # citation verified -> may confirm alone
JUDGE_UNCITED: str = "real_bug_uncited"  # asserts an absence -> may not
# The judge DECLINED to decide. Distinct from JUDGE_UNCITED ("claimed a bug
# without citing") — this is "made no claim at all". The prompt designates
# exploitable=0.5 as "genuinely impossible to tell", and that is the branch that
# actually executes: 10 of 10 live verdicts, and 40 of 207 cached rows, sit
# exactly there. Labelling them JUDGE_CITED put the sole-confirmation
# admissibility marker on an empty assertion.
#
# Inadmissible by CONSTRUCTION, not by a new rule: both _judge_verdict_admissible
# implementations compare one literal, so anything != JUDGE_CITED already fails.
JUDGE_UNDECIDED: str = "undecided"

# Check ids whose POSITIVE weight is human ground truth and overrides the
# obligation gate. The weight test is load-bearing (see _has_authoritative_
# positive): `memory` is bidirectional, so keying on the id alone would let a
# user marking something a FALSE POSITIVE grant it a confirmation override.
AUTHORITATIVE_POSITIVE: frozenset[str] = frozenset({"memory"})

# ── Feature 0072 T4.2 (C2/AC5): confidence 1.0 is reserved ──────────────────
# A single judge verdict at exploitable >= 0.834 used to clamp to exactly
# 1.000 — a model vote presenting as total certainty. The ceiling is applied
# as the CLAMP BOUND, never as an `if confidence >= 1.0` equality test: the
# two voters fold weights in different orders (0.5 + sum(w) here, accumulate-
# from-0.5 in Go), so an equality trigger can fire in one language and not
# the other for the same checks (measured: weights {0.1, 0.3, 0.1} give 1.0
# in Python and 0.9999999999999999 in Go).
#
# Only ground truth lifts the ceiling — today an operator's own positive
# label (AUTHORITATIVE_POSITIVE); a future mechanical-verification check id
# joins that set rather than adding a second mechanism.
#
# PARITY: mirrored in validation_voter.go; pinned by the shared fixture.
CONFIDENCE_CEILING_UNVERIFIED: float = 0.99


log = logging.getLogger(__name__)


def _clamp(value: float, lo: float, hi: float) -> float:
    return lo if value < lo else hi if value > hi else value


def _has_authoritative_demotion(checks: list[ValidationCheck]) -> bool:
    """True if any AUTHORITATIVE_CHECKS check has a negative weight.

    Operator overrides (e.g. `# nosec`) carry singular weight: one such
    check sends the finding to `likely_fp` regardless of agreement.
    """
    return any(
        c.id in AUTHORITATIVE_CHECKS and c.weight < 0 for c in checks
    )


def _is_refuted(checks: list[ValidationCheck]) -> bool:
    """True if the obligation was refuted at the class's declared scope."""
    return any(
        c.id == OBLIGATION_ID and c.result == OBLIGATION_REFUTED for c in checks
    )


def _count_demoting(checks: list[ValidationCheck]) -> int:
    return sum(1 for c in checks if c.weight < 0)


def _classify(confidence: float, demoting_count: int) -> str:
    """V7 status classification given a clamped confidence + demoting count."""
    if confidence < 0.30 and demoting_count >= 2:
        return "likely_fp"
    if confidence < 0.55:
        return "suspicious"
    return "high_confidence"


def _has_authoritative_positive(checks: list[ValidationCheck]) -> bool:
    """An operator's own POSITIVE label — human ground truth (feature 0072).

    The `weight > 0` test is load-bearing: `memory` is bidirectional (+0.40
    user-confirmed-real, -0.40 user-marked-false-positive), so testing the id
    alone would let a human calling something a false positive grant it a
    confirmation override. Mirrors _has_authoritative_demotion's `weight < 0`.
    """
    return any(
        c.id in AUTHORITATIVE_POSITIVE and c.weight > 0 for c in checks
    )


def _judge_verdict_admissible(check: ValidationCheck) -> bool:
    """Whether a promoting judge verdict cited something checkable.

    Decided at INGESTION (where the source is readable) and encoded in
    `result`, so the voter stays pure and both languages compare one literal.
    Fails closed: a verdict cached under an older schema carries neither
    marker and is inadmissible.
    """
    return check.result == JUDGE_CITED


def _sole_promoter_is_inadmissible_judge(checks: list[ValidationCheck]) -> bool:
    """True when the ONLY thing raising this finding is a judge verdict that
    cites nothing. Sign-aware by construction: a demoting check can never be
    mistaken for corroboration.
    """
    promoting = [c for c in checks if c.weight > 0]
    if len(promoting) != 1:
        return False
    only = promoting[0]
    return only.id == "llm_judge" and not _judge_verdict_admissible(only)


def _may_confirm(checks: list[ValidationCheck]) -> bool:
    """Whether this finding may carry the `high_confidence` LABEL.

    Confidence is unaffected either way — the gate withholds a label, it does
    not re-score. Deliberately NOT a quorum rule: measured on a real run, 81%
    of findings carry no non-zero check at all and every confirmed finding
    rested on exactly one, so requiring two would empty the confirmed tier.
    """
    if _has_authoritative_positive(checks):
        return True
    if any(c.id == OBLIGATION_ID and c.result == OBLIGATION_UNKNOWN
           for c in checks):
        return False
    # A secret-class finding whose cited line verifiably assigns NO value may
    # not be CONFIRMED. The value is what the finding is about, and its absence
    # was read from source — a fact, not an opinion, so a model verdict must not
    # outrank it. Measured: `backend/config.yaml:3` is literally `admin_secret:`
    # with nothing after the colon, and the judge (shown a snippet where sibling
    # values were masked to ***REDACTED***, so it could not tell empty from
    # masked) called it a hardcoded credential at exploitable=0.9, reaching
    # 0.99 high_confidence.
    #
    # This withholds the LABEL, it does not assert likely_fp: the cited line can
    # be off by one, or the value can live on a continuation line, and neither
    # case justifies dismissing the finding outright.
    if any(c.id == SECRET_VALUE_ID and c.result == SECRET_VALUE_ABSENT
           for c in checks):
        return False
    # An injection finding whose every interpolated value is provably
    # validated may not be CONFIRMED. Like `secret_value`, this was read from
    # source — the identifier is guarded by an anchored pattern or a
    # membership test in the cited file — so a model verdict formed on a
    # +/-2-line window must not outrank it. Measured: the judge scored
    # `seed-poll-verifications.qa.ts:423` a real bug at exploitable=0.85
    # while `pollId` was UUID-validated at the handler entry 100 lines above.
    #
    # The additive weight alone does not settle it: 0.5 base + 0.525 judge -
    # 0.40 here is 0.625, still inside the confirmed band.
    #
    # And, as with `secret_value`, this withholds the LABEL rather than
    # asserting likely_fp — the guard can be removed tomorrow, and a
    # file-scope guard need not cover every path into the sink.
    if any(c.id == INPUT_VALIDATION_ID and c.result == INPUT_VALIDATION_GUARDED
           for c in checks):
        return False
    return not _sole_promoter_is_inadmissible_judge(checks)


def vote(checks: Iterable[ValidationCheck]) -> tuple[str, float]:
    """Apply V7 vote rules to a list of validation checks.

    Returns `(status, confidence)` where status is one of
    `"high_confidence"`, `"suspicious"`, `"likely_fp"`.
    """
    checks_list = list(checks)
    ceiling = (1.0 if _has_authoritative_positive(checks_list)
               else CONFIDENCE_CEILING_UNVERIFIED)
    confidence = _clamp(0.5 + sum(c.weight for c in checks_list), 0.0, ceiling)
    if _has_authoritative_demotion(checks_list):
        return "likely_fp", min(confidence, 0.05)
    # Feature 0072: a REFUTED obligation is positive evidence of absence, not an
    # absence of evidence — the mitigation was found at the class's declared
    # scope. It is the only verdict that REMOVES a finding rather than merely
    # withholding its label, and reaching it requires STRUCTURAL evidence
    # (MAX_VERDICT), so a textual match can never get here.
    #
    # Confidence is preserved: it measures how strong the DETECTION evidence is,
    # and the obligation is a separate axis. Collapsing the two would make a
    # refuted finding indistinguishable from a weak one, and reviewing refuted
    # findings by detection strength is how the refuter itself gets audited.
    if _is_refuted(checks_list):
        return "likely_fp", confidence
    status = _classify(confidence, _count_demoting(checks_list))
    # Withhold the LABEL, never the number. A blocking obligation deliberately
    # does not prevent `likely_fp` — independent refutation may still dismiss a
    # finding whose obligations were never searched.
    if status == "high_confidence" and not _may_confirm(checks_list):
        status = "suspicious"
    return status, confidence
