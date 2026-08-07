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

from collections.abc import Iterable

from .types import ValidationCheck

__all__ = [
    "AUTHORITATIVE_CHECKS",
    "AUTHORITATIVE_POSITIVE",
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
# explicit operator overrides (a `# nosec` etc.).
AUTHORITATIVE_CHECKS: frozenset[str] = frozenset({"suppression"})

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
    return not _sole_promoter_is_inadmissible_judge(checks)


def vote(checks: Iterable[ValidationCheck]) -> tuple[str, float]:
    """Apply V7 vote rules to a list of validation checks.

    Returns `(status, confidence)` where status is one of
    `"high_confidence"`, `"suspicious"`, `"likely_fp"`.
    """
    checks_list = list(checks)
    confidence = _clamp(0.5 + sum(c.weight for c in checks_list), 0.0, 1.0)
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
