# ╔══════════════════════════════════════════════════════════════╗
# ║  voter rules — PARITY-CRITICAL                              ║
# ║                                                              ║
# ║  If you modify this file, you MUST modify                    ║
# ║  backend/internal/service/validation_voter.go in the same    ║
# ║  PR. The cross-language parity test                          ║
# ║  (test_voter_parity.py + validation_voter_parity_test.go)    ║
# ║  consumes the same JSON fixture and asserts identical        ║
# ║  outputs — CI will fail on drift.                            ║
# ╚══════════════════════════════════════════════════════════════╝

"""Validate voter (V7) — collapses L1+L2+L3+L4+L5 checks into one
`(status, confidence)` per finding.
"""

from __future__ import annotations

from typing import Iterable

from .types import ValidationCheck

__all__ = ["AUTHORITATIVE_CHECKS", "vote"]


# Single-check ids that can demote a finding to `likely_fp` solo,
# bypassing the ≥2-demoting-checks floor of V7. These represent
# explicit operator overrides (a `# nosec` etc.).
AUTHORITATIVE_CHECKS: frozenset[str] = frozenset({"suppression"})


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


def _count_demoting(checks: list[ValidationCheck]) -> int:
    return sum(1 for c in checks if c.weight < 0)


def _classify(confidence: float, demoting_count: int) -> str:
    """V7 status classification given a clamped confidence + demoting count."""
    if confidence < 0.30 and demoting_count >= 2:
        return "likely_fp"
    if confidence < 0.55:
        return "suspicious"
    return "high_confidence"


def vote(checks: Iterable[ValidationCheck]) -> tuple[str, float]:
    """Apply V7 vote rules to a list of validation checks.

    Returns `(status, confidence)` where status is one of
    `"high_confidence"`, `"suspicious"`, `"likely_fp"`.
    """
    checks_list = list(checks)
    confidence = _clamp(0.5 + sum(c.weight for c in checks_list), 0.0, 1.0)
    if _has_authoritative_demotion(checks_list):
        return "likely_fp", min(confidence, 0.05)
    status = _classify(confidence, _count_demoting(checks_list))
    return status, confidence
