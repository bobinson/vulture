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


def vote(checks: Iterable[ValidationCheck]) -> tuple[str, float]:
    """Apply V7 vote rules to a list of validation checks.

    Returns `(status, confidence)` where status is one of
    `"high_confidence"`, `"suspicious"`, `"likely_fp"`.
    """
    checks_list = list(checks)
    confidence = 0.5 + sum(c.weight for c in checks_list)
    if confidence < 0.0:
        confidence = 0.0
    elif confidence > 1.0:
        confidence = 1.0

    # Authoritative-demoting checks (e.g. explicit `# nosec`) always
    # land in `likely_fp` regardless of how many other layers disagree.
    authoritative_negatives = [
        c for c in checks_list
        if c.id in AUTHORITATIVE_CHECKS and c.weight < 0
    ]
    if authoritative_negatives:
        return "likely_fp", min(confidence, 0.05)

    # V7: require ≥ 2 demoting checks to land in `likely_fp`.
    # Single-check demotions can only land in `suspicious`.
    demoting_checks = [c for c in checks_list if c.weight < 0]
    if confidence < 0.30 and len(demoting_checks) >= 2:
        return "likely_fp", confidence
    if confidence < 0.55:
        return "suspicious", confidence
    return "high_confidence", confidence
