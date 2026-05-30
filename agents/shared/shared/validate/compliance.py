"""V8 compliance-mode neutering.

In compliance mode the layers still run (their checks remain in
`validation.checks` for audit-trail purposes) but no finding may
receive `validation_status = "likely_fp"`. Status is forced to
`suspicious` as the most-demoted permitted state, with a
sentinel check recording that the override happened.
"""

from __future__ import annotations

from .types import FindingValidation, ValidationCheck

__all__ = ["apply_compliance_mode"]


def apply_compliance_mode(v: FindingValidation) -> FindingValidation:
    """Demote `likely_fp` → `suspicious`; record the override."""
    if v.status != "likely_fp":
        return v
    return FindingValidation(
        status="suspicious",
        confidence=max(v.confidence, 0.40),    # floor at 0.40
        checks=v.checks + [
            ValidationCheck(
                id="compliance", result="neutered", weight=0.0,
                reason="compliance_mode prevents likely_fp; "
                       "status forced to suspicious for review",
            ),
        ],
        validated_at=v.validated_at,
    )
