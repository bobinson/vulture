"""Feature 0082 C10 — the window reason must survive the validate stage.

`_attach_code_snippet` (audit_runner.py:2487) stamps the reason; `_validate`
(:2550) runs AFTER it and REBUILDS the validation blob from its own computed
check list (`validate/__init__.py:225`, `new_f["validation"] = v.to_json()`).
That is an overwrite, not a merge — so a reason stamped beforehand is destroyed
unless it is explicitly preserved, and the acceptance criterion "416 findings
with an empty window and no recorded reason -> 0" would be measured at a point
where the reason no longer exists.

The reason is preserved OUTSIDE the vote: it carries weight 0.0 and must never
be able to move a status or a confidence.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from shared.tools.window import (
    WINDOW_NO_CODE_LOCATION, record_window_reason, window_reason_of,
)
from shared.validate import ValidateConfig
from shared.validate import _apply_validation_to_finding
from shared.validate.types import ValidationCheck


def _finding_with_reason():
    f = {"title": "t", "category": "CWE-89", "file_path": "a.ts", "line_start": 0}
    record_window_reason(f, WINDOW_NO_CODE_LOCATION)
    return f


def test_non_vacuity_the_reason_is_present_before_validate():
    assert window_reason_of(_finding_with_reason()) == WINDOW_NO_CODE_LOCATION


def test_reason_survives_the_validate_rebuild():
    f = _finding_with_reason()
    checks = [ValidationCheck(id="heuristic", weight=0.3, result="pass")]
    out = _apply_validation_to_finding(f, checks, ValidateConfig())
    assert window_reason_of(out) == WINDOW_NO_CODE_LOCATION, (
        "validate rebuilt the blob and destroyed the window reason"
    )


def test_preserving_the_reason_does_not_move_the_verdict():
    """Weight 0.0 bookkeeping must be verdict-neutral: the status and
    confidence must be identical with and without a stamped reason."""
    checks = [ValidationCheck(id="heuristic", weight=0.3, result="pass")]
    without = _apply_validation_to_finding(
        {"title": "t", "category": "CWE-89", "file_path": "a.ts"}, checks, ValidateConfig())
    with_reason = _apply_validation_to_finding(
        _finding_with_reason(), list(checks), ValidateConfig())

    assert with_reason["validation_status"] == without["validation_status"]
    assert with_reason["validation_confidence"] == without["validation_confidence"]


def test_validate_does_not_invent_a_reason_where_none_was_stamped():
    checks = [ValidationCheck(id="heuristic", weight=0.3, result="pass")]
    out = _apply_validation_to_finding(
        {"title": "t", "category": "CWE-89", "file_path": "a.ts"}, checks, ValidateConfig())
    assert window_reason_of(out) == ""
