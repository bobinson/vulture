"""V3, V10: round-trip serialisation of validate types."""

import json

from shared.validate.types import (
    FindingValidation,
    ValidateConfig,
    ValidationCheck,
    ValidationResult,
)


def _normalize(d):
    """Drop computed/non-equality fields so re-runs compare cleanly (M3)."""
    if isinstance(d, dict):
        d.pop("validated_at", None)
        d.pop("duration_ms", None)
        for v in d.values():
            _normalize(v)
    elif isinstance(d, list):
        for v in d:
            _normalize(v)
    return d


def test_validation_check_round_trip():
    c = ValidationCheck(
        id="path", result="demoted", weight=-0.20,
        reason="path matches test/", extras={"file_path": "/x/tests/y.py"},
    )
    j = c.to_json()
    j = json.loads(json.dumps(j))
    c2 = ValidationCheck.from_json(j)
    assert c == c2


def test_finding_validation_round_trip():
    v = FindingValidation(
        status="suspicious", confidence=0.40,
        checks=[
            ValidationCheck(id="path", result="demoted", weight=-0.20),
            ValidationCheck(id="rollup", result="singleton", weight=0.0),
        ],
    )
    j = v.to_json()
    j = json.loads(json.dumps(j))
    v2 = FindingValidation.from_json(j)
    assert _normalize(v.to_json()) == _normalize(v2.to_json())


def test_validation_result_round_trip_empty():
    r = ValidationResult(findings=[], rollups=[], event_texts=["[validate] empty"])
    j = r.to_json()
    r2 = ValidationResult.from_json(json.loads(json.dumps(j)))
    assert _normalize(r.to_json()) == _normalize(r2.to_json())


def test_validation_result_round_trip_realistic():
    """30+ representative shapes — abbreviated to 5 for unit-test speed."""
    r = ValidationResult(
        findings=[
            {"id": "f1", "category": "CWE-89", "validation_status": "high_confidence"},
            {"id": "f2", "category": "CWE-22", "validation_status": "likely_fp"},
            {"id": "f3", "category": "CWE-79", "validation_status": "suspicious"},
        ],
        rollups=[{"id": "rollup-abc", "is_rollup": True, "instance_count": 5}],
        event_texts=["[validate] L1 done", "[validate] done"],
        layers_run=["L1", "L2", "vote"],
        duration_ms={"L1": 12, "L2": 3, "vote": 1},
    )
    j = json.loads(json.dumps(r.to_json()))
    r2 = ValidationResult.from_json(j)
    assert len(r2.findings) == 3
    assert len(r2.rollups) == 1
    assert r2.layers_run == ["L1", "L2", "vote"]


def test_validate_config_defaults():
    cfg = ValidateConfig()
    assert cfg.compliance_mode is False
    assert cfg.use_llm is False
    assert cfg.enable_l1 is True
    assert cfg.enable_l2 is True
    assert cfg.enable_l5 is False
    # Feature 0046 D4: locked default at 1000 (was 100 in 0045).
    assert cfg.top_n_for_llm == 1000
