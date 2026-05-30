"""Integration tests: full validate() end-to-end + V6 + V8."""

from shared.validate import ValidateConfig, validate


def _f(idx, **overrides):
    base = {
        "id": f"f-{idx}",
        "category": "CWE-89",
        "severity": "high",
        "title": "Potential SQL injection",
        "description": "test",
        "file_path": "/tmp/some/file.py",
        "line_start": 10,
        "line_end": 10,
        "recommendation": "use parameterized queries",
    }
    base.update(overrides)
    return base


def test_v6_length_preserving_empty():
    r = validate([])
    assert r.findings == []
    assert r.rollups == []


def test_v6_length_preserving_one_finding():
    r = validate([_f(1)])
    assert len(r.findings) == 1


def test_v6_length_preserving_with_rollup():
    """L2 rollup must NOT remove member findings (V6)."""
    findings = [
        _f(1, file_path="/tmp/x.py", line_start=10),
        _f(2, file_path="/tmp/x.py", line_start=20),
        _f(3, file_path="/tmp/x.py", line_start=30),
    ]
    r = validate(findings, audit_id="t-audit")
    assert len(r.findings) == 3, "members must stay in dataset"
    assert len(r.rollups) == 1, "one rollup parent emitted"
    # All members reference the rollup parent.
    parent_id = r.rollups[0]["id"]
    for f in r.findings:
        rollup_checks = [c for c in f["validation"]["checks"] if c["id"] == "rollup"]
        assert rollup_checks, "each member has a rollup check"
        assert rollup_checks[0]["extras"]["rolled_up_into"] == parent_id


def test_v8_compliance_mode_prevents_likely_fp():
    """Compliance mode never produces likely_fp regardless of layer outputs."""
    findings = [
        _f(1, file_path="/tmp/tests/foo_test.py", line_start=10),
        _f(2, file_path="/tmp/tests/bar_test.py", line_start=20),
    ]
    # With compliance_mode=true, even findings that would normally
    # land in likely_fp are kept at suspicious.
    r = validate(
        findings, audit_id="t-audit",
        config=ValidateConfig(compliance_mode=True),
    )
    for f in r.findings:
        assert f["validation_status"] != "likely_fp", (
            f"compliance mode must not produce likely_fp; got {f['validation_status']}"
        )


def test_path_classifier_demotes_test_paths():
    """Test paths get a `path` check with negative weight."""
    findings = [_f(1, file_path="/src/tests/test_foo.py", line_start=5)]
    r = validate(findings)
    checks = r.findings[0]["validation"]["checks"]
    path_check = next((c for c in checks if c["id"] == "path"), None)
    assert path_check is not None
    assert path_check["weight"] < 0


def test_idempotency_replaces_validation():
    """M5: re-running validate replaces the validation blob."""
    findings = [_f(1)]
    r1 = validate(findings)
    # Re-run with the already-validated finding.
    second_input = list(r1.findings)
    r2 = validate(second_input)
    assert r2.findings[0]["validation"]["status"] == r1.findings[0]["validation"]["status"]
    # validated_at timestamps differ but the structure is the same
    assert len(r2.findings[0]["validation"]["checks"]) > 0


def test_disable_validate_via_env(monkeypatch):
    """is_enabled honors VULTURE_DISABLE_VALIDATE."""
    from shared.validate import is_enabled
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "true")
    assert is_enabled({}) is False
    monkeypatch.setenv("VULTURE_DISABLE_VALIDATE", "")
    assert is_enabled({}) is True
    assert is_enabled({"disable_validate": True}) is False


def test_layer_isolation_l1_error_does_not_kill_l2(monkeypatch):
    """RC3: a layer's failure must not nullify other layers' output."""
    import shared.validate.context_heuristics as ch

    def boom(_):
        raise RuntimeError("simulated L1 catastrophe")

    monkeypatch.setattr(ch, "run_l1", boom)
    findings = [_f(1), _f(2), _f(3)]
    r = validate(findings, audit_id="iso-test")
    assert len(r.findings) == 3, "V6 preserved despite L1 crash"
    for f in r.findings:
        assert "validation" in f, "each finding still has a validation blob"
