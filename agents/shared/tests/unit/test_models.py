"""Unit tests for shared models."""

import pytest
from pydantic import ValidationError

from shared.models.finding import Finding, Severity


class TestSeverity:
    """Tests for Severity enum."""

    def test_all_levels_exist(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_is_string_enum(self):
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.CRITICAL == "critical"


class TestFinding:
    """Tests for Finding pydantic model."""

    def test_valid_finding(self):
        f = Finding(
            id="f-1",
            audit_id="a-1",
            agent_type="chaos",
            severity=Severity.HIGH,
            category="retry",
            title="Missing retry",
            description="No retry on HTTP call",
            file_path="/src/client.py",
            line_start=10,
            line_end=15,
            recommendation="Add retry with backoff",
        )
        assert f.severity == Severity.HIGH
        assert f.title == "Missing retry"

    def test_defaults(self):
        f = Finding(
            id="f-2",
            audit_id="a-1",
            agent_type="owasp",
            severity=Severity.MEDIUM,
            category="auth",
            title="Weak hash",
            description="Using MD5",
        )
        assert f.file_path == ""
        assert f.line_start == 0
        assert f.line_end == 0
        assert f.recommendation == ""
        assert f.references == []

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            Finding(
                id="f-3",
                audit_id="a-1",
                agent_type="chaos",
                severity="invalid",
                category="test",
                title="Test",
                description="Test",
            )

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            Finding(id="f-4", severity=Severity.LOW)

    def test_serialization(self):
        f = Finding(
            id="f-5",
            audit_id="a-1",
            agent_type="soc2",
            severity=Severity.CRITICAL,
            category="access",
            title="No logging",
            description="Audit logging missing",
        )
        d = f.model_dump()
        assert d["severity"] == "critical"
        assert d["id"] == "f-5"
        assert isinstance(d["references"], list)
