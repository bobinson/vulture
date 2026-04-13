"""Unit tests for SSDF practice group composites."""

from pathlib import Path

import pytest


@pytest.fixture
def sample_source(tmp_path: Path) -> Path:
    """Create minimal sample source."""
    (tmp_path / "app.py").write_text("def main():\n    pass\n")
    return tmp_path


class TestPracticeGroupMap:
    """Tests for practice group map."""

    def test_all_groups_in_map(self) -> None:
        from ssdf_agent.practice_groups import PRACTICE_GROUP_MAP
        assert "PO" in PRACTICE_GROUP_MAP
        assert "PS" in PRACTICE_GROUP_MAP
        assert "PW" in PRACTICE_GROUP_MAP
        assert "RV" in PRACTICE_GROUP_MAP

    def test_map_has_four_groups(self) -> None:
        from ssdf_agent.practice_groups import PRACTICE_GROUP_MAP
        assert len(PRACTICE_GROUP_MAP) == 4


class TestPOGroup:
    """Tests for PO practice group."""

    def test_po_returns_findings(self, sample_source: Path) -> None:
        from ssdf_agent.practice_groups.po_prepare import audit_po
        result = audit_po(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) > 0


class TestPSGroup:
    """Tests for PS practice group."""

    def test_ps_returns_findings(self, sample_source: Path) -> None:
        from ssdf_agent.practice_groups.ps_protect import audit_ps
        result = audit_ps(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)


class TestPWGroup:
    """Tests for PW practice group."""

    def test_pw_returns_findings(self, sample_source: Path) -> None:
        from ssdf_agent.practice_groups.pw_produce import audit_pw
        result = audit_pw(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) > 0


class TestRVGroup:
    """Tests for RV practice group."""

    def test_rv_returns_findings(self, sample_source: Path) -> None:
        from ssdf_agent.practice_groups.rv_respond import audit_rv
        result = audit_rv(str(sample_source))
        assert "findings" in result
        assert isinstance(result["findings"], list)
