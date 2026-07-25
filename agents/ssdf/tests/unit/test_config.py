"""Unit tests for SSDF agent configuration."""

from ssdf_agent.config import ALL_PRACTICE_GROUPS, AGENT_INFO, CONFIG_SCHEMA


class TestConfig:
    """Tests for SSDF configuration."""

    def test_all_practice_groups_values(self) -> None:
        assert ALL_PRACTICE_GROUPS == ["PO", "PS", "PW", "RV"]

    def test_agent_info_type(self) -> None:
        assert AGENT_INFO["type"] == "ssdf"

    def test_agent_info_name(self) -> None:
        assert AGENT_INFO["name"] == "NIST SSDF v1.1 Auditor"

    def test_config_schema_has_practice_groups(self) -> None:
        assert "properties" in CONFIG_SCHEMA
        assert "practice_groups" in CONFIG_SCHEMA["properties"]
        pg = CONFIG_SCHEMA["properties"]["practice_groups"]
        assert pg["items"]["enum"] == ["PO", "PS", "PW", "RV"]

    def test_agent_info_skills_count(self) -> None:
        assert len(AGENT_INFO["skills"]) >= 18
