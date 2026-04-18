"""Tests for ASVS agent configuration."""

from asvs_agent.config import ALL_CATEGORIES, AGENT_INFO, CONFIG_SCHEMA


def test_all_categories_has_single_entry():
    assert ALL_CATEGORIES == ["asvs_requirements"]


def test_agent_info_basics():
    assert AGENT_INFO["type"] == "asvs"
    assert AGENT_INFO["name"] == "ASVS Compliance Auditor"
    assert "345" in AGENT_INFO["description"]
    assert "17 chapters" in AGENT_INFO["description"]


def test_config_schema_has_chapters_and_levels():
    props = CONFIG_SCHEMA["properties"]
    assert "chapters" in props
    assert "levels" in props


def test_config_schema_chapters_enum_has_17_entries():
    chapters = CONFIG_SCHEMA["properties"]["chapters"]["items"]["enum"]
    assert len(chapters) == 17
    assert chapters[0] == "V1"
    assert chapters[-1] == "V17"


def test_config_schema_levels_enum():
    levels = CONFIG_SCHEMA["properties"]["levels"]["items"]["enum"]
    assert levels == [1, 2, 3]


def test_config_schema_levels_default():
    assert CONFIG_SCHEMA["properties"]["levels"]["default"] == [1, 2, 3]
