from do178c_agent.config import (
    ALL_CATEGORIES,
    AGENT_INFO,
    CONFIG_SCHEMA,
    DAL_LEVELS,
    dal_severity,
    dal_skip,
)


def test_all_categories_has_six_skills():
    assert len(ALL_CATEGORIES) == 6
    assert "dead_code" in ALL_CATEGORIES
    assert "mcdc_coverage" in ALL_CATEGORIES
    assert "recursion" in ALL_CATEGORIES
    assert "malloc" in ALL_CATEGORIES
    assert "traceability" in ALL_CATEGORIES
    assert "timing" in ALL_CATEGORIES


def test_dal_levels():
    assert DAL_LEVELS == ["A", "B", "C", "D", "E"]


def test_dal_severity_returns_correct_level():
    assert dal_severity("A", "dead_code") == "critical"
    assert dal_severity("B", "mcdc_coverage") == "high"
    assert dal_severity("D", "dead_code") == "medium"


def test_dal_skip_returns_true_for_excluded():
    assert dal_skip("E", "dead_code") is True
    assert dal_skip("C", "mcdc_coverage") is True
    assert dal_skip("A", "dead_code") is False


def test_agent_info_has_required_fields():
    assert AGENT_INFO["type"] == "do178c"
    assert "name" in AGENT_INFO
    assert "config_schema" in AGENT_INFO


def test_config_schema_has_dal_and_categories():
    props = CONFIG_SCHEMA["properties"]
    assert "dal_level" in props
    assert "categories" in props
    assert props["dal_level"]["enum"] == ["A", "B", "C", "D", "E"]
