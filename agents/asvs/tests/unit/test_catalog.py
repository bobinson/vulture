"""Tests for ASVS catalog helpers."""

from asvs_agent.catalog import (
    build_catalog_context,
    enrich_finding,
    get_requirement,
    get_requirements_by_chapter,
    get_requirements_by_level,
    is_applicable_at_level,
    load_catalog,
)


def test_load_catalog_has_345_requirements():
    assert len(load_catalog()) == 345


def test_get_requirement_v3_4_2():
    e = get_requirement("V3.4.2")
    assert e is not None
    assert e["chapter_id"] == "V3"
    assert "1004" in e["cwe_ids"]


def test_get_requirements_by_chapter():
    v3 = get_requirements_by_chapter("V3")
    assert len(v3) > 0
    assert all(e["chapter_id"] == "V3" for e in v3)


def test_get_requirements_by_level_l1_is_70():
    """ASVS v5.0.0 has 70 reqs applying at L1 (level == 1)."""
    l1_only = [e for e in load_catalog().values() if e["level"] == 1]
    assert len(l1_only) == 70


def test_is_applicable_at_level_l2_applies_at_l3():
    assert is_applicable_at_level({"level": 2}, 3) is True


def test_is_applicable_at_level_l3_does_not_apply_at_l2():
    assert is_applicable_at_level({"level": 3}, 2) is False


def test_is_applicable_at_level_l1_applies_everywhere():
    for target in (1, 2, 3):
        assert is_applicable_at_level({"level": 1}, target) is True


def test_get_requirements_by_level_l2_includes_l1_and_l2():
    reqs = get_requirements_by_level([1, 2])
    assert len(reqs) == 253


def test_enrich_finding_adds_metadata():
    f = {"category": "ASVS-V3.4.2"}
    enriched = enrich_finding(f, "V3.4.2")
    assert enriched["chapter_id"] == "V3"
    assert enriched["chapter_name"]
    assert "1004" in enriched["cwe_ids"]
    assert enriched["level"] in (1, 2, 3)


def test_enrich_finding_with_missing_req_returns_unchanged():
    f = {"category": "ASVS-V999.99.99"}
    enriched = enrich_finding(f, "V999.99.99")
    assert enriched == f


def test_build_catalog_context_contains_req_ids():
    ctx = build_catalog_context(["V3.4.2", "V6.2.2"])
    assert "ASVS-V3.4.2" in ctx
    assert "ASVS-V6.2.2" in ctx


def test_build_catalog_context_respects_max_chars():
    ctx = build_catalog_context(["V3.4.2"] * 100, max_chars=200)
    assert len(ctx) <= 400  # Some slack for line assembly
