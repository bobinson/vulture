"""Unit tests for the OWASP edition mapping engine (feature 0063)."""

import pytest

from shared.owasp.mapping import (
    UnknownEditionError,
    available_editions,
    load_edition,
    parse_cwe_id,
)


def test_default_edition_is_2025():
    ed = load_edition()
    assert ed.edition_id == "2025"
    assert len(ed.categories) == 10


def test_available_editions_lists_both():
    assert set(available_editions()) >= {"2021", "2025"}


def test_parse_cwe_id():
    assert parse_cwe_id("CWE-1321") == 1321
    assert parse_cwe_id("CWE-89") == 89
    assert parse_cwe_id(" CWE-918 ") == 918
    assert parse_cwe_id("A03-injection") is None
    assert parse_cwe_id("") is None


def test_map_cwe_to_category_2021():
    assert any(c.id == "A03" for c in load_edition("2021").map_cwe(89))


def test_ssrf_maps_only_to_a10_in_2021():
    assert [c.id for c in load_edition("2021").map_cwe(918)] == ["A10"]


def test_ssrf_moves_into_a01_in_2025():
    # 2025 folded SSRF (CWE-918) into Broken Access Control.
    assert [c.id for c in load_edition("2025").map_cwe(918)] == ["A01"]


def test_map_cwe_returns_empty_list_for_unmapped():
    assert load_edition("2021").map_cwe(999999) == []


def test_map_cwe_return_type_is_list():
    # Engine supports multi-category membership; result is always a list.
    assert isinstance(load_edition("2021").map_cwe(89), list)


def test_unknown_edition_raises():
    with pytest.raises(UnknownEditionError):
        load_edition("1999")


def test_categories_have_source_urls():
    for ed_id in available_editions():
        for c in load_edition(ed_id).categories:
            assert c.source_url.startswith("https://owasp.org"), (ed_id, c.id)
