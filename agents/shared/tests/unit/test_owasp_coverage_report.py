"""Unit tests for the OWASP coverage manifest builder (feature 0063)."""

import json

from shared.owasp.coverage import build_manifest
from shared.owasp.mapping import load_edition


def test_manifest_covers_every_category():
    m = build_manifest(load_edition("2021"), detected_cwes={89, 918})
    assert len(m.categories) == 10  # nothing omitted
    a03 = next(c for c in m.categories if c.id == "A03")
    assert 89 in a03.found_cwes and a03.status == "found"
    assert next(c for c in m.categories if c.id == "A10").found_cwes == [918]


def test_empty_category_reported_not_dropped():
    m = build_manifest(load_edition("2021"), detected_cwes=set())
    a01 = next(c for c in m.categories if c.id == "A01")
    assert a01.found_count == 0 and a01.status == "clean-or-undetected"
    assert a01.mapped_count == 34


def test_manifest_records_cwe_stage_status():
    m = build_manifest(load_edition("2021"), detected_cwes=set(), cwe_stage_status="failed")
    d = m.to_dict()
    assert d["cwe_stage_status"] == "failed"
    assert d["edition"] == "2021"
    json.dumps(d)  # must be json-serialisable


def test_manifest_default_status_completed():
    m = build_manifest(load_edition("2025"), detected_cwes={918})
    assert m.to_dict()["cwe_stage_status"] == "completed"
    # 2025 folded SSRF into A01 — the manifest reflects the selected edition.
    a01 = next(c for c in m.categories if c.id == "A01")
    assert "CWE-918" in a01.to_dict()["found_cwes"]
