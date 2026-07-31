"""Detected CWEs that no OWASP category maps must still be reported.

The manifest reported only the intersection of detected CWEs with each
category's mapped set. Anything outside every category vanished: on a
one audit, 112 of 866 CWE findings mapped to no 2025 category and so
were invisible in the OWASP view, while the report still read as complete.

That is the same class of dishonesty as an inflated category — the operator
cannot tell "we found nothing there" from "we found something the taxonomy
does not place". An explicit unmapped bucket makes the residue visible without
inventing a mapping for it.
"""

import json

from shared.owasp.coverage import build_manifest
from shared.owasp.mapping import load_edition


def test_unmapped_cwe_is_reported_not_dropped():
    # CWE-1104 is mapped by 2025; CWE-99999 is mapped by nothing.
    m = build_manifest(load_edition("2025"), detected_cwes={1104, 99999})
    assert 99999 in m.unmapped_cwes, "a detected CWE outside every category must be surfaced"
    assert 1104 not in m.unmapped_cwes, "a mapped CWE must not appear in the unmapped bucket"


def test_unmapped_bucket_is_empty_when_all_mapped():
    m = build_manifest(load_edition("2025"), detected_cwes={1104})
    assert m.unmapped_cwes == []


def test_unmapped_appears_in_serialised_manifest():
    m = build_manifest(load_edition("2025"), detected_cwes={1104, 99999})
    d = m.to_dict()
    assert d["unmapped_cwes"] == ["CWE-99999"]
    assert d["unmapped_count"] == 1
    json.dumps(d)  # must stay json-serialisable


def test_every_detected_cwe_is_accounted_for():
    """The invariant: mapped-and-found plus unmapped equals everything detected."""
    detected = {79, 89, 1104, 99999, 88888}
    m = build_manifest(load_edition("2025"), detected_cwes=detected)
    placed = set()
    for c in m.categories:
        placed |= set(c.found_cwes)
    assert placed | set(m.unmapped_cwes) == detected, \
        "no detected CWE may disappear between detection and the manifest"


def test_existing_category_shape_is_unchanged():
    """Additive only — the four pre-existing category keys must survive."""
    d = build_manifest(load_edition("2025"), detected_cwes={1104}).to_dict()
    cat = d["categories"][0]
    for key in ("id", "name", "mapped_count", "found_cwes", "found_count", "status", "source_url"):
        assert key in cat, f"category key {key} must not be removed"
    assert d["edition"] == "2025" and "cwe_stage_status" in d
