"""Guard: the backend 0050 representative-CWE map agrees with the shared editions.

Feature 0050 ships `backend/internal/cwe/data/category_to_cwe.json`, mapping each
OWASP category slug to ONE representative CWE. Feature 0063 ships the full
per-category CWE membership as the single source of truth. This test fails if
the 0050 representative for a category is NOT a member of that category in the
2021 edition — catching silent divergence between the two artifacts.
"""

import json
import pathlib
import re

from shared.owasp.mapping import load_edition, parse_cwe_id

# test file: agents/shared/tests/unit/ -> repo root is parents[4].
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
_MAP_PATH = _REPO_ROOT / "backend" / "internal" / "cwe" / "data" / "category_to_cwe.json"

_CATEGORY_PREFIX = re.compile(r"^(A\d{2})-")


def test_0050_map_file_is_present():
    # The map is a committed, load-bearing artifact; its absence is a failure,
    # not a reason to skip (no silent skip — audit finding R1).
    assert _MAP_PATH.exists(), f"0050 map not found at {_MAP_PATH}"


def test_representative_cwe_is_a_member_of_its_2021_category():
    mapping = json.loads(_MAP_PATH.read_text("utf-8"))
    ed = load_edition("2021")
    by_id = {c.id: c for c in ed.categories}

    mismatches = []
    for slug, cwe_str in mapping.items():
        m = _CATEGORY_PREFIX.match(slug)
        if not m:
            continue  # non-OWASP entries (SSDF PO/PS/PW/RV) are out of scope
        cat_id = m.group(1)
        cat = by_id.get(cat_id)
        if cat is None:
            mismatches.append((slug, cwe_str, "no such category id in edition"))
            continue
        cwe = parse_cwe_id(cwe_str)
        if cwe is None:
            mismatches.append((slug, cwe_str, "unparseable CWE"))
        elif cwe not in cat.cwes:
            mismatches.append((slug, cwe_str, f"not in {cat_id} membership"))

    assert not mismatches, (
        "0050 representative CWEs diverge from the 2021 edition membership: "
        f"{mismatches}"
    )
