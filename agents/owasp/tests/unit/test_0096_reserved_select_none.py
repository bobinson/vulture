"""`A00` is the mapping result's reserved "select nothing" id (0096).

When a `categories` filter leaves no usable id, the agent sends
``selected: ["A00"]`` so the backend labels nothing rather than everything.
That only works while no edition defines an A00 category.
"""
import json
from pathlib import Path

from owasp_agent.agent import _SELECT_NONE

EDITIONS = Path(__file__).resolve().parents[3] / "shared" / "shared" / "owasp" / "editions"


def test_select_none_sentinel_is_a00():
    assert _SELECT_NONE == "A00"


def test_no_edition_defines_the_reserved_id():
    files = sorted(EDITIONS.glob("owasp_*.json"))
    assert files, f"no edition files under {EDITIONS}"
    for path in files:
        data = json.loads(path.read_text())
        ids = {c.get("id") for c in data.get("categories", [])}
        assert ids, f"{path.name}: no category ids read — the guard would pass vacuously"
        assert "A00" not in ids, f"{path.name} defines A00, the reserved select-nothing id"
