"""Feature 0104 WS-A2, D-S (2) follow-up: a group row's LLM merges keep contract T3's bound.

Contract T3 (0074 C3): ``merged_llm`` rides the raw ``result`` snapshot to live clients before
Go persists anything, so one row carries at most ``MERGED_LLM_MAX_ENTRIES`` entries, and an
entry refused at the cap is counted in ``merged_llm_dropped``. Under D-S (2) the group row
gathers its members' merges; it keeps the same bound: the first entries in member order, the
rest counted with the members' own drop counts. The members keep exactly their own merges.

RED until the fold caps the gathered list (it concatenated every member's entries).
"""

from __future__ import annotations

from typing import Any

from shared import provenance
from tests.unit.ast._0104 import _carrying, _fold, _members

CAP = 8
PER_MEMBER = 4


def _merges(member: int) -> dict[str, Any]:
    """``PER_MEMBER`` distinct LLM merges for one member, and one already-dropped entry."""
    entries = [
        {"provenance": "llm", "description": f"model note {member}.{n}"}
        for n in range(PER_MEMBER)
    ]
    return {"merged_llm": entries, "merged_llm_dropped": 1}


def _group_row() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    members = _carrying(_members(), {i: _merges(i) for i in range(3)})
    rows = _fold(members)
    return rows[0], members


def test_the_group_row_keeps_at_most_the_cap() -> None:
    group, _ = _group_row()
    assert len(group["merged_llm"]) == CAP


def test_the_kept_entries_are_the_first_in_member_order() -> None:
    group, members = _group_row()
    gathered = [entry for row in members for entry in row["merged_llm"]]
    assert group["merged_llm"] == gathered[:CAP]


def test_entries_past_the_cap_are_counted_as_dropped() -> None:
    group, members = _group_row()
    overflow = len(members) * PER_MEMBER - CAP
    assert group["merged_llm_dropped"] == len(members) + overflow


def test_the_cap_is_the_shared_one() -> None:
    assert provenance.MERGED_LLM_MAX_ENTRIES == CAP
