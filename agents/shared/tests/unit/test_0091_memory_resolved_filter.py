"""Feature 0091 §8 — which remediation statuses leave the "known issues" block.

``_filter_and_dedup``'s docstring has always said it "filters out resolved
findings". Its body did not: it filtered by confidence weight, edges and MMR
only. That gap is load-bearing now, because lineage transitions write
``remediation_status`` back to the memory row (D1a) — a finding the scanner has
closed would otherwise stay in the block that tells the model to skip it, so it
could never be re-reported and never become a ``regression`` (S11).

The other half of the rule is just as deliberate: ``false_positive`` and
``accepted_risk`` STAY in the block (S13). A human ruled on those, and dropping
them would invite the model to re-report exactly what someone already dismissed.
"""

from __future__ import annotations

from typing import Any

from shared.tools.memory_client import _filter_and_dedup


def _memory(title: str, status: str) -> dict[str, Any]:
    """One memory row, distinct enough that dedup never merges two of them."""
    return {
        "title": title,
        "severity": "high",
        "category": "security",
        "file_paths": [f"src/{title.replace(' ', '_').lower()}.py"],
        "remediation_status": status,
        "confidence_score": 0.9,
        "created_at": "",
    }


def _titles(rows: list[dict[str, Any]]) -> set[str]:
    return {row["title"] for row in rows}


def test_resolved_memories_are_excluded() -> None:
    kept = _filter_and_dedup([
        _memory("Hardcoded API token", "open"),
        _memory("Command injection in migrate helper", "resolved"),
    ])

    assert _titles(kept) == {"Hardcoded API token"}


def test_dismissed_memories_are_kept() -> None:
    """S13: the model must not re-report a finding a human already ruled on."""
    kept = _filter_and_dedup([
        _memory("Hardcoded API token", "false_positive"),
        _memory("Weak hash in password path", "accepted_risk"),
        _memory("Unbounded log retention", "in_progress"),
        _memory("Missing timeout on outbound call", "regression"),
    ])

    assert _titles(kept) == {
        "Hardcoded API token",
        "Weak hash in password path",
        "Unbounded log retention",
        "Missing timeout on outbound call",
    }


def test_status_matching_is_case_and_whitespace_insensitive() -> None:
    """The value arrives from two repos and a Go struct; don't trust its shape."""
    kept = _filter_and_dedup([_memory("Hardcoded API token", "  Resolved ")])

    assert kept == []


def test_a_missing_status_is_not_resolved() -> None:
    """5,750 persisted rows predate the field; absence must never close one."""
    row = _memory("Hardcoded API token", "open")
    del row["remediation_status"]

    assert _titles(_filter_and_dedup([row])) == {"Hardcoded API token"}


def test_a_resolved_duplicate_cannot_take_its_open_twin_out_of_the_block() -> None:
    """Why the filter runs BEFORE the dedup passes.

    ``_text_dedup`` keeps the first row of a title+path group. Filtering after
    it would let a resolved row win the group and then be dropped, removing the
    still-open finding from the block along with it.
    """
    resolved = _memory("Hardcoded API token", "resolved")
    still_open = _memory("Hardcoded API token", "open")

    kept = _filter_and_dedup([resolved, still_open])

    assert _titles(kept) == {"Hardcoded API token"}
