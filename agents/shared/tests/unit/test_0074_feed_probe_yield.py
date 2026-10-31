"""Feature 0074 P0 T0.3 — per-extension and per-tier LLM yield in the feed probe.

Measurement only, no AC: T0.3 is what turns "the `.graphql` over-representation
comes from Tier-2 admission, not the whitelist" (§13.1) from an inference into a
reading. It EXTENDS 0075's ``shared/diag/feed_probe.py`` rather than adding a
tool (DRY), so the probe keeps calling the sweep's own helpers.

This is a SHAPE test. The probe calls no model, so every finding and anchor
count is zero here; what is pinned is that the slots exist, are zero-filled
with the full vocabulary, and that ``files_sent`` partitions the rendered feed
by the prioritiser's tiers:

    stats["yield"]["per_tier"][tier1|tier2|tier3]  -> {"files_sent", "findings"}
    stats["yield"]["per_extension"][ext]           -> {"files_sent", "findings",
                                                       "anchor_status": {STATUSES},
                                                       "claimed_line_range":
                                                           {in_file, past_eof, no_line}}

``claimed_line_range`` is O3 option C's orthogonal field; the anchor status
vocabulary itself is 0076's and is NOT changed by 0074.

Synthetic tree only: token-free names, a fresh temp directory, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared import anchor
from shared.tools.file_scanner import clear_caches

_TIERS = ("tier1", "tier2", "tier3")
_LINE_RANGE = frozenset({"in_file", "past_eof", "no_line"})


@pytest.fixture(autouse=True)
def _fresh_scan_cache():
    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Tier1: flagged.py (carries a skill finding). Tier2: main.py (entry point).
    Tier3: omega.go and schema.sql (the long tail)."""
    (tmp_path / "flagged.py").write_text("x = input()\neval(x)\n")
    (tmp_path / "main.py").write_text("def run():\n    return 1\n")
    (tmp_path / "omega.go").write_text("package omega\n\nvar V = 1\n")
    (tmp_path / "schema.sql").write_text("CREATE TABLE t (id int);\n")
    return tmp_path


def _yield_block(root: Path, llm_tier3: bool) -> dict:
    from shared.diag.feed_probe import render_feed

    finding = {"file_path": str(root / "flagged.py"), "line_start": 2}
    stats = render_feed(str(root), skill_findings=[finding], llm_tier3=llm_tier3)["stats"]
    assert "yield" in stats, f"T0.3: the probe must publish a yield block; keys={sorted(stats)}"
    return stats


def _files_sent(block: dict) -> dict[str, int]:
    return {tier: block["per_tier"][tier]["files_sent"] for tier in _TIERS}


def test_per_tier_files_sent_partitions_the_feed(tree):
    """T0.3: each rendered file is counted under exactly one prioritiser tier."""
    stats = _yield_block(tree, llm_tier3=True)
    assert _files_sent(stats["yield"]) == {"tier1": 1, "tier2": 1, "tier3": 2}
    assert sum(_files_sent(stats["yield"]).values()) == stats["files"]


def test_tier3_slot_present_and_zero_when_the_tail_is_off(tree):
    """T0.3: the tier-3 gate's effect is a reading (0), not a missing key."""
    block = _yield_block(tree, llm_tier3=False)["yield"]
    assert _files_sent(block) == {"tier1": 1, "tier2": 1, "tier3": 0}


def test_per_tier_findings_slot_is_zero_without_a_model(tree):
    """T0.3: the findings slot exists per tier; the probe calls no model."""
    block = _yield_block(tree, llm_tier3=True)["yield"]
    assert {tier: block["per_tier"][tier]["findings"] for tier in _TIERS} == dict.fromkeys(_TIERS, 0)


def test_per_extension_files_sent(tree):
    """T0.3: files sent per extension, as rendered (`.sql` reaches the feed)."""
    block = _yield_block(tree, llm_tier3=True)["yield"]["per_extension"]
    assert {ext: row["files_sent"] for ext, row in block.items()} == {".py": 2, ".go": 1, ".sql": 1}


def test_per_extension_anchor_and_line_range_slots_are_zero_filled(tree):
    """T0.3: every extension carries the full anchor-status vocabulary and the
    O3-C ``claimed_line_range`` vocabulary, zero-filled, plus a findings slot."""
    block = _yield_block(tree, llm_tier3=True)["yield"]["per_extension"]
    empty = {
        "findings": 0,
        "anchor_status": dict.fromkeys(anchor.STATUSES, 0),
        "claimed_line_range": dict.fromkeys(_LINE_RANGE, 0),
    }
    got = {ext: {key: row.get(key) for key in empty} for ext, row in block.items()}
    assert got == dict.fromkeys((".py", ".go", ".sql"), empty)


def test_yield_block_is_json_serialisable(tree):
    """The probe's CLI prints the stats as JSON, so the new block must survive it."""
    stats = _yield_block(tree, llm_tier3=True)
    assert json.loads(json.dumps(stats["yield"], sort_keys=True)) == stats["yield"]
