"""Feature 0074 O3 / AC37 — the anchor attestation carries the claim's range.

O3 = C put ``claimed_line_range`` (``in_file`` / ``past_eof`` / ``no_line``)
beside every anchor verdict, and AC37 gave a lone candidate past
``VULTURE_LLM_QUOTE_MAX_DELTA`` its own ``ambiguous`` reason,
``beyond_max_delta``. The generated ``ANCHOR_STATUS.md`` showed neither, so a
regression in either was invisible in the one table built to make verifier
drift visible. The column is DERIVED per claim from ``anchor.claimed_line_range``
— the same function the anchor stamp calls — never typed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from shared.anchor import claimed_line_range

_TOOL = Path(__file__).resolve().parents[2] / "tools" / "report_anchor_status.py"


@pytest.fixture(scope="module")
def reporter():
    spec = importlib.util.spec_from_file_location("report_anchor_status_0074_range", _TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_row_carries_the_derived_claimed_range(reporter) -> None:
    entries = reporter.load_manifest()
    rows = reporter.build_rows()
    expected = [claimed_line_range(reporter._finding(e), reporter._resolved(e)) or "-"
                for e in entries]
    assert [row["claimed_range"] for row in rows] == expected
    assert "in_file" in expected  # non-vacuous: the column says something


def test_outcome_table_has_the_column_and_names_the_reasons(reporter) -> None:
    table = "\n".join(reporter._outcome_table(reporter.build_rows()))
    assert "| claimed range |" in table
    assert "`claimed_line_range`" in table
    assert "`beyond_max_delta`" in table
