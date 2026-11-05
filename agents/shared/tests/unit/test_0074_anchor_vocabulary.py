"""Feature 0074 review items 20 and 43c — the anchor vocabulary is declared
once and every Python reader resolves a duplicated check the same way.

``tests/contract/anchor_vocabulary_0074.json`` exports ``anchor.py``'s check
id, statuses and claimed-line ranges for the frontend tests; this file pins it
to the source of truth. The voter and the L1 stage use ``ANCHOR_CHECK_ID``
rather than a literal, and the duplicate rule is LAST-wins in every reader
(``anchor_extras`` already was; the window-reason reader was first-wins).

All fixtures are synthetic.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from shared import anchor
from shared.tools.window import window_reason_of
from shared.validate import context_heuristics, voter

_FIXTURE = Path(__file__).resolve().parents[1] / "contract" / "anchor_vocabulary_0074.json"
_VOCAB = json.loads(_FIXTURE.read_text())


def test_fixture_matches_anchor_py() -> None:
    assert (_VOCAB["check_id"], set(_VOCAB["statuses"]), set(_VOCAB["claimed_line_ranges"])) == (
        anchor.ANCHOR_CHECK_ID, set(anchor.STATUSES), set(anchor.CLAIMED_LINE_RANGES))
    assert _VOCAB["duplicate_rule"] == "last"


def test_voter_names_the_anchor_check_by_its_constant() -> None:
    assert anchor.ANCHOR_CHECK_ID in voter.AUTHORITATIVE_CHECKS
    assert '"anchor"' not in inspect.getsource(voter), "voter redeclares the literal"
    assert "_ANCHOR_ID" not in vars(context_heuristics), "43c: no redundant alias"


def _two(check_id: str, first: dict, last: dict) -> dict:
    return {"validation": {"checks": [{"id": check_id, **first}, {"id": check_id, **last}]}}


def test_anchor_reader_is_last_wins() -> None:
    finding = _two(anchor.ANCHOR_CHECK_ID, {"extras": {"delta": 1}}, {"extras": {"delta": 2}})
    assert anchor.anchor_extras(finding) == {"delta": 2}


def test_window_reason_reader_is_last_wins() -> None:
    finding = _two("window", {"result": "unreadable"}, {"result": "present"})
    assert window_reason_of(finding) == "present"
