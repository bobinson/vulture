"""Cross-language voter parity — the Python half.

Both voters consume `backend/internal/service/testdata/voter_parity_cases.json`
and must produce identical `(status, confidence)`. The Go half is
`validation_voter_parity_test.go`; the fixture lives beside it so there is
exactly one copy.

Feature 0072 created this pair. Before it, `voter.py`'s header claimed the test
existed and that CI failed on drift, `validation_voter.go`'s header said it was
a follow-up, and neither the fixture nor either test was present — so the two
implementations were free to diverge silently. That matters more now that a
check's `result` carries gate semantics across the process boundary.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from shared.validate.types import ValidationCheck
from shared.validate.voter import (
    AUTHORITATIVE_CHECKS,
    AUTHORITATIVE_POSITIVE,
    JUDGE_CITED,
    JUDGE_UNCITED,
    JUDGE_UNDECIDED,
    OBLIGATION_DISCHARGED,
    OBLIGATION_ID,
    OBLIGATION_REFUTED,
    OBLIGATION_UNKNOWN,
    vote,
)

# .../agents/shared/tests/unit/validate/test_voter_parity.py
#   parents: [0]=validate [1]=unit [2]=tests [3]=shared [4]=agents [5]=repo root
_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[5]
    / "backend/internal/service/testdata/voter_parity_cases.json"
)


def _load() -> list[dict]:
    if not _FIXTURE.exists():  # pragma: no cover - guards a moved fixture
        pytest.skip(
            f"parity fixture not found at {_FIXTURE}", allow_module_level=True
        )
    return json.loads(_FIXTURE.read_text())["cases"]


def _ids(cases: list[dict]) -> list[str]:
    return [c["name"] for c in cases]


_CASES = _load()


@pytest.mark.parametrize("case", _CASES, ids=_ids(_CASES))
def test_voter_parity(case: dict) -> None:
    checks = [
        ValidationCheck(
            id=c["id"], result=c.get("result", ""), weight=c["weight"], reason=""
        )
        for c in case["checks"]
    ]
    status, confidence = vote(checks)

    assert status == case["want"]["status"], (
        f"status drift on {case['name']!r}: "
        f"python={status!r} fixture={case['want']['status']!r}"
    )
    assert confidence == pytest.approx(case["want"]["confidence"]), (
        f"confidence drift on {case['name']!r}: "
        f"python={confidence} fixture={case['want']['confidence']}"
    )


def test_parity_literals_pinned() -> None:
    """The obligation state and judge admissibility cross a process boundary as
    bare strings. If Go and Python drift on a literal the gate silently
    disables, because each side stays self-consistent and no behavioural test
    fails. Both halves pin the same values.
    """
    assert OBLIGATION_ID == "obligation"
    assert OBLIGATION_UNKNOWN == "unknown"
    assert OBLIGATION_DISCHARGED == "discharged"
    assert OBLIGATION_REFUTED == "refuted"
    assert JUDGE_CITED == "real_bug"
    assert JUDGE_UNCITED == "real_bug_uncited"
    assert JUDGE_UNDECIDED == "undecided"
    assert AUTHORITATIVE_POSITIVE == frozenset({"memory"})
    assert AUTHORITATIVE_CHECKS == frozenset({"suppression"})


def test_fixture_covers_every_gate_branch() -> None:
    """A rule added to either voter without a fixture case is exactly the drift
    this pair exists to catch."""
    seen: set[str] = set()
    for case in _CASES:
        for c in case["checks"]:
            if c["id"] == OBLIGATION_ID:
                seen.add(f"obligation:{c.get('result')}")
            elif c["id"] == "llm_judge" and c["weight"] >= 0:
                seen.add(f"judge:{c.get('result')}")
            elif c["id"] == "memory":
                seen.add("memory:positive" if c["weight"] > 0 else "memory:negative")

    required = {
        f"obligation:{OBLIGATION_UNKNOWN}",
        f"obligation:{OBLIGATION_DISCHARGED}",
        f"obligation:{OBLIGATION_REFUTED}",
        f"judge:{JUDGE_CITED}",
        f"judge:{JUDGE_UNCITED}",
        "memory:positive",
        "memory:negative",
    }
    assert required <= seen, f"fixture is missing cases for: {sorted(required - seen)}"
