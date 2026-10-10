"""Feature 0074 P-1 (T-1.2, AC33) — the LLM-family rule is ONE rule in two
languages.

The Go backend classifies a finding as LLM-authored with ``isLLMProvenance``
(``strings.HasPrefix(strings.ToLower(strings.TrimSpace(p)), "llm")``). The
agents' L5 safeguard decides the opposite question, "is this row
deterministic", with ``validate.llm_judge._is_deterministic``. If the two
disagree on a spelling, one row is "LLM" to the backend's dedup guard and
"deterministic" (demotion-immune) to the judge: hazard D1b.

Both halves read the same fixture,
``backend/internal/handler/testdata/llm_provenance_family_0074.json``; the Go
half is ``backend/internal/handler/llm_family_parity_0074_test.go``. Every row
here carries a ``check_id`` — the D1b precondition — so the only thing that can
make it non-deterministic is the LLM-family rule.
"""

from __future__ import annotations

import pytest

from tests.support.llm_family import cases as _cases


def test_fixture_is_shared_and_covers_the_plan_list():
    """AC33: the shared list names every spelling T-1.2 enumerates, plus the
    rows that tell a PREFIX rule from a substring rule ("llm" in p): an
    implementation that matched anywhere in the string would agree on the
    plan list yet call "skill_llm" LLM-authored, which Go's HasPrefix does not."""
    names = {c["provenance"] for c in _cases()}
    assert {"skill", "llm", "llm_l5_verified", "LLM", " llm ", "semgrep", "signature",
            "skill_llm", "semgrep-llm", "llmfoo"} <= names


@pytest.mark.parametrize("case", _cases(), ids=lambda c: repr(c["provenance"]))
def test_python_llm_family_rule_agrees_with_go(case):
    """AC33: a row is deterministic exactly when Go says it is NOT LLM-authored
    (given a check_id and no candidate signature)."""
    from shared.validate.llm_judge import _is_deterministic

    finding = {"provenance": case["provenance"], "check_id": "any.check"}
    assert _is_deterministic(finding) is (not case["is_llm"]), (
        f"provenance={case['provenance']!r}: Go isLLMProvenance says is_llm={case['is_llm']}, "
        "so the Python deterministic predicate must say the opposite"
    )


# --------------------------------------------------------------------------- #
# Review item 7 — every Python reader of the rule iterates the shared fixture
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("case", _cases(), ids=lambda c: repr(c["provenance"]))
def test_is_llm_provenance_agrees_with_go(case):
    """The rule itself, not only its deterministic complement."""
    from shared.provenance import is_llm_provenance

    assert is_llm_provenance(case["provenance"]) is case["is_llm"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: repr(c["provenance"]))
def test_result_helper_uses_the_one_rule(case):
    """``tests.support.agent_run.llm_rows`` — the helper every 0074 counter test
    reads the result through — classifies exactly as Go does."""
    from tests.support.agent_run import llm_rows

    payload = {"findings": [{"provenance": case["provenance"]}]}
    assert bool(llm_rows(payload)) is case["is_llm"]


@pytest.mark.parametrize("case", [c for c in _cases() if c["provenance"]],
                         ids=lambda c: repr(c["provenance"]))
def test_agent_dedup_records_merged_llm_by_the_one_rule(case):
    """C3 + O1: a dropped row is recorded on a skill survivor iff its
    provenance is LLM-family. (A row with NO provenance reaching the agent's
    dedup is an LLM row by construction — the tag is set after it — so the
    empty spelling is not a dedup case.)"""
    from shared.audit_runner import _deduplicate_findings

    base = [{"check_id": "c", "file_path": "a.py", "provenance": "skill"}]
    _deduplicate_findings(base, [{"check_id": "c", "file_path": "a.py",
                                  "provenance": case["provenance"]}])
    assert ("merged_llm" in base[0]) is case["is_llm"]
