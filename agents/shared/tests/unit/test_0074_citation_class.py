"""0074 P5 / T5.5 / AC29 — `citation_class` is computable on BOTH bases.

0072 T5.3 records, observation-only, whether the L5 judge's `evidence_line`
merely echoes the line it was handed (`self_line`) or names a distinguishable
one (`other_line`). It compares against the finding's CURRENT `line_start`.

O6 turns the re-anchor actuator on by default, so for every re-anchored row
`line_start` is no longer the line the model claimed. Classified only on the
current line, 0072's `self_line` / `other_line` series silently changes basis
the day the flip ships, and the T4.3/T4.4 deferral's exit criterion rests on
that series (R17, §5.4 gap 4).

Contract this file pins (the plan names the property, not the key):

  * `extras["citation_class"]` keeps its meaning — the CURRENT line.
  * `extras["citation_class_claimed"]` is the same classification computed on
    the model's `claimed_line`, read from the persisted `anchor` check's extras
    (the only place the claim survives the private-field strip).
  * a row that was never re-anchored has one basis only, so the claimed-basis
    class (when recorded) equals the current one.
  * both are OBSERVATION-ONLY: neither moves the verdict's result or weight.

Synthetic fixtures only; `_verdict_to_check` is pure, no model, no network.
"""

from __future__ import annotations

from typing import Any

import pytest

_CLAIMED = 12
_CURRENT = 27


def _anchor_blob(claimed: int, current: int) -> dict[str, Any]:
    """The persisted validation blob L1 leaves on a re-anchored row."""
    return {"checks": [{
        "id": "anchor", "result": "reanchored", "weight": 0.0,
        "reason": "evidence quote: reanchored",
        "extras": {"claimed_line": claimed, "delta": current - claimed,
                   "candidates": 1},
    }]}


def _finding(*, reanchored: bool = True) -> dict[str, Any]:
    row: dict[str, Any] = {"id": "f1", "file_path": "src/app.ts",
                           "line_start": _CURRENT, "line_end": _CURRENT,
                           "provenance": "llm"}
    if reanchored:
        row["validation"] = _anchor_blob(_CLAIMED, _CURRENT)
    return row


def _check(evidence_line: Any, finding: dict[str, Any],
           evidence_file: str | None = None) -> Any:
    """The L5 check ``_verdict_to_check`` builds for one confirming verdict."""
    from shared.validate.llm_judge import _verdict_to_check

    verdict = {"id": "f1", "exploitable": 0.9, "reasoning": "x",
               "evidence_line": evidence_line, "evidence_file": evidence_file}
    return _verdict_to_check(verdict, model="m", batch_id=0, language="ts",
                             finding=finding)


def _extras(check: Any) -> dict[str, Any]:
    return dict(check.extras or {})


def _claimed_class(extras: dict[str, Any]) -> str:
    assert "citation_class_claimed" in extras, (
        "AC29: a re-anchored row's verdict must also record citation_class on "
        "the model's claimed_line (extras['citation_class_claimed'])"
    )
    return extras["citation_class_claimed"]


@pytest.mark.parametrize(("evidence", "evidence_file", "current", "claimed"), [
    (_CLAIMED, None, "other_line", "self_line"),
    (_CURRENT, None, "self_line", "other_line"),
    (40, None, "other_line", "other_line"),
    # no evidence_line is `missing` whatever the basis
    (None, None, "missing", "missing"),
    # a citation into another file: the line number is a coincidence there
    # (0089 item 4.2), so `other_file` on either basis
    (_CLAIMED, "lib/helper.ts", "other_file", "other_file"),
], ids=["claimed", "current", "elsewhere", "missing", "other_file"])
def test_reanchored_row_records_both_bases(evidence, evidence_file, current, claimed):
    """AC29 / T5.5: the same citation is classified on the current line AND on
    claimed_line, so 0072's series stays comparable across the O6 flip."""
    extras = _extras(_check(evidence, _finding(), evidence_file))

    assert extras["citation_class"] == current, (
        "citation_class keeps its 0072 meaning: the CURRENT line_start"
    )
    assert _claimed_class(extras) == claimed


@pytest.mark.parametrize("evidence", [_CURRENT, _CLAIMED, None])
def test_unmoved_row_has_one_basis(evidence):
    """AC29: a row never re-anchored has claimed == current, so recording a
    claimed-basis class may not invent a disagreement."""
    extras = _extras(_check(evidence, _finding(reanchored=False)))
    assert extras.get("citation_class_claimed",
                      extras["citation_class"]) == extras["citation_class"]


def test_claimed_basis_is_observation_only():
    """AC29: like 0072's citation_class, the claimed-basis class is read by no
    voter branch — the verdict's result and weight are those of an identical
    row that was never re-anchored."""
    moved = _check(_CLAIMED, _finding())
    still = _check(_CLAIMED, _finding(reanchored=False))
    assert _claimed_class(_extras(moved)) == "self_line"
    assert (moved.result, moved.weight) == (still.result, still.weight)


# --------------------------------------------------------------------------- #
# Review item 24 — the claimed basis goes through the ONE classification rule
# --------------------------------------------------------------------------- #


def test_claimed_basis_uses_the_one_rule(monkeypatch) -> None:
    """``citation_class_claimed`` is ``_classify_citation`` against the claimed
    line — no second encoding of the class rule that a new class could miss."""
    from shared.validate import llm_judge

    bases: list[int] = []
    real = llm_judge._classify_citation

    def spy(evidence_line, own, evidence_file, finding):
        bases.append(own)
        return real(evidence_line, own, evidence_file, finding)

    monkeypatch.setattr(llm_judge, "_classify_citation", spy)
    finding = {"line_start": 40, "file_path": "a.py",
               "validation": {"checks": [{"id": "anchor", "extras": {"claimed_line": 12}}]}}
    out = llm_judge._citation_extras(12, finding, None)
    assert (bases, out) == ([40, 12], {"citation_class": "other_line",
                                      "citation_class_claimed": "self_line"})
    assert not hasattr(llm_judge, "_reclassify_line")
