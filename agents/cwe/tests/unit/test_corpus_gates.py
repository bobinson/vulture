"""Feature 0057 Phase 5 — T17/T18: the per-CWE recall + precision GATES (R15).

These pin the gate-decision contract of ``corpus_runner`` independent of the
detectors: they build ``CweScore`` objects by hand (the scorer's output type)
and assert how ``apply_gates`` / ``verified_cwes`` classify them. This isolates
the gate arithmetic so a regression in EITHER the recall axis (T17) or the
clean-code precision/FP axis (T18) is caught deterministically.

RED until ``corpus_runner`` exists with:
    corpus_runner.CweScore(cwe, n_positive, n_clean, recall, fp_rate)
        (a constructible record; field names per the scorer contract)
    corpus_runner.apply_gates(scores: dict[str, CweScore], gates) -> dict[str,band]
    corpus_runner.verified_cwes(scores, gates) -> set[str]
    Gates with the strict defaults min_recall=1.0, max_fp_rate=0.0,
    min_fixtures=3.

The gate (R15): VERIFIED iff
    n_positive >= min_fixtures AND n_clean >= min_fixtures
    AND recall >= min_recall AND fp_rate <= max_fp_rate.
"""

from __future__ import annotations

import importlib

import pytest

corpus_runner = importlib.import_module("corpus_runner")


def _score(cwe, n_pos, n_clean, recall, fp_rate):
    """Build a CweScore via the runner's record type (contract under test)."""
    return corpus_runner.CweScore(
        cwe=cwe,
        n_positive=n_pos,
        n_clean=n_clean,
        recall=recall,
        fp_rate=fp_rate,
    )


# --------------------------------------------------------------------------
# T17 — the RECALL gate fails on a regressed (undetected) positive.
# --------------------------------------------------------------------------
def test_T17_missed_positive_drops_below_recall_gate():
    """A CWE with enough fixtures and a clean FP record but a single MISSED
    positive (recall 2/3 < min_recall=1.0) must NOT be VERIFIED. This is the
    auto-demotion guard: a signature whose CWE regresses falls out of N."""
    gates = corpus_runner.load_gates()
    scores = {
        # 3 positives but one undetected → recall 0.667 < 1.0
        "regressed": _score("regressed", 3, 3, recall=2 / 3, fp_rate=0.0),
    }
    bands = corpus_runner.apply_gates(scores, gates)

    assert bands["regressed"] != "VERIFIED"
    assert "regressed" not in corpus_runner.verified_cwes(scores, gates)


def test_T17_perfect_recall_with_enough_fixtures_is_verified():
    """Control: the SAME shape with full recall + zero FP + >=3/3 fixtures
    DOES verify — proving the recall axis is what flipped T17, not the counts."""
    gates = corpus_runner.load_gates()
    scores = {"good": _score("good", 3, 3, recall=1.0, fp_rate=0.0)}
    assert corpus_runner.apply_gates(scores, gates)["good"] == "VERIFIED"
    assert "good" in corpus_runner.verified_cwes(scores, gates)


# --------------------------------------------------------------------------
# T18 — the per-CWE PRECISION gate fails on a flagged clean fixture.
# --------------------------------------------------------------------------
def test_T18_flagged_clean_twin_trips_precision_gate():
    """A CWE with perfect recall and enough fixtures but ONE flagged clean twin
    (fp_rate 1/3 > max_fp_rate=0.0) must NOT be VERIFIED. Clean-code precision
    is a hard gate: any false positive on a clean twin of that CWE disqualifies
    it."""
    gates = corpus_runner.load_gates()
    scores = {
        "fp": _score("fp", 3, 3, recall=1.0, fp_rate=1 / 3),
    }
    bands = corpus_runner.apply_gates(scores, gates)

    assert bands["fp"] != "VERIFIED"
    assert "fp" not in corpus_runner.verified_cwes(scores, gates)


def test_T18_zero_fp_with_enough_fixtures_is_verified():
    """Control: identical shape with fp_rate 0.0 verifies — isolates the FP
    axis as the sole cause of the T18 failure."""
    gates = corpus_runner.load_gates()
    scores = {"clean": _score("clean", 3, 3, recall=1.0, fp_rate=0.0)}
    assert corpus_runner.apply_gates(scores, gates)["clean"] == "VERIFIED"


def test_T18_strict_defaults_are_recall_1_fp_0():
    """Pin the strict + uniform 0057 defaults the gates depend on."""
    gates = corpus_runner.load_gates()
    g = gates.for_cwe("anything")
    assert g["min_recall"] == pytest.approx(1.0)
    assert g["max_fp_rate"] == pytest.approx(0.0)
    assert g["min_fixtures"] == 3
