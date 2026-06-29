"""Feature 0057 Phase 5 — T16/T19/T20: the deterministic corpus runner + scorer.

These tests pin the CONTRACT of ``tests/corpus/corpus_runner.py`` (P5b), the
module that scores per-CWE recall + false-positive rate over the labeled corpus
using the DETERMINISTIC tiers only (regex skills + signatures, NO live LLM) and
applies the per-CWE promotion gate (R15).

They are RED until ``corpus_runner`` exists. They are self-contained: they drive
the runner over the tiny ``manifest.d/_golden.yaml`` fragment (CWE-78 with 1+1
fixtures = under-min; CWE-1333 with 3+3 = meets-min), so they do not depend on
the full seed corpus and stay deterministic.

CONTRACT pinned here (the implementer MUST satisfy this surface):

    corpus_runner.CORPUS_DIR -> Path to agents/cwe/tests/corpus/
    corpus_runner.load_manifest(fragments=["_golden"]) -> list[dict]
        each entry: {file, language, cwe, expectation, line?} ; `file` relative
        to corpus/fixtures/. With no `fragments`, globs manifest.d/*.yaml but
        EXCLUDES the golden slice (basename starting "_") so the golden fixtures
        never pollute the production N.
    corpus_runner.load_gates() -> Gates ; Gates.for_cwe(cwe) -> dict with keys
        min_recall, max_fp_rate, min_fixtures.
    corpus_runner.run_deterministic(abs_fixture_path) -> set[str] of "CWE-N"
        categories. Copies the fixture to a NEUTRAL temp dir first (so the
        scanner's test/skills/fixtures filters do not exclude it), unions the
        category of every SKILL_MAP function, calls NO live LLM.
    corpus_runner.score_corpus(entries) -> dict[cwe -> CweScore] with fields
        n_positive, n_clean, recall, fp_rate (floats; recall/fp_rate == 0.0
        when the denominator is 0).
"""

from __future__ import annotations

import importlib

import pytest

corpus_runner = importlib.import_module("corpus_runner")


# --------------------------------------------------------------------------
# T16 — runner scores per-CWE recall + FP on the deterministic tiers.
# --------------------------------------------------------------------------
def test_T16_run_deterministic_no_llm_and_neutral_copy():
    """run_deterministic detects the target CWE of a genuine positive even
    though the fixture lives under a `tests/`/`fixtures/` path (proves the
    neutral-copy step) and emits a `category` set — with NO live LLM call."""
    entries = corpus_runner.load_manifest(fragments=["_golden"])
    by_file = {e["file"]: e for e in entries}

    pos = by_file["_golden/g_1333_1.js"]
    clean = by_file["_golden/g_1333_1_clean.js"]
    assert pos["expectation"] == "positive"
    assert clean["expectation"] == "negative"

    pos_path = corpus_runner.CORPUS_DIR / "fixtures" / pos["file"]
    clean_path = corpus_runner.CORPUS_DIR / "fixtures" / clean["file"]

    pos_cats = corpus_runner.run_deterministic(str(pos_path))
    clean_cats = corpus_runner.run_deterministic(str(clean_path))

    assert isinstance(pos_cats, set)
    # genuine positive fires; clean twin of the SAME cwe does not.
    assert "CWE-1333" in pos_cats
    assert "CWE-1333" not in clean_cats


def test_T16_score_corpus_computes_recall_and_fp():
    """score_corpus returns per-CWE recall + fp_rate. On the golden slice,
    CWE-1333 has 3 genuine positives (all detected → recall 1.0) and 3 clean
    twins (none flagged → fp_rate 0.0)."""
    entries = corpus_runner.load_manifest(fragments=["_golden"])
    scores = corpus_runner.score_corpus(entries)

    assert "1333" in scores
    s = scores["1333"]
    assert s.n_positive == 3
    assert s.n_clean == 3
    assert s.recall == pytest.approx(1.0)
    assert s.fp_rate == pytest.approx(0.0)


def test_T16_run_deterministic_does_not_invoke_llm(monkeypatch):
    """Hard guarantee: the deterministic runner never reaches the LLM phase.
    We poison run_combined_audit so any call raises; run_deterministic must
    still succeed by going only through the skill functions."""
    import shared.audit_runner as audit_runner

    def _boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("run_deterministic must not invoke the LLM phase")

    monkeypatch.setattr(audit_runner, "run_combined_audit", _boom, raising=False)

    corpus_runner.load_manifest(fragments=["_golden"])
    path = corpus_runner.CORPUS_DIR / "fixtures" / "_golden" / "g_1333_2.py"
    cats = corpus_runner.run_deterministic(str(path))
    assert "CWE-1333" in cats


# --------------------------------------------------------------------------
# T19 — a CWE with < min_fixtures is NOT counted (anti-vacuity guard).
# --------------------------------------------------------------------------
def test_T19_under_min_fixtures_not_verified():
    """CWE-78 in the golden slice has only 1 positive + 1 clean (< the
    min_fixtures=3 bar). Even though its single positive is detected with
    perfect recall and zero FP, it MUST land in a non-VERIFIED band and MUST
    NOT be counted in N."""
    entries = corpus_runner.load_manifest(fragments=["_golden"])
    scores = corpus_runner.score_corpus(entries)
    gates = corpus_runner.load_gates()

    s78 = scores["78"]
    assert s78.n_positive == 1
    assert s78.n_clean == 1
    # the single positive really is detected (recall is good) ...
    assert s78.recall == pytest.approx(1.0)
    assert s78.fp_rate == pytest.approx(0.0)

    bands = corpus_runner.apply_gates(scores, gates)
    # ... yet the anti-vacuity guard keeps it OUT of VERIFIED.
    assert bands["78"] != "VERIFIED"
    assert "78" not in corpus_runner.verified_cwes(scores, gates)


def test_T19_min_fixtures_default_is_three():
    """The strict + uniform 0057 bar: min_fixtures defaults to 3."""
    gates = corpus_runner.load_gates()
    assert gates.for_cwe("1333")["min_fixtures"] == 3
    assert gates.for_cwe("78")["min_fixtures"] == 3


# --------------------------------------------------------------------------
# T20 — a weak candidate is MEASURED but does not fail CI.
# --------------------------------------------------------------------------
def test_T20_below_gate_candidate_is_measured_not_errored():
    """A CWE that fires but misses the bar (here CWE-78, under-min) is recorded
    in a DETECTED-below-gate band — scoring/banding return a result, they do NOT
    raise. Honest N excludes it; CI (the gate computation) stays green."""
    entries = corpus_runner.load_manifest(fragments=["_golden"])
    scores = corpus_runner.score_corpus(entries)
    gates = corpus_runner.load_gates()

    bands = corpus_runner.apply_gates(scores, gates)
    # It is present and measured (not dropped, not an exception) ...
    assert "78" in bands
    # ... in a recognised below-gate band, distinct from VERIFIED.
    assert bands["78"] in {"DETECTED", "NOT_DETECTED"}
    assert bands["78"] != "VERIFIED"

    # N is the count of VERIFIED CWEs — computed, never asserted to a constant.
    n = len(corpus_runner.verified_cwes(scores, gates))
    assert isinstance(n, int)
    # the golden slice verifies exactly CWE-1333 (78 is under-min).
    assert n == 1
    assert corpus_runner.verified_cwes(scores, gates) == {"1333"}
