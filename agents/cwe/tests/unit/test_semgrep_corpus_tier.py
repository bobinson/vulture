"""Feature 0058 Phase 4 (P4a/P4b, R7) — T6/T9/T10: the Semgrep corpus tier.

These tests pin the CONTRACT for extending the 0057 corpus gate + attestation
to a Semgrep-derived detection tier. They are RED until ``corpus_runner`` and
``report_coverage`` grow the surface below. The GREEN team may NOT modify these
tests.

CONTRACT pinned here (the implementer MUST satisfy this surface exactly):

corpus_runner (agents/cwe/tests/corpus/corpus_runner.py):

    score_semgrep_corpus(entries: list[dict], runner) -> dict[str, CweScore]
        Same scoring semantics as ``score_corpus`` (per-CWE recall + fp_rate,
        file-level, denominators-0 -> 0.0, keys are bare-digit CWE-id strings,
        values are ``CweScore``), EXCEPT the detector is the INJECTED callable
        ``runner(fixture_path) -> set[str]`` of "CWE-N" category strings.
        * ``entries`` are manifest-shaped dicts (keys ``file`` relative to
          fixtures/, ``language``, ``cwe``, ``expectation``, optional ``line``)
          exactly as ``load_manifest`` returns.
        * ``runner`` is called EXACTLY ONCE per fixture entry with the string
          absolute path ``str(CORPUS_DIR / "fixtures" / entry["file"])``.
        * NO semgrep binary, NO filesystem access by the scorer itself: the
          fixture files need not exist (unit tests inject a fake runner).

    write_semgrep_trusted(bands: dict[str, str], path) -> None
        Serialize an ``apply_gates``-style band mapping to JSON at ``path``:
            {"trusted": ["CWE-N", ...], "detected_below_gate": ["CWE-N", ...]}
        * "trusted"             <- CWEs whose band == "VERIFIED"
        * "detected_below_gate" <- CWEs whose band == "DETECTED"
        * NOT_DETECTED CWEs appear in NEITHER list.
        * Each list is "CWE-"-prefixed and sorted numerically (reproducible,
          R8).

    The existing ``apply_gates`` / ``verified_cwes`` / ``Gates`` machinery is
    reused UNCHANGED on the semgrep scores (strict + uniform bar, decision 3).

report_coverage (agents/cwe/tests/corpus/report_coverage.py):

    SEMGREP_TRUSTED_PATH: Path
        Module-level constant, default ``CORPUS_DIR / "semgrep_trusted.json"``.
        MUST be read at call time (so tests can monkeypatch it), not captured.

    trusted_semgrep_cwe_ids() -> set[str]
        Reads the JSON at ``SEMGREP_TRUSTED_PATH`` and returns the "trusted"
        ids NORMALIZED to bare digit strings (e.g. {"917"}), matching
        ``skill_category_cwe_ids()`` / ``trusted_signature_cwe_ids()``.
        A MISSING file returns the empty set (graceful — no raise).

    build_buckets() gains the "semgrep" tier:
        * buckets["verified"] == gate-verified UNION semgrep-trusted ids
          (bare digits; a set-union so an id in both is counted ONCE) and
          buckets["n"] == len(that union).
        * semgrep below-gate ids land in buckets["detected_below_gate"] and
          are NEVER in buckets["verified"] / never counted in n.
        * a semgrep-trusted id previously in DECLARED-ONLY moves to VERIFIED
          (buckets stay pairwise disjoint; no double-count).
        * buckets["semgrep"] is a dict exposing the tier breakdown with keys
          "trusted" and "detected_below_gate" (id lists, "CWE-" prefix
          tolerated by the coercion below).

``corpus_runner`` / ``report_coverage`` are importable by bare module name via
``tests/unit/conftest.py`` (it adds ``tests/corpus`` to ``sys.path``).
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

corpus_runner = importlib.import_module("corpus_runner")
report_coverage = importlib.import_module("report_coverage")


# --------------------------------------------------------------------------
# synthetic manifest entries + fake runners (NO semgrep binary, NO real files)
# --------------------------------------------------------------------------
def _entries_917() -> list[dict]:
    """3 positives + 3 clean twins for CWE-917 in the manifest shape
    ``load_manifest`` returns. The fixture files deliberately do NOT exist:
    the scorer must rely solely on the injected runner."""
    entries = []
    for i in (1, 2, 3):
        entries.append(
            {
                "file": f"_semgrep_synth/s917_pos_{i}.py",
                "language": "Python",
                "cwe": "917",
                "expectation": "positive",
                "line": 3,
            }
        )
        entries.append(
            {
                "file": f"_semgrep_synth/s917_clean_{i}.py",
                "language": "Python",
                "cwe": "917",
                "expectation": "negative",
            }
        )
    return entries


def _perfect_runner(fixture_path) -> set[str]:
    """Fake semgrep tier: fires CWE-917 on every positive, never on a clean."""
    name = Path(str(fixture_path)).name
    return set() if "clean" in name else {"CWE-917"}


def _miss_one_runner(fixture_path) -> set[str]:
    """Fake semgrep tier that MISSES one positive (s917_pos_3)."""
    name = Path(str(fixture_path)).name
    if "clean" in name or name == "s917_pos_3.py":
        return set()
    return {"CWE-917"}


def _ids(bucket_value) -> set[str]:
    """Coerce a bucket payload to a set of bare CWE-id strings (digits only).
    Mirrors the tolerant coercion in test_report_coverage_counts."""
    out: set[str] = set()
    if isinstance(bucket_value, dict):
        bucket_value = bucket_value.get("cwes", bucket_value.get("rows", []))
    if isinstance(bucket_value, (list, tuple, set)):
        for item in bucket_value:
            if isinstance(item, dict):
                cwe = str(item.get("cwe", "")).replace("CWE-", "").strip()
            else:
                cwe = str(item).replace("CWE-", "").strip()
            if cwe.isdigit():
                out.add(cwe)
    return out


# --------------------------------------------------------------------------
# T6 — a semgrep CWE is candidate until its corpus fixtures pass, then trusted.
# --------------------------------------------------------------------------
def test_T6_perfect_semgrep_runner_scores_full_recall_zero_fp():
    """score_semgrep_corpus with a runner that hits ALL positives and NO
    cleans yields a CweScore of recall 1.0 / fp_rate 0.0 over 3+3 fixtures."""
    scores = corpus_runner.score_semgrep_corpus(_entries_917(), _perfect_runner)

    assert "917" in scores
    s = scores["917"]
    assert s.n_positive == 3
    assert s.n_clean == 3
    assert s.recall == pytest.approx(1.0)
    assert s.fp_rate == pytest.approx(0.0)


def test_T6_perfect_semgrep_runner_is_verified_by_existing_gates():
    """The EXISTING apply_gates/verified_cwes machinery — unchanged, strict +
    uniform bar — promotes the perfect semgrep score to VERIFIED (trusted)."""
    scores = corpus_runner.score_semgrep_corpus(_entries_917(), _perfect_runner)
    gates = corpus_runner.load_gates()

    bands = corpus_runner.apply_gates(scores, gates)
    assert bands["917"] == "VERIFIED"
    assert "917" in corpus_runner.verified_cwes(scores, gates)


def test_T6_runner_missing_one_positive_is_not_verified():
    """A runner that misses ONE positive (recall 2/3 < min_recall 1.0) must
    NOT reach VERIFIED — the semgrep tier gets NO softer bar than signatures."""
    scores = corpus_runner.score_semgrep_corpus(_entries_917(), _miss_one_runner)
    gates = corpus_runner.load_gates()

    assert scores["917"].recall == pytest.approx(2 / 3)
    bands = corpus_runner.apply_gates(scores, gates)
    assert bands["917"] != "VERIFIED"
    assert "917" not in corpus_runner.verified_cwes(scores, gates)


def test_T6_score_semgrep_corpus_uses_injected_runner_only():
    """The scorer calls the injected runner EXACTLY ONCE per fixture entry,
    with str(CORPUS_DIR / 'fixtures' / entry['file']) — and needs neither the
    semgrep binary nor the fixture files on disk."""
    entries = _entries_917()
    calls: list[str] = []

    def recording_runner(fixture_path) -> set[str]:
        calls.append(str(fixture_path))
        return _perfect_runner(fixture_path)

    corpus_runner.score_semgrep_corpus(entries, recording_runner)

    expected = sorted(
        str(corpus_runner.CORPUS_DIR / "fixtures" / e["file"]) for e in entries
    )
    assert sorted(calls) == expected


# --------------------------------------------------------------------------
# T10 — fires-but-below-gate lands in the DETECTED band, never in N.
# --------------------------------------------------------------------------
def test_T10_partial_hits_band_is_detected_below_gate():
    """A semgrep CWE that fires on >=1 positive but misses the strict gate is
    banded DETECTED (measured, below-gate) — not VERIFIED, not NOT_DETECTED."""
    scores = corpus_runner.score_semgrep_corpus(_entries_917(), _miss_one_runner)
    gates = corpus_runner.load_gates()

    bands = corpus_runner.apply_gates(scores, gates)
    assert bands["917"] == "DETECTED"


def test_T10_write_semgrep_trusted_json_shape(tmp_path):
    """write_semgrep_trusted serializes bands to the pinned JSON shape:
    VERIFIED -> "trusted", DETECTED -> "detected_below_gate", NOT_DETECTED
    omitted; "CWE-"-prefixed ids sorted numerically."""
    bands = {
        "1333": "VERIFIED",
        "917": "VERIFIED",
        "9999": "DETECTED",
        "611": "NOT_DETECTED",
    }
    out = tmp_path / "semgrep_trusted.json"
    corpus_runner.write_semgrep_trusted(bands, out)

    data = json.loads(out.read_text(encoding="utf-8"))
    assert set(data) == {"trusted", "detected_below_gate"}
    assert data["trusted"] == ["CWE-917", "CWE-1333"]  # numeric sort
    assert data["detected_below_gate"] == ["CWE-9999"]


def test_T10_below_gate_id_excluded_from_N_by_build_buckets(
    tmp_path, monkeypatch
):
    """A below-gate semgrep id lands in the DETECTED band of the attestation
    and is NOT counted in N (buckets['verified'] / buckets['n'] unchanged)."""
    payload = {"trusted": [], "detected_below_gate": ["CWE-9999"]}
    p = tmp_path / "semgrep_trusted.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(report_coverage, "SEMGREP_TRUSTED_PATH", p)

    from corpus_runner import build_report

    gate_verified = set(build_report()["verified"])
    buckets = report_coverage.build_buckets()

    verified_ids = _ids(buckets["verified"])
    assert "9999" not in verified_ids
    assert "9999" in _ids(buckets["detected_below_gate"])
    assert verified_ids == gate_verified
    assert buckets["n"] == len(gate_verified)


# --------------------------------------------------------------------------
# T9 — attestation semgrep tier: readers + count reconciliation.
# --------------------------------------------------------------------------
def test_T9_trusted_semgrep_cwe_ids_normalizes_to_bare_digits(
    tmp_path, monkeypatch
):
    """trusted_semgrep_cwe_ids() reads the generated JSON and normalizes the
    "CWE-N" strings to bare digit ids, matching the other id-set helpers."""
    p = tmp_path / "semgrep_trusted.json"
    p.write_text(
        json.dumps({"trusted": ["CWE-917", "CWE-89"], "detected_below_gate": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_coverage, "SEMGREP_TRUSTED_PATH", p)

    assert report_coverage.trusted_semgrep_cwe_ids() == {"917", "89"}


def test_T9_trusted_semgrep_cwe_ids_missing_file_is_graceful(
    tmp_path, monkeypatch
):
    """No generated semgrep_trusted.json -> empty set, NO exception (semgrep
    is augmentation, never a hard dependency — R9)."""
    monkeypatch.setattr(
        report_coverage,
        "SEMGREP_TRUSTED_PATH",
        tmp_path / "does_not_exist.json",
    )
    assert report_coverage.trusted_semgrep_cwe_ids() == set()


def test_T9_semgrep_trusted_default_path_is_corpus_json():
    """The generated JSON lives at tests/corpus/semgrep_trusted.json."""
    expected = Path(report_coverage.CORPUS_DIR) / "semgrep_trusted.json"
    assert Path(report_coverage.SEMGREP_TRUSTED_PATH) == expected


def test_T9_counts_reconcile_union_without_double_count(tmp_path, monkeypatch):
    """N == |gate-verified UNION semgrep-trusted|: an id in both the
    skills/signatures gate AND semgrep is counted ONCE; a net-new
    semgrep-trusted id grows N by exactly one; the below-gate id never
    enters N."""
    from corpus_runner import build_report

    gate_verified = set(build_report()["verified"])
    assert gate_verified, "expected a non-empty gate-verified baseline"
    overlap_id = sorted(gate_verified, key=int)[0]  # covered by BOTH tiers
    net_new_id = "9998"
    below_id = "9999"
    assert net_new_id not in gate_verified and below_id not in gate_verified

    payload = {
        "trusted": [f"CWE-{overlap_id}", f"CWE-{net_new_id}"],
        "detected_below_gate": [f"CWE-{below_id}"],
    }
    p = tmp_path / "semgrep_trusted.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(report_coverage, "SEMGREP_TRUSTED_PATH", p)

    buckets = report_coverage.build_buckets()
    verified_ids = _ids(buckets["verified"])

    assert verified_ids == gate_verified | {net_new_id}
    assert buckets["n"] == len(gate_verified) + 1  # overlap counted ONCE
    assert below_id not in verified_ids
    assert below_id in _ids(buckets["detected_below_gate"])
    # a net-new semgrep id is VERIFIED, never simultaneously DECLARED-ONLY
    assert net_new_id not in _ids(buckets["declared_only"])


def test_T9_semgrep_trusted_declared_only_id_moves_to_verified(
    tmp_path, monkeypatch
):
    """A skill-declared (but not gate-verified) CWE that semgrep trusts moves
    from DECLARED-ONLY into VERIFIED — buckets stay pairwise disjoint and the
    id is counted exactly once in N."""
    from corpus_runner import build_report

    report = build_report()
    gate_verified = set(report["verified"])
    below = {c for c, b in report["bands"].items() if b == "DETECTED"}
    declared = (
        report_coverage.skill_category_cwe_ids()
        | report_coverage.trusted_signature_cwe_ids()
    )
    declared_only_baseline = declared - gate_verified - below
    assert declared_only_baseline, "expected >=1 declared-only CWE"
    promoted = sorted(declared_only_baseline, key=int)[0]

    p = tmp_path / "semgrep_trusted.json"
    p.write_text(
        json.dumps({"trusted": [f"CWE-{promoted}"], "detected_below_gate": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(report_coverage, "SEMGREP_TRUSTED_PATH", p)

    buckets = report_coverage.build_buckets()
    verified_ids = _ids(buckets["verified"])

    assert promoted in verified_ids
    assert promoted not in _ids(buckets["declared_only"])
    assert buckets["n"] == len(gate_verified) + 1


def test_T9_build_buckets_exposes_semgrep_tier(tmp_path, monkeypatch):
    """build_buckets() output gains a 'semgrep' tier dict with the trusted +
    below-gate breakdown, so VERIFIED_CWES.md can attribute coverage per tier
    (P4b)."""
    payload = {
        "trusted": ["CWE-9998"],
        "detected_below_gate": ["CWE-9999"],
    }
    p = tmp_path / "semgrep_trusted.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(report_coverage, "SEMGREP_TRUSTED_PATH", p)

    buckets = report_coverage.build_buckets()

    assert "semgrep" in buckets
    tier = buckets["semgrep"]
    assert isinstance(tier, dict)
    assert _ids(tier.get("trusted")) == {"9998"}
    assert _ids(tier.get("detected_below_gate")) == {"9999"}
