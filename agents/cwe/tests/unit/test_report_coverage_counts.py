"""T24 — Feature 0057 Phase 6 (P6a / R16): the four-bucket attestation counts
reconcile, with no double-counting.

``report_coverage`` layers the four attestation buckets on top of the corpus
engine's ``build_report()``:

    VERIFIED            — the gate-passing CWEs; N == len(VERIFIED).
    DETECTED-below-gate — fires but misses the bar (currently empty).
    DECLARED-ONLY       — declared/detectable skill + trusted-signature CWE-ids
                          that are NOT corpus-gated (minus VERIFIED, minus
                          DETECTED-below-gate). The 846-catalog is metadata.
    LLM-ASSISTED        — non-deterministic; NEVER counted in N.

The invariants pinned here (honest in BOTH directions):
  * N in VERIFIED_CWES.md == count of VERIFIED rows == len(build_report["verified"])
    == number of DISTINCT gate-verified CWE ids.
  * The four buckets are pairwise DISJOINT on CWE-id (no double-count): a CWE
    that is VERIFIED must NOT also appear in DECLARED-ONLY or below-gate.
  * A trusted-signature CWE that passed the gate lands in VERIFIED, not
    DECLARED-ONLY (no underclaim).
  * LLM-ASSISTED contributes ZERO to N.

RED until ``tests/corpus/report_coverage.py`` provides ``build_buckets()``
(structured) + ``build_markdown()`` (rendered) + the committed golden.

``report_coverage`` / ``corpus_runner`` are importable by bare module name via
``tests/unit/conftest.py`` (it adds ``tests/corpus`` to ``sys.path``).
"""

from __future__ import annotations

import re
from pathlib import Path

import report_coverage  # noqa: E402 — sys.path injected by conftest
from corpus_runner import build_report  # noqa: E402

_CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"
_GOLDEN = _CORPUS_DIR / "VERIFIED_CWES.md"

# the four attestation bucket keys report_coverage.build_buckets() must expose
_BUCKET_KEYS = {
    "verified",
    "detected_below_gate",
    "declared_only",
    "llm_assisted",
}


def _ids(bucket_value) -> set[str]:
    """Coerce a bucket payload to a set of CWE-id strings (digits only).

    A bucket may be a list of ids, a list of row dicts (each with a ``cwe``
    key), or — for LLM-ASSISTED — a non-enumerable static label. Non-id
    payloads coerce to the empty set so LLM-ASSISTED contributes 0 to N.
    """
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


class TestAttestationCountsReconcile:
    def test_build_buckets_exposes_four_buckets(self):
        buckets = report_coverage.build_buckets()
        assert _BUCKET_KEYS.issubset(set(buckets)), (
            f"build_buckets() must expose {_BUCKET_KEYS}, got {set(buckets)}"
        )

    def test_verified_bucket_equals_gate_verified_set(self):
        buckets = report_coverage.build_buckets()
        gate_verified = set(build_report()["verified"])
        assert _ids(buckets["verified"]) == gate_verified, (
            "VERIFIED bucket must equal the corpus gate's verified CWE set"
        )

    def test_N_reconciles_three_ways(self):
        """N == len(VERIFIED bucket) == len(build_report['verified']) ==
        distinct gate-verified ids (no double-count)."""
        buckets = report_coverage.build_buckets()
        report = build_report()
        verified_ids = _ids(buckets["verified"])
        assert len(verified_ids) == report["n"]
        assert len(verified_ids) == len(set(report["verified"]))
        # distinct: the bucket carries no duplicate CWE-id
        # (set length already collapses dupes; assert the source list had none)
        assert len(report["verified"]) == len(set(report["verified"]))

    def test_buckets_are_pairwise_disjoint(self):
        """No CWE-id appears in more than one of the deterministic buckets —
        a VERIFIED CWE is NOT also counted as DECLARED-ONLY or below-gate."""
        buckets = report_coverage.build_buckets()
        verified = _ids(buckets["verified"])
        below = _ids(buckets["detected_below_gate"])
        declared = _ids(buckets["declared_only"])
        assert verified.isdisjoint(below), verified & below
        assert verified.isdisjoint(declared), verified & declared
        assert below.isdisjoint(declared), below & declared

    def test_trusted_signature_verified_cwes_are_in_verified_not_declared(self):
        """Trusted-signature CWEs that passed the gate (e.g. 90, 91, 117, 548,
        917, 943, 1333) belong in VERIFIED, never DECLARED-ONLY (no underclaim).
        """
        from cwe_agent.skills.signatures.detector import SIGNATURES

        trusted = {s.cwe_id for s in SIGNATURES if s.status == "trusted"}
        buckets = report_coverage.build_buckets()
        verified = _ids(buckets["verified"])
        declared = _ids(buckets["declared_only"])
        gate_verified_trusted = trusted & set(build_report()["verified"])
        assert gate_verified_trusted, "expected >=1 trusted signature in N"
        assert gate_verified_trusted <= verified
        assert gate_verified_trusted.isdisjoint(declared)

    def test_llm_assisted_contributes_zero_to_N(self):
        """LLM-ASSISTED is non-deterministic and must add 0 to N — its ids do
        not overlap the VERIFIED set."""
        buckets = report_coverage.build_buckets()
        llm = _ids(buckets["llm_assisted"])
        verified = _ids(buckets["verified"])
        assert llm.isdisjoint(verified)

    def test_golden_N_matches_verified_bucket(self):
        """The committed golden's header N equals len(VERIFIED bucket)."""
        committed = _GOLDEN.read_text(encoding="utf-8")
        m = re.search(r"N\s*=\s*(\d+)", committed)
        assert m, "golden must carry an 'N = <count>' header"
        golden_n = int(m.group(1))
        buckets = report_coverage.build_buckets()
        assert golden_n == len(_ids(buckets["verified"]))
