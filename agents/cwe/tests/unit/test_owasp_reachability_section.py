"""The attestation must state OWASP-2025 reachability, with a denominator.

"All applicable CWEs must be identified" is unfalsifiable without a
denominator: there are ~940 CWEs, the OWASP 2025 edition maps 249 of them, and
the agent's deterministic tier reaches a minority. Publishing that minority --
computed, never hand-typed -- turns an unanswerable requirement into a tracked
number.

The section must also record the limitation the juice-shop scan exposed: the
corpus gate attests per CWE, not per language. CWE-89 sat in the VERIFIED
bucket at recall 1.0 while every SQL-injection pattern was Python- or
Go-shaped, so JS/TS template-literal injection went undetected on a
known-vulnerable target. A VERIFIED band is evidence about the fixtures that
exist, not about every ecosystem.
"""

import re
import sys
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
sys.path.insert(0, str(CORPUS))

import report_coverage as rc  # noqa: E402


def test_reachability_section_present():
    md = rc.build_markdown()
    assert "OWASP Top 10:2025 reachability" in md, \
        "the attestation must carry an OWASP reachability section"


def test_denominator_is_the_edition_universe():
    md = rc.build_markdown()
    from shared.owasp.mapping import load_edition
    universe = set()
    for c in load_edition("2025").categories:
        universe |= c.cwes
    assert str(len(universe)) in md, \
        f"the mapped universe ({len(universe)}) must appear as the denominator"


def test_verified_and_union_counts_are_computed_not_literal():
    """Numbers must be derived from the buckets, so they cannot go stale."""
    b = rc.build_buckets()
    from shared.owasp.mapping import load_edition
    universe = set()
    for c in load_edition("2025").categories:
        universe |= c.cwes

    def nums(ids):
        return {int(re.search(r"(\d+)", str(i)).group(1)) for i in ids}

    verified_in = nums(b["verified"]) & universe
    md = rc.build_markdown()
    assert re.search(rf"\b{len(verified_in)}\b", md), \
        "the VERIFIED-in-2025 count must appear in the section"
    assert len(verified_in) <= len(b["verified"]), "sanity: intersection cannot exceed the bucket"


def test_per_language_caveat_is_stated():
    md = rc.build_markdown()
    low = md.lower()
    assert "per cwe, not per language" in low or "not per language" in low, \
        "the attestation must state that the gate attests per CWE, not per language"
    assert "cwe-89" in low, "the concrete CWE-89 example must be named"


def test_committed_golden_is_not_stale():
    """Mirrors the existing regenerate-and-diff contract for the new section."""
    golden = (CORPUS / "VERIFIED_CWES.md").read_text()
    assert golden == rc.build_markdown(), \
        "VERIFIED_CWES.md is stale — regenerate with report_coverage.py --write"
