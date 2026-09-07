"""Feature 0079 C2: compound categories must reduce to their LEADING member.

`_fold` collapses [-_.\\s]+ but not the compound joiners "," and "/", so a
compound value does not match its leading declared token on a token boundary.
`_fallback_token` then scans with re.findall and can match a LATER member.

Measured, and this is the whole defect — a SILENT MISCLASSIFICATION, not a
survival:

    normalize_to_enum("circuit_breaker, retry", chaos_enum) -> "retry"

A circuit-breaker finding filed under retry. The value is inside the declared
vocabulary, so nothing downstream can notice.

Scope note, kept because my first write-up got it wrong: the ASVS example I
originally cited was fabricated. asvs passes no category_enum, its declared
vocabulary is ["asvs_requirements"], and no such compound occurs in the tree.
For ssdf and soc2 the joiner is already harmless because their declared tokens
are short prefixes. chaos is the real case.
"""

from __future__ import annotations

import pytest

from shared.tools.category_enum import normalize_to_enum

CHAOS = frozenset({"blast_radius", "circuit_breaker", "fallback", "retry", "timeout"})
SSDF = frozenset({"PO", "PS", "PW", "RV"})
SOC2 = frozenset({"CC6", "CC7", "CC8"})


@pytest.mark.parametrize(
    "raw,want",
    [
        # THE defect: the leading member must win, not a later one.
        ("circuit_breaker, retry", "circuit_breaker"),
        ("circuit_breaker,retry", "circuit_breaker"),
        ("retry/timeout", "retry"),
        ("timeout, retry", "timeout"),
        ("fallback / circuit_breaker", "fallback"),
    ],
)
def test_compound_reduces_to_the_leading_member(raw, want):
    assert normalize_to_enum(raw, CHAOS) == want


@pytest.mark.parametrize(
    "raw,want",
    [
        ("blast_radius", "blast_radius"),
        ("blast-radius", "blast_radius"),
        ("Circuit_Breaker", "circuit_breaker"),
        ("retry", "retry"),
    ],
)
def test_non_compound_values_are_unchanged(raw, want):
    """Separator and case folding must behave exactly as before."""
    assert normalize_to_enum(raw, CHAOS) == want


def test_ssdf_and_soc2_are_unaffected():
    """Both already reduced correctly; the fix must not move them."""
    assert normalize_to_enum("PW-1/PW-3", SSDF) == "PW"
    assert normalize_to_enum("PW-102", SSDF) == "PW"
    assert normalize_to_enum("CC6-access-logging", SOC2) == "CC6"


def test_an_unrecognised_value_is_still_left_alone():
    """The documented rule: reduce to a declared leading token, otherwise leave
    it ALONE. Guessing would trade a visible contract break for an invisible
    mis-classification — which is exactly the bug being fixed."""
    assert normalize_to_enum("CWE-79", CHAOS) == "CWE-79"
    assert normalize_to_enum("something, else", CHAOS) == "something, else"


def test_the_joiner_fix_is_not_vacuous():
    """Prove the compound form actually occurs in a shape the fix changes: the
    pre-fix result and the post-fix result must differ for at least one input."""
    assert normalize_to_enum("circuit_breaker, retry", CHAOS) != "retry", (
        "the fix is not applied: the compound still reduces to a later member"
    )
