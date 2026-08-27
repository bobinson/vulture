"""The reduction must reach vocabularies containing digits and separators.

Plan §11.2: `_LEAD` matched LETTERS ONLY, so a declared value containing a
digit was UNREACHABLE and a separator variant could not be folded:

    soc2  declares CC6/CC7/CC8      -> "CC6-encryption" reduced to "CC" (not declared) -> no-op
    chaos declares blast_radius     -> "blast-radius" differs only by separator -> no-op

So the mechanism was a total no-op for soc2 and a half no-op for chaos -- the
two agents the plan's own motivating table cites. The reduction is now
"longest declared prefix, after folding -/_/. to a single separator".
"""

from shared.tools.category_enum import normalize_to_enum

SSDF = frozenset({"PO", "PS", "PW", "RV"})
SOC2 = frozenset({"CC6", "CC7", "CC8"})
CHAOS = frozenset({"retry", "circuit_breaker", "timeout", "fallback", "blast_radius"})


class TestDigitBearingVocabulary:
    def test_soc2_suffixed(self):
        assert normalize_to_enum("CC6-encryption", SOC2) == "CC6"

    def test_soc2_prose_form(self):
        assert normalize_to_enum("Change Management (CC8)", SOC2) == "CC8"

    def test_soc2_exact(self):
        assert normalize_to_enum("CC7", SOC2) == "CC7"

    def test_soc2_unrelated_left_alone(self):
        assert normalize_to_enum("CWE-79", SOC2) == "CWE-79"


class TestSeparatorFolding:
    def test_hyphen_folds_to_declared_underscore(self):
        assert normalize_to_enum("blast-radius", CHAOS) == "blast_radius"

    def test_suffixed_pattern_name(self):
        assert normalize_to_enum("retry-pattern", CHAOS) == "retry"

    def test_timeout_handling(self):
        assert normalize_to_enum("timeout-handling", CHAOS) == "timeout"

    def test_fallback_pattern(self):
        assert normalize_to_enum("fallback-pattern", CHAOS) == "fallback"

    def test_exact_underscore_form(self):
        assert normalize_to_enum("circuit_breaker", CHAOS) == "circuit_breaker"

    def test_longest_prefix_wins(self):
        # `blast_radius` must win over a hypothetical shorter `blast`.
        assert normalize_to_enum("blast-radius-check", CHAOS | {"blast"}) == "blast_radius"


class TestSsdfStillWorks:
    def test_dotted_task_id(self):
        assert normalize_to_enum("PW-3.3", SSDF) == "PW"

    def test_group_name(self):
        assert normalize_to_enum("PW-produce-well-secured-software", SSDF) == "PW"

    def test_missing_hyphen(self):
        assert normalize_to_enum("PW2", SSDF) == "PW"

    def test_doubled_id(self):
        assert normalize_to_enum("PW-1/PW-3", SSDF) == "PW"


class TestNeverInvents:
    def test_unknown_prefix_unchanged(self):
        assert normalize_to_enum("ZZ-9", SSDF) == "ZZ-9"

    def test_empty_safe(self):
        assert normalize_to_enum("", SSDF) == ""
