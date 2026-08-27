"""The category normaliser must conform without inventing."""

from shared.tools.category_enum import normalize_to_enum, split_practice_detail

SSDF = frozenset({"PO", "PS", "PW", "RV"})


class TestNormalize:
    def test_declared_value_passes_through(self):
        assert normalize_to_enum("PW", SSDF) == "PW"

    def test_dotted_task_id_reduces_to_group(self):
        assert normalize_to_enum("PW-3.3", SSDF) == "PW"

    def test_missing_hyphen_reduces(self):
        assert normalize_to_enum("PW2", SSDF) == "PW"

    def test_practice_group_name_reduces(self):
        assert normalize_to_enum("PW-produce-well-secured-software", SSDF) == "PW"

    def test_doubled_id_reduces_to_the_first(self):
        assert normalize_to_enum("PW-1/PW-3", SSDF) == "PW"

    def test_invented_task_number_still_reduces_to_its_group(self):
        assert normalize_to_enum("PW-102", SSDF) == "PW"

    def test_lowercase_group_is_upcased(self):
        assert normalize_to_enum("pw-3.3", SSDF) == "PW"

    def test_unrelated_value_is_left_alone_not_guessed(self):
        assert normalize_to_enum("CWE-79", SSDF) == "CWE-79"

    def test_empty_is_safe(self):
        assert normalize_to_enum("", SSDF) == ""


class TestDetailPreserved:
    def test_dropped_detail_is_returned(self):
        assert split_practice_detail("PW-3.3", "PW") == "PW-3.3"

    def test_no_detail_when_unchanged(self):
        assert split_practice_detail("PW", "PW") is None
