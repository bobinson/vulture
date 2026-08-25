"""AC3.5 — a category rewrite must be COUNTED and reported, never silent.

The plan gates the whole normalisation on a measurement: "report, per agent,
the finding count before and after normalisation, and the list of rows that
collided. A collapse is acceptable only when the collided rows are the same
defect."

Nothing implemented that. `_conform_category` rewrote the field and returned,
leaving no counter, no log line and no record — so the one number the plan says
must gate the feature could not be produced from a run at all. Worse, the
rewrite is what CREATES dedup collisions: `crossAgentKey` in the Go merge makes
category the primary discriminant, so collapsing two labels onto one can delete
a row, and that deletion was unobservable.

This does not re-derive the counts inside the agent (the collision happens in
the backend, after egress). It records what the agent DID: how many rows it
rewrote, from which label to which, so the before/after is reconstructible from
one run's logs instead of being unmeasurable.
"""

import logging

import pytest

from shared import audit_runner as ar


@pytest.fixture(autouse=True)
def _reset():
    tok = ar._CATEGORY_ENUM.set(frozenset({"CC6", "CC7", "CC8"}))
    ar.reset_conform_stats()
    yield
    ar._CATEGORY_ENUM.reset(tok)


class TestRewritesAreCounted:
    def test_a_rewrite_is_counted(self):
        ar._conform_category({"category": "CC6-encryption"})
        assert ar.conform_stats()["rewritten"] == 1

    def test_a_conforming_value_is_not_counted(self):
        ar._conform_category({"category": "CC6"})
        assert ar.conform_stats()["rewritten"] == 0

    def test_an_unreducible_value_is_counted_separately(self):
        # Prose the normaliser deliberately refuses to guess at. This is the
        # number that says "the prompt fix is not working".
        ar._conform_category({"category": "Access Logging"})
        s = ar.conform_stats()
        assert s["rewritten"] == 0 and s["unreducible"] == 1

    def test_the_mapping_is_recorded_not_just_the_count(self):
        ar._conform_category({"category": "CC6-encryption"})
        ar._conform_category({"category": "CC6-access-logging"})
        ar._conform_category({"category": "CC8-change-management"})
        pairs = ar.conform_stats()["pairs"]
        assert pairs[("CC6-encryption", "CC6")] == 1
        assert pairs[("CC8-change-management", "CC8")] == 1

    def test_collapse_is_visible_as_many_to_one(self):
        for raw in ("CC6-encryption", "CC6-access-logging", "CC6-data-retention"):
            ar._conform_category({"category": raw})
        pairs = ar.conform_stats()["pairs"]
        collapsed = [src for (src, dst) in pairs if dst == "CC6"]
        assert len(collapsed) == 3, "a 3->1 collapse must be reconstructible"


class TestReportIsEmitted:
    def test_summary_logged_when_anything_was_rewritten(self, caplog):
        ar._conform_category({"category": "CC6-encryption"})
        with caplog.at_level(logging.INFO):
            ar.log_conform_stats("run-1", "soc2")
        assert "category_conform" in caplog.text
        assert "soc2" in caplog.text

    def test_nothing_logged_when_nothing_was_rewritten(self, caplog):
        with caplog.at_level(logging.INFO):
            ar.log_conform_stats("run-1", "soc2")
        assert "category_conform" not in caplog.text


class TestNoOpWhenNoVocabulary:
    def test_agent_without_a_declared_enum_records_nothing(self):
        tok = ar._CATEGORY_ENUM.set(None)
        try:
            ar._conform_category({"category": "whatever"})
            assert ar.conform_stats()["rewritten"] == 0
        finally:
            ar._CATEGORY_ENUM.reset(tok)
