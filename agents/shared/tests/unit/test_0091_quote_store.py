"""Feature 0091 P1 — the agent-local quote store and its two keys.

The E2E suite (tests/e2e/test_0091_lineage_checks.py) drives the store through
a real audit and pins the OUTCOMES. These pin the store's own contract: what
the hash is over, that both key routes reach the same row, and that the write
happens at the one moment the quote still exists — inside
``_strip_private_fields``, immediately before the strip deletes it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared import quote_store
from shared.audit_runner import _normalize_finding, _strip_private_fields
from shared.lineage_checks import quote_hash

QUOTE = (
    'token = request.headers.get("X-Api-Token")\n'
    'if token == "s3cr3t-static-token-value":'
)


@pytest.fixture(autouse=True)
def _local_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Never touch the developer's ~/.vulture cache."""
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "cache" / "l5_cache.db"))
    quote_store.reset_for_tests()
    yield
    quote_store.reset_for_tests()


class TestHash:
    def test_hash_is_over_the_normalised_quote(self) -> None:
        """Indentation must not change the identity.

        The model copies from a rendered listing whose indentation has already
        shifted; a hash over raw text would make the row's `quote_hash`
        disagree with the same code read back from the file.
        """
        indented = "\n".join("    " + line for line in QUOTE.splitlines())
        assert quote_hash(indented) == quote_hash(QUOTE)

    def test_hash_is_prefixed_and_stable(self) -> None:
        assert quote_hash(QUOTE).startswith("sha256:")
        assert len(quote_hash(QUOTE)) == len("sha256:") + 64
        assert quote_hash(QUOTE) == quote_hash(QUOTE)

    def test_hashing_is_idempotent_over_the_stored_form(self) -> None:
        """The store keeps the NORMALISED quote, and re-hashing it must agree.

        Otherwise every cached row would fail its own hash check on the next
        scan and degrade to `unconfirmable` — S9 firing on a cache that is in
        fact intact.
        """
        assert quote_hash(quote_store.normalise_quote(QUOTE)) == quote_hash(QUOTE)


class TestKeys:
    def test_round_trip_by_fingerprint(self) -> None:
        quote_store.store("fp2-abc", QUOTE)
        assert quote_store.lookup("fp2-abc") == quote_store.normalise_quote(QUOTE)

    def test_a_row_written_by_fingerprint_is_also_findable_by_hash(self) -> None:
        """The verify path falls back to the hash, so the column must be filled."""
        quote_store.store("fp2-abc", QUOTE)
        assert quote_store.lookup_by_hash(quote_hash(QUOTE)) == \
            quote_store.normalise_quote(QUOTE)

    def test_store_by_hash_is_content_addressed(self) -> None:
        """The EMIT path has no fingerprint_v2 — the backend derives it (0079).

        So the write is keyed by the quote's own hash, which is the one
        identifier the lineage row is guaranteed to carry back.
        """
        digest = quote_store.store_by_hash(QUOTE)
        assert digest == quote_hash(QUOTE)
        assert quote_store.lookup(digest) == quote_store.normalise_quote(QUOTE)
        assert quote_store.lookup_by_hash(digest) == quote_store.normalise_quote(QUOTE)

    def test_misses_are_none_not_errors(self) -> None:
        assert quote_store.lookup("nothing-here") is None
        assert quote_store.lookup_by_hash("sha256:" + "0" * 64) is None
        assert quote_store.lookup("") is None

    def test_an_empty_quote_is_not_stored(self) -> None:
        quote_store.store("fp2-empty", "   \n\n")
        assert quote_store.lookup("fp2-empty") is None


class TestStripSite:
    """The write happens where the quote last exists — and only there."""

    def test_strip_persists_the_quote_and_leaves_only_its_hash(self) -> None:
        finding = {"title": "t", "evidence_quote": QUOTE}

        _strip_private_fields(finding, ("evidence_quote",))

        assert "evidence_quote" not in finding
        assert finding["quote_hash"] == quote_hash(QUOTE)
        assert quote_store.lookup_by_hash(finding["quote_hash"]) == \
            quote_store.normalise_quote(QUOTE)

    def test_a_bare_model_authored_hash_never_enters_the_finding(self) -> None:
        """`_normalize_finding` admits `quote_hash` only as half of a PAIR.

        A hash with no quote beside it is a hash of nothing this process can
        check; on a lineage row it would resolve every future check of that row
        to `no_quote` forever. So the normaliser drops it, and the strip has
        nothing to undo — which is what keeps the strip idempotent.
        """
        assert "quote_hash" not in _normalize_finding(
            {"title": "t", "quote_hash": "sha256:" + "f" * 64},
        )

    def test_a_hash_paired_with_a_quote_is_admitted_then_overwritten(self) -> None:
        normalized = _normalize_finding(
            {"title": "t", "evidence_quote": QUOTE, "quote_hash": "sha256:" + "f" * 64},
        )
        assert normalized["quote_hash"] == "sha256:" + "f" * 64

        _strip_private_fields(normalized, ("evidence_quote",))

        assert normalized["quote_hash"] == quote_hash(QUOTE)

    def test_a_model_authored_hash_is_overwritten_by_the_real_one(self) -> None:
        finding = {"title": "t", "evidence_quote": QUOTE,
                   "quote_hash": "sha256:" + "f" * 64}

        _strip_private_fields(finding, ("evidence_quote",))

        assert finding["quote_hash"] == quote_hash(QUOTE)

    def test_a_strip_that_does_not_cover_the_quote_writes_nothing(self) -> None:
        """`_strip_private_fields` is called with two different rosters."""
        finding = {"title": "t", "evidence_quote": QUOTE}

        _strip_private_fields(finding, ("_model_check_id",))

        assert finding["evidence_quote"] == QUOTE
        assert quote_store.lookup_by_hash(quote_hash(QUOTE)) is None

    def test_a_dead_cache_costs_the_cache_not_the_finding(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A store that raises would delete a finding the audit already made."""
        def _boom(_quote: str) -> str:
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(quote_store, "store_by_hash", _boom)
        finding = {"title": "t", "evidence_quote": QUOTE}

        _strip_private_fields(finding, ("evidence_quote",))

        assert "evidence_quote" not in finding
        assert "quote_hash" not in finding
