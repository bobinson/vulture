"""Unit tests for enhanced MMR with embedding similarity and confidence feedback."""

import pytest

from shared.tools.memory_client import (
    _cosine_similarity,
    _mmr_select,
    _prove_confidence_boost,
    _similarity,
    _title_tokens,
    _jaccard,
)


class TestCosineSimilarity:
    """Tests for cosine similarity computation."""

    def test_identical_vectors(self):
        v = [1.0, 0.0, 0.5]
        assert abs(_cosine_similarity(v, v) - 1.0) < 0.01

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        assert abs(_cosine_similarity(a, b)) < 0.01

    def test_opposite_vectors(self):
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert abs(_cosine_similarity(a, b) - (-1.0)) < 0.01

    def test_empty_vectors(self):
        assert _cosine_similarity([], []) == 0.0

    def test_mismatched_lengths(self):
        assert _cosine_similarity([1.0, 2.0], [1.0]) == 0.0

    def test_zero_vector(self):
        assert _cosine_similarity([0.0, 0.0], [1.0, 0.0]) == 0.0


class TestProveConfidenceBoost:
    """Tests for prove agent confidence adjustment."""

    def test_verified_boosts(self):
        m = {"prove_status": "verified"}
        assert _prove_confidence_boost(m) == 1.3

    def test_not_reproduced_demotes(self):
        m = {"prove_status": "not_reproduced"}
        assert _prove_confidence_boost(m) == 0.6

    def test_inconclusive_neutral(self):
        m = {"prove_status": "inconclusive"}
        assert _prove_confidence_boost(m) == 1.0

    def test_empty_neutral(self):
        m = {}
        assert _prove_confidence_boost(m) == 1.0


class TestSimilarityFunction:
    """Tests for the hybrid similarity function."""

    def test_uses_cosine_when_embeddings_available(self):
        a = {"title": "SQL injection", "embedding": [1.0, 0.0, 0.0]}
        b = {"title": "Command injection", "embedding": [0.0, 1.0, 0.0]}
        sim = _similarity(a, b, _title_tokens("SQL injection"), _title_tokens("Command injection"))
        # Should use cosine, which gives 0.0 for orthogonal
        assert abs(sim) < 0.01

    def test_falls_back_to_jaccard_without_embeddings(self):
        a = {"title": "SQL injection"}
        b = {"title": "SQL injection vulnerability"}
        tokens_a = _title_tokens("SQL injection")
        tokens_b = _title_tokens("SQL injection vulnerability")
        sim = _similarity(a, b, tokens_a, tokens_b)
        # Should use Jaccard, which gives positive overlap
        assert sim > 0.0

    def test_falls_back_when_embedding_not_list(self):
        a = {"title": "test", "embedding": "invalid"}
        b = {"title": "test", "embedding": "invalid"}
        sim = _similarity(a, b, _title_tokens("test"), _title_tokens("test"))
        # Should fall back to Jaccard
        assert sim >= 0.0


class TestMMRSelectEnhanced:
    """Tests for enhanced MMR selection."""

    def _make_memory(self, title, severity="high", confidence=0.5, prove_status="", embedding=None):
        m = {
            "title": title,
            "severity": severity,
            "confidence_score": confidence,
            "created_at": "2026-02-01T00:00:00Z",
        }
        if prove_status:
            m["prove_status"] = prove_status
        if embedding:
            m["embedding"] = embedding
        return m

    def test_selects_up_to_max(self):
        candidates = [self._make_memory(f"Finding {i}") for i in range(10)]
        selected = _mmr_select(candidates, 5)
        assert len(selected) == 5

    def test_returns_all_if_under_max(self):
        candidates = [self._make_memory(f"Finding {i}") for i in range(3)]
        selected = _mmr_select(candidates, 5)
        assert len(selected) == 3

    def test_prefers_verified_findings(self):
        candidates = [
            self._make_memory("Unverified finding", confidence=0.5),
            self._make_memory("Verified finding", confidence=0.5, prove_status="verified"),
            self._make_memory("Another unverified", confidence=0.5),
        ]
        selected = _mmr_select(candidates, 2)
        titles = [s["title"] for s in selected]
        assert "Verified finding" in titles

    def test_demotes_not_reproduced_findings(self):
        candidates = [
            self._make_memory("Good finding", confidence=0.8),
            self._make_memory("Rejected finding", confidence=0.8, prove_status="not_reproduced"),
        ]
        selected = _mmr_select(candidates, 1)
        assert selected[0]["title"] == "Good finding"

    def test_diversity_with_embeddings(self):
        # Two similar findings (same direction) and one different
        candidates = [
            self._make_memory("SQL injection A", confidence=0.8, embedding=[1.0, 0.0, 0.0]),
            self._make_memory("SQL injection B", confidence=0.8, embedding=[0.9, 0.1, 0.0]),
            self._make_memory("XSS vulnerability", confidence=0.7, embedding=[0.0, 1.0, 0.0]),
        ]
        selected = _mmr_select(candidates, 2, lam=0.5)
        titles = [s["title"] for s in selected]
        # With diversity pressure, should pick one SQL + one XSS
        assert any("SQL" in t for t in titles)
        assert any("XSS" in t for t in titles)

    def test_pure_relevance_mode(self):
        candidates = [
            self._make_memory("High conf", confidence=0.9),
            self._make_memory("Low conf", confidence=0.3),
        ]
        selected = _mmr_select(candidates, 1, lam=1.0)
        assert selected[0]["title"] == "High conf"
