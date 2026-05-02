"""Tests for shared/llm/mode.py — feature 0043."""

from __future__ import annotations

import pytest

from shared.llm import mode


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch):
    """Clear LLM-mode env vars before every test."""
    monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
    monkeypatch.delenv("VULTURE_REQUIRE_LLM", raising=False)


class TestIsSkillsOnly:
    def test_unset_is_skills_only(self):
        assert mode.is_skills_only() is True

    def test_empty_is_skills_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "")
        assert mode.is_skills_only() is True

    def test_false_is_skills_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "false")
        assert mode.is_skills_only() is True

    def test_garbage_is_skills_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "yes")
        assert mode.is_skills_only() is True

    def test_true_is_not_skills_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        assert mode.is_skills_only() is False

    def test_TRUE_uppercase_is_not_skills_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "TRUE")
        assert mode.is_skills_only() is False

    def test_True_mixed_case_is_not_skills_only(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "True")
        assert mode.is_skills_only() is False


class TestIsLLMRequired:
    def test_unset_is_not_required(self):
        assert mode.is_llm_required() is False

    def test_false_is_not_required(self, monkeypatch):
        monkeypatch.setenv("VULTURE_REQUIRE_LLM", "false")
        assert mode.is_llm_required() is False

    def test_true_is_required(self, monkeypatch):
        monkeypatch.setenv("VULTURE_REQUIRE_LLM", "true")
        assert mode.is_llm_required() is True

    def test_TRUE_uppercase_is_required(self, monkeypatch):
        monkeypatch.setenv("VULTURE_REQUIRE_LLM", "TRUE")
        assert mode.is_llm_required() is True
