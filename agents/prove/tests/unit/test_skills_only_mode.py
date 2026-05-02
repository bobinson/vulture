"""Feature 0043: prove agent honors VULTURE_USE_LLM=false.

Asserts the regression class that hit users on 2026-05-02:

    [agent-prove] LLM call failed (attempt 1): AuthenticationError ...
    [agent-prove] model_cooldown_start model=gpt-4o failures=12 cooldown=300s

The prove agent must short-circuit BEFORE any LLM call when the
operator has opted out of LLM use, so no AuthenticationError +
litellm cooldown loops happen.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch):
    """Clear LLM-mode env vars before every test."""
    monkeypatch.delenv("VULTURE_USE_LLM", raising=False)
    monkeypatch.delenv("VULTURE_REQUIRE_LLM", raising=False)


def _run_with_valid_url(config_overrides=None):
    """Run run_prove with validate_staging_url stubbed to OK so we
    exit through the skills-only branch (next gate after URL valid)."""
    from prove_agent.agent import run_prove

    config = {"staging_url": "https://example.com", "types": ["owasp"]}
    if config_overrides:
        config.update(config_overrides)

    with patch("prove_agent.agent.validate_staging_url", return_value=None):
        # Critical: do NOT mock get_model or any LLM-side function. If
        # the skills-only short-circuit doesn't fire, the test will hit
        # the real provider lookup (and fail loudly), which is the
        # correct failure mode — we want to prove the short-circuit
        # happens BEFORE any LLM machinery is touched.
        return list(run_prove(
            run_id="test-skills-only",
            source_path="/tmp/test",
            config=config,
            prior_findings=None,
        ))


class TestSkillsOnlyShortCircuit:
    def test_unset_use_llm_skips_prove(self):
        """Default: VULTURE_USE_LLM unset → prove skips cleanly."""
        events = _run_with_valid_url()
        joined = " ".join(events)
        assert "skills-only mode" in joined
        assert "VULTURE_USE_LLM" in joined
        # Run finished with `skipped`, not failed.
        assert any('"status":"skipped"' in e or "'status':'skipped'" in e
                   or '"skipped"' in e for e in events), \
            f"expected run_finished('skipped'); events: {events[-3:]}"

    def test_explicit_false_skips_prove(self, monkeypatch):
        monkeypatch.setenv("VULTURE_USE_LLM", "false")
        events = _run_with_valid_url()
        assert any("skills-only mode" in e for e in events)

    def test_no_llm_imports_in_skills_mode(self, monkeypatch):
        """Critical: skills-only path must NOT import litellm / call
        get_model / contact any LLM provider. Test asserts no calls to
        prove_agent.llm_helper are made."""
        monkeypatch.setenv("VULTURE_USE_LLM", "false")

        # Patch reset_token_usage and get_model — if they're called,
        # the short-circuit didn't fire.
        with patch("prove_agent.llm_helper.reset_token_usage") as mock_reset, \
             patch("shared.llm.provider.get_model") as mock_get_model:
            _run_with_valid_url()
            mock_reset.assert_not_called()
            mock_get_model.assert_not_called()

    def test_required_plus_skills_only_is_config_conflict(self, monkeypatch):
        """VULTURE_REQUIRE_LLM=true + VULTURE_USE_LLM != true →
        explicit config-conflict error, not skipped."""
        monkeypatch.setenv("VULTURE_REQUIRE_LLM", "true")
        # VULTURE_USE_LLM remains unset (skills-only)
        events = _run_with_valid_url()
        joined = " ".join(events)
        assert "Configuration conflict" in joined
        # Should fail, not skip.
        assert any('"status":"failed"' in e or "'status':'failed'" in e
                   or '"failed"' in e for e in events), \
            f"expected run_finished('failed'); events: {events[-3:]}"

    def test_use_llm_true_does_not_short_circuit(self, monkeypatch):
        """When operator opts into LLM, skills-only branch must NOT
        fire — prove should proceed to the existing LLM-checks path.
        Test stops at the staging-URL probe (next gate)."""
        monkeypatch.setenv("VULTURE_USE_LLM", "true")
        from prove_agent.agent import run_prove

        with patch("prove_agent.agent.validate_staging_url", return_value=None), \
             patch("shared.llm.provider.get_model", return_value="gpt-4o"), \
             patch("prove_agent.agent.detect_capabilities",
                   side_effect=Exception("staging unreachable for test")):
            events = list(run_prove(
                run_id="test-llm-mode",
                source_path="/tmp/test",
                config={"staging_url": "https://example.com", "types": ["owasp"]},
                prior_findings=None,
            ))

        # Skills-only banner must NOT appear when use_llm=true.
        assert not any("skills-only mode" in e for e in events), \
            "LLM mode incorrectly triggered the skills-only short-circuit"
        # Should reach the LLM-availability check + the staging probe.
        joined = " ".join(events)
        assert "Using LLM model" in joined or "Staging URL unreachable" in joined
