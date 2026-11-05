"""Feature 0074 contract T2: VULTURE_USE_LLM is on for any of true/1/yes/on
(the shared token list), so the prove agent's skills-only messages must not
tell the operator the switch has to be exactly ``true``."""

from __future__ import annotations

from unittest.mock import patch

import pytest


def _messages(monkeypatch, use_llm: str, require: bool) -> str:
    from prove_agent.agent import run_prove

    monkeypatch.setenv("VULTURE_USE_LLM", use_llm)
    if require:
        monkeypatch.setenv("VULTURE_REQUIRE_LLM", "true")
    else:
        monkeypatch.delenv("VULTURE_REQUIRE_LLM", raising=False)
    config = {"staging_url": "https://example.com", "types": ["owasp"]}
    with patch("prove_agent.agent.validate_staging_url", return_value=None):
        return " ".join(run_prove(run_id="t2", source_path="/tmp/t2", config=config,
                                  prior_findings=None))


@pytest.mark.parametrize("require", [False, True], ids=["skipped", "conflict"])
def test_skills_only_messages_name_the_token_list(monkeypatch, require) -> None:
    joined = _messages(monkeypatch, "off", require)
    assert "!= true" not in joined
    assert "not set to 'true'" not in joined
    assert "true, 1, yes or on" in joined
