"""RED tests: prove agent continues with API probing when no findings exist."""

from unittest.mock import AsyncMock, MagicMock, patch


def test_run_prove_continues_without_findings(monkeypatch):
    """Prove should NOT exit with 'Run a scan first' when no findings.

    Sets VULTURE_USE_LLM=true to exercise the LLM-mode prove path
    (this test is about the pipeline's empty-findings handling, not
    feature 0043's skills-only short-circuit — see
    test_skills_only_mode.py for that)."""
    monkeypatch.setenv("VULTURE_USE_LLM", "true")
    from prove_agent.agent import run_prove

    caps = MagicMock()
    caps.http = True
    caps.websocket = caps.jsonrpc_http = caps.jsonrpc_ws = False
    caps.grpc = caps.sse = caps.mqtt_ws = False

    bg = MagicMock()
    bg.done = True
    bg.result = None
    bg.learnings_context = ""
    bg.error = None
    bg.context_updated = False

    with patch("prove_agent.agent.validate_staging_url", return_value=None), \
         patch("prove_agent.agent.detect_capabilities", new_callable=AsyncMock, return_value=(caps, "HTTP")), \
         patch("prove_agent.agent._BackgroundDiscovery", return_value=bg), \
         patch("prove_agent.agent.load_cached_discovery", return_value=None), \
         patch("prove_agent.agent.probe_api_endpoints", new_callable=AsyncMock, return_value=[]), \
         patch("shared.llm.provider.get_model", return_value="test"):

        events = list(run_prove(
            run_id="test-no-findings",
            source_path="/tmp/test",
            config={"staging_url": "https://example.com", "types": ["owasp"]},
            prior_findings=None,
        ))

    text = " ".join(events)
    assert "Run a scan first" not in text
    assert "No scan findings" in text or "probing" in text.lower()
