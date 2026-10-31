"""An agent-to-agent ``/run`` call must present the shared agent token.

The receiving agent refuses ``/run`` without ``X-Vulture-Agent-Token`` whenever
``VULTURE_AGENT_TOKEN`` is set (``sse_app._verify_agent_token``), and the
launcher now always sets one. The header a caller sends and the header the
verifier reads must come from the same place, so they cannot drift.
"""

from shared.transport import sse_app


def test_headers_carry_the_configured_token(monkeypatch):
    monkeypatch.setattr(sse_app, "_AGENT_TOKEN", "tok-123")
    assert sse_app.agent_token_headers() == {"X-Vulture-Agent-Token": "tok-123"}


def test_no_header_without_a_token(monkeypatch):
    monkeypatch.setattr(sse_app, "_AGENT_TOKEN", "")
    assert sse_app.agent_token_headers() == {}
