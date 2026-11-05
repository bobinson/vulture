"""prove → discover is an agent-to-agent ``/run`` call; discover enforces the
shared agent token, so prove must send it or every discovery is refused."""

from unittest.mock import patch

from prove_agent.discover_client import call_discover
from shared.transport import sse_app


class _CapturingClient:
    """httpx.Client stand-in that records the headers of the streamed request,
    then fails it (call_discover treats any error as "discovery unavailable")."""

    seen: dict = {}

    def __init__(self, *_args, **_kwargs):
        pass

    def stream(self, _method, _url, **kwargs):
        _CapturingClient.seen = kwargs.get("headers") or {}
        raise RuntimeError("stop after capturing the request")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _sent_headers() -> dict:
    with patch("prove_agent.discover_client.httpx.Client", _CapturingClient):
        call_discover("http://target.example")
    return _CapturingClient.seen


def test_sends_the_agent_token(monkeypatch):
    monkeypatch.setattr(sse_app, "_AGENT_TOKEN", "tok-123")
    assert _sent_headers().get("X-Vulture-Agent-Token") == "tok-123"


def test_sends_no_token_when_none_is_configured(monkeypatch):
    monkeypatch.setattr(sse_app, "_AGENT_TOKEN", "")
    assert "X-Vulture-Agent-Token" not in _sent_headers()
