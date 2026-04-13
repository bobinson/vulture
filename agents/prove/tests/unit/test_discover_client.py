"""Tests for the discover_client module — HTTP SSE client for discover agent."""

import json
from unittest.mock import MagicMock, patch

import pytest

from prove_agent.discover_client import call_discover


class _FakeStreamResponse:
    """Mock httpx streaming response."""

    def __init__(self, events: list[tuple[str, dict]]):
        self._lines = []
        for event_type, data in events:
            self._lines.append(f"event: {event_type}")
            self._lines.append(f"data: {json.dumps(data)}")
            self._lines.append("")  # blank line separator
        self.status_code = 200

    def iter_lines(self):
        return iter(self._lines)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _FakeClient:
    """Mock httpx.Client that returns a streaming response."""

    def __init__(self, events: list[tuple[str, dict]]):
        self._events = events

    def stream(self, method, url, **kwargs):
        return _FakeStreamResponse(self._events)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class TestCallDiscover:
    """Tests for call_discover HTTP SSE client."""

    def test_parses_discover_result_event(self):
        """Should parse site_map_json and learnings_context from discover_result."""
        site_json = json.dumps({
            "urls": ["/login", "/api/users"],
            "api_endpoints": ["/api/users", "/api/auth"],
            "forms": [],
            "disallowed_paths": [],
            "headers": {},
            "technologies": ["Express"],
        })
        events = [
            ("discover_result", {
                "site_map_json": site_json,
                "learnings_context": "Auth type: jwt\nTech stack: Express",
            }),
        ]
        with patch("prove_agent.discover_client.httpx.Client") as mock_cls:
            mock_cls.return_value = _FakeClient(events)
            site, ctx, findings = call_discover("https://example.com")

        assert site is not None
        assert len(site.api_endpoints) == 2
        assert "jwt" in ctx
        assert findings == []

    def test_parses_finding_events(self):
        """Should collect finding events."""
        events = [
            ("finding", {"severity": "high", "title": "XSS", "category": "owasp"}),
            ("finding", {"severity": "low", "title": "Info", "category": "misc"}),
        ]
        with patch("prove_agent.discover_client.httpx.Client") as mock_cls:
            mock_cls.return_value = _FakeClient(events)
            site, ctx, findings = call_discover("https://example.com")

        assert site is None
        assert ctx == ""
        assert len(findings) == 2
        assert findings[0]["title"] == "XSS"

    def test_handles_empty_response(self):
        """Should return None when no events received."""
        with patch("prove_agent.discover_client.httpx.Client") as mock_cls:
            mock_cls.return_value = _FakeClient([])
            site, ctx, findings = call_discover("https://example.com")

        assert site is None
        assert ctx == ""
        assert findings == []

    def test_handles_connection_error(self):
        """Should handle connection errors gracefully."""
        with patch(
            "prove_agent.discover_client.httpx.Client",
            side_effect=Exception("connection refused"),
        ):
            site, ctx, findings = call_discover("https://example.com")

        assert site is None
        assert ctx == ""
        assert findings == []

    def test_passes_config_options(self):
        """Should pass source_path, no_cache, schemas in request."""
        captured = {}

        class _CapturingClient:
            def stream(self, method, url, **kwargs):
                captured["method"] = method
                captured["url"] = url
                captured["json"] = kwargs.get("json", {})
                return _FakeStreamResponse([])

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        with patch("prove_agent.discover_client.httpx.Client") as mock_cls:
            mock_cls.return_value = _CapturingClient()
            call_discover(
                "https://example.com",
                source_path="/code",
                no_cache=True,
                schemas={"openapi": "/spec.json"},
            )

        assert captured["method"] == "POST"
        assert "/run" in captured["url"]
        config = captured["json"]["config"]
        assert config["target_url"] == "https://example.com"
        assert config["source_path"] == "/code"
        assert config["no_cache"] is True
        assert config["schemas"] == {"openapi": "/spec.json"}
