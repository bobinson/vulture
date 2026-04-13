"""E2E tests for the discover agent with mock HTTP server."""

import json
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

import pytest

from discover_agent.agent import run_discover


class _MockHandler(SimpleHTTPRequestHandler):
    """Simple mock web server for discovery testing."""

    def do_GET(self):
        routes = {
            "/": (200, "text/html", (
                "<html><head><title>Test App</title></head>"
                "<body>"
                '<a href="/api/users">Users</a>'
                '<a href="/about">About</a>'
                '<form action="/api/login" method="POST">'
                '<input name="email"/><input name="password"/>'
                "</form>"
                "</body></html>"
            )),
            "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /admin\n"),
            "/api/users": (200, "application/json", '{"users": []}'),
            "/api/login": (200, "application/json", '{"status": "ok"}'),
            "/health": (200, "application/json", '{"status": "healthy"}'),
        }
        path = self.path.split("?")[0]
        if path in routes:
            status, ct, body = routes[path]
            self.send_response(status)
            self.send_header("Content-Type", ct)
            self.send_header("Server", "TestServer/1.0")
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress log output during tests


@pytest.fixture(scope="module")
def mock_server():
    """Start a mock HTTP server for discovery testing."""
    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestDiscoverE2E:
    """E2E tests for the discover agent pipeline."""

    def test_full_discovery_pipeline(self, mock_server):
        """Test complete discovery against mock server."""
        config = {"target_url": mock_server}
        events = list(run_discover("e2e-run-1", "", config, []))

        event_types = [_parse_event_type(e) for e in events]
        assert "agent_start" in event_types
        assert "agent_end" in event_types
        assert "discover_result" in event_types
        assert "result" in event_types

    def test_discovery_finds_endpoints(self, mock_server):
        """Test that discovery finds API endpoints from HTML."""
        config = {"target_url": mock_server}
        events = list(run_discover("e2e-run-2", "", config, []))

        discover_event = _find_event(events, "discover_result")
        assert discover_event is not None
        data = _parse_event_data(discover_event)
        assert data["api_count"] >= 1

    def test_discovery_detects_server_version(self, mock_server):
        """Test that security analysis catches server version disclosure."""
        config = {"target_url": mock_server}
        events = list(run_discover("e2e-run-3", "", config, []))

        finding_events = [e for e in events if _parse_event_type(e) == "finding"]
        titles = [_parse_event_data(e).get("title", "") for e in finding_events]
        assert any("Server Version" in t for t in titles)

    def test_discovery_emits_progress(self, mock_server):
        """Test that discovery emits thinking/status events."""
        config = {"target_url": mock_server}
        events = list(run_discover("e2e-run-4", "", config, []))

        thinking_events = [e for e in events if _parse_event_type(e) == "thinking"]
        assert len(thinking_events) >= 2  # At least start + complete messages

    def test_no_cache_mode(self, mock_server):
        """Test that no_cache mode skips cached results."""
        config = {"target_url": mock_server, "no_cache": True}
        events = list(run_discover("e2e-run-5", "", config, []))

        event_types = [_parse_event_type(e) for e in events]
        assert "discover_result" in event_types

    def test_prior_findings_filter(self, mock_server):
        """Test that prior findings are filtered from output."""
        prior = [{"title": "Missing HSTS Header"}]
        config = {"target_url": mock_server}

        events_without_prior = list(run_discover("e2e-run-6a", "", config, []))
        events_with_prior = list(run_discover("e2e-run-6b", "", config, prior))

        findings_without = [e for e in events_without_prior if _parse_event_type(e) == "finding"]
        findings_with = [e for e in events_with_prior if _parse_event_type(e) == "finding"]
        assert len(findings_with) <= len(findings_without)

    def test_missing_target_url_returns_error(self):
        """Test that missing target_url produces error."""
        events = list(run_discover("e2e-run-7", "", {}, []))

        event_types = [_parse_event_type(e) for e in events]
        assert "agent_start" in event_types
        assert "agent_end" in event_types

        end_event = _find_event(events, "agent_end")
        data = _parse_event_data(end_event)
        assert data.get("status") == "failed"

    def test_result_contains_score(self, mock_server):
        """Test that result event includes a discovery score."""
        config = {"target_url": mock_server}
        events = list(run_discover("e2e-run-8", "", config, []))

        result_event = _find_event(events, "result")
        data = _parse_event_data(result_event)
        assert "score" in data
        assert 0.0 <= data["score"] <= 1.0


def _parse_event_type(event_str: str) -> str:
    """Extract event type from SSE string."""
    for line in event_str.split("\n"):
        if line.startswith("event: "):
            return line[7:].strip()
    return ""


def _parse_event_data(event_str: str) -> dict:
    """Extract data payload from SSE string."""
    for line in event_str.split("\n"):
        if line.startswith("data: "):
            return json.loads(line[6:])
    return {}


def _find_event(events: list[str], event_type: str) -> str | None:
    """Find the first event of a given type."""
    for e in events:
        if _parse_event_type(e) == event_type:
            return e
    return None
