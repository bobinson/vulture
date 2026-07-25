"""Unit tests for the discover agent."""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest

from discover_agent.findings import (
    analyze_security_exposures,
    _check_exposed_debug_endpoints,
    _check_graphql_introspection,
    _check_missing_security_headers,
    _check_sensitive_file_exposure,
    _check_server_version_disclosure,
)
from discover_agent.agent import _compute_discovery_score
from shared.discovery.sitemap import SiteMap


class _MockVerifyHandler(BaseHTTPRequestHandler):
    """Mock server for sensitive-file and graphql verification tests."""

    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=secret123\nAPI_KEY=abc")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            body = json.dumps({
                "data": {"__schema": {"queryType": {"name": "Query"}}}
            })
            self.wfile.write(body.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def verify_server():
    """Start a mock HTTP server for verification-based tests."""
    server = HTTPServer(("127.0.0.1", 0), _MockVerifyHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestSecurityFindings:
    """Tests for security exposure analysis."""

    def test_missing_hsts_header(self):
        site = SiteMap(headers={"content-type": "text/html"})
        findings = _check_missing_security_headers(site)
        titles = [f["title"] for f in findings]
        assert "Missing HSTS Header" in titles

    def test_all_headers_present_no_findings(self):
        site = SiteMap(headers={
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
        })
        findings = _check_missing_security_headers(site)
        assert len(findings) == 0

    def test_exposed_debug_endpoint(self):
        site = SiteMap(api_endpoints=["/api/users", "/debug", "/api/auth"])
        findings = _check_exposed_debug_endpoints(site)
        assert len(findings) == 1
        assert "debug" in findings[0]["title"].lower()

    def test_no_debug_endpoints(self):
        site = SiteMap(api_endpoints=["/api/users", "/api/auth"])
        findings = _check_exposed_debug_endpoints(site)
        assert len(findings) == 0

    def test_graphql_introspection_detected(self, verify_server):
        """GraphQL finding only when introspection is confirmed via HTTP probe."""
        site = SiteMap(api_endpoints=["/graphql", "/api/users"])
        findings = _check_graphql_introspection(site, verify_server)
        assert len(findings) == 1
        assert "GraphQL" in findings[0]["title"]
        assert "Introspection Enabled" in findings[0]["title"]

    def test_graphql_no_probe_without_url(self):
        """Without target_url, no graphql findings are emitted."""
        site = SiteMap(api_endpoints=["/graphql", "/api/users"])
        findings = _check_graphql_introspection(site)
        assert len(findings) == 0

    def test_no_graphql(self):
        site = SiteMap(api_endpoints=["/api/users"])
        findings = _check_graphql_introspection(site)
        assert len(findings) == 0

    def test_server_version_disclosure(self):
        site = SiteMap(headers={"server": "nginx/1.24.0"})
        findings = _check_server_version_disclosure(site)
        assert len(findings) == 1
        assert "nginx/1.24.0" in findings[0]["title"]

    def test_server_no_version(self):
        site = SiteMap(headers={"server": "nginx"})
        findings = _check_server_version_disclosure(site)
        assert len(findings) == 0

    def test_x_powered_by_disclosure(self):
        site = SiteMap(headers={"x-powered-by": "Express"})
        findings = _check_x_powered_by_disclosure(site)
        assert len(findings) == 1
        assert "Express" in findings[0]["title"]

    def test_sensitive_file_exposure_verified(self, verify_server):
        """Sensitive file finding only when HTTP 200 with real content."""
        site = SiteMap(urls=["/.env", "/api/users"], api_endpoints=["/api/auth"])
        findings = _check_sensitive_file_exposure(site, verify_server)
        assert len(findings) == 1
        assert ".env" in findings[0]["title"].lower()

    def test_sensitive_file_not_found(self, verify_server):
        """No finding when sensitive file returns 404."""
        site = SiteMap(urls=["/.git/config"], api_endpoints=[])
        findings = _check_sensitive_file_exposure(site, verify_server)
        assert len(findings) == 0

    def test_no_sensitive_files(self):
        site = SiteMap(urls=["/login", "/dashboard"], api_endpoints=["/api/auth"])
        findings = _check_sensitive_file_exposure(site, "http://localhost:1")
        assert len(findings) == 0


class TestAnalyzeSecurityExposures:
    """Tests for the combined exposure analysis."""

    def test_empty_site_produces_header_findings(self):
        site = SiteMap()
        findings = analyze_security_exposures(site, "https://example.com")
        # Empty site should still report missing headers
        assert len(findings) >= 4  # 4 missing security headers

    def test_secure_site_minimal_findings(self):
        site = SiteMap(
            headers={
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
            },
            api_endpoints=["/api/users", "/api/auth"],
            urls=["/login", "/dashboard"],
        )
        findings = analyze_security_exposures(site, "https://example.com")
        assert len(findings) == 0

    def test_findings_are_deduplicated(self):
        """Duplicate findings should be removed."""
        site = SiteMap(
            headers={"server": "nginx/1.24.0"},
        )
        findings = analyze_security_exposures(site, "https://example.com")
        titles = [f["title"] for f in findings]
        assert len(titles) == len(set(titles))


class TestDiscoveryScore:
    """Tests for discovery score computation."""

    def test_empty_site_zero_score(self):
        site = SiteMap()
        score = _compute_discovery_score(site, [])
        assert score == 0.0

    def test_rich_site_high_score(self):
        site = SiteMap(
            api_endpoints=[f"/api/v1/{i}" for i in range(20)],
            urls=[f"/page/{i}" for i in range(10)],
            forms=[{"action": f"/form/{i}", "method": "POST"} for i in range(3)],
        )
        score = _compute_discovery_score(site, [])
        assert score >= 0.5

    def test_findings_reduce_score(self):
        site = SiteMap(api_endpoints=["/api/users"])
        no_findings_score = _compute_discovery_score(site, [])
        with_findings_score = _compute_discovery_score(site, [
            {"severity": "critical"},
            {"severity": "high"},
        ])
        assert with_findings_score < no_findings_score

    def test_score_capped_at_one(self):
        site = SiteMap(
            api_endpoints=[f"/api/{i}" for i in range(100)],
            urls=[f"/u/{i}" for i in range(100)],
        )
        score = _compute_discovery_score(site, [])
        assert score <= 1.0


class TestRunDiscover:
    """Tests for the run_discover generator."""

    def test_missing_target_url_fails(self):
        from discover_agent.agent import run_discover
        events = list(run_discover("test-run", "/tmp", {}, []))
        event_types = [_parse_event_type(e) for e in events]
        assert "agent_start" in event_types
        assert "agent_end" in event_types
        # Should contain error about missing target_url
        assert any("ERROR" in e for e in events)


def _parse_event_type(event_str: str) -> str:
    """Extract event type from SSE string."""
    for line in event_str.split("\n"):
        if line.startswith("event: "):
            return line[7:].strip()
    return ""


def _check_x_powered_by_disclosure(site: SiteMap) -> list[dict]:
    """Helper wrapping the internal check for x-powered-by."""
    return _check_server_version_disclosure(site)
