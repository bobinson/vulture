"""RED tests for scan enrichment in discover agent."""

from unittest.mock import MagicMock, patch



# --- Route extraction tests ---

def test_extract_routes_from_scan_findings():
    from discover_agent.agent import _extract_routes_from_findings

    findings = [
        {"title": "SQL Injection", "file_path": "/app/api/users.py", "category": "injection"},
        {"title": "XSS", "file_path": "/app/routes/admin.js", "category": "xss"},
        {"title": "Weak Crypto", "file_path": "/lib/crypto.py", "category": "crypto"},
    ]
    routes = _extract_routes_from_findings(findings)
    assert "/api/users" in routes
    assert "/routes/admin" in routes
    assert "/lib/crypto" not in routes


def test_extract_routes_empty():
    from discover_agent.agent import _extract_routes_from_findings

    assert _extract_routes_from_findings([]) == []


def test_extract_routes_no_file_paths():
    from discover_agent.agent import _extract_routes_from_findings

    findings = [{"title": "Bug", "category": "misc"}]
    assert _extract_routes_from_findings(findings) == []


def test_extract_routes_deduplicates():
    from discover_agent.agent import _extract_routes_from_findings

    findings = [
        {"title": "A", "file_path": "/api/users.py"},
        {"title": "B", "file_path": "/api/users.py"},
    ]
    routes = _extract_routes_from_findings(findings)
    assert routes.count("/api/users") == 1


# --- Backend fetch tests ---

def test_fetch_scan_findings_from_backend():
    from discover_agent.agent import _fetch_scan_findings

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"title": "SQLi", "file_path": "/api/users.py"},
    ]
    with patch("discover_agent.agent.httpx.get", return_value=mock_resp) as mock_get:
        results = _fetch_scan_findings("/path/to/source")
    assert len(results) == 1
    mock_get.assert_called_once()


def test_fetch_scan_findings_no_source_path():
    from discover_agent.agent import _fetch_scan_findings

    assert _fetch_scan_findings("") == []


def test_fetch_scan_findings_backend_error():
    from discover_agent.agent import _fetch_scan_findings

    with patch("discover_agent.agent.httpx.get", side_effect=Exception("down")):
        assert _fetch_scan_findings("/path") == []


def test_fetch_scan_findings_http_error_status():
    from discover_agent.agent import _fetch_scan_findings

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    with patch("discover_agent.agent.httpx.get", return_value=mock_resp):
        assert _fetch_scan_findings("/path") == []


def test_fetch_scan_findings_dict_response():
    from discover_agent.agent import _fetch_scan_findings

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"memories": [{"title": "Bug"}]}
    with patch("discover_agent.agent.httpx.get", return_value=mock_resp):
        results = _fetch_scan_findings("/path")
    assert len(results) == 1


def test_fetch_scan_findings_malformed_json():
    from discover_agent.agent import _fetch_scan_findings

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("not json")
    with patch("discover_agent.agent.httpx.get", return_value=mock_resp):
        assert _fetch_scan_findings("/path") == []
