"""Unit tests for chaos engineering skills."""

import os
import pytest

from chaos_agent.skills.retry_analysis import (
    check_retry_patterns,
    HTTP_CALL_PATTERNS,
    RETRY_PATTERNS,
)
from chaos_agent.config import ALL_CATEGORIES, AGENT_INFO, CONFIG_SCHEMA


class TestRetryPatternDetection:
    """Tests for retry pattern regex matching."""

    def test_detects_requests_get(self):
        assert any(p.search("requests.get(url)") for p in HTTP_CALL_PATTERNS)

    def test_detects_requests_post(self):
        assert any(p.search("requests.post(url, data=d)") for p in HTTP_CALL_PATTERNS)

    def test_detects_fetch(self):
        assert any(p.search("fetch('/api/data')") for p in HTTP_CALL_PATTERNS)

    def test_detects_axios(self):
        assert any(p.search("axios.get('/api')") for p in HTTP_CALL_PATTERNS)

    def test_detects_go_http(self):
        assert any(p.search("http.Get(url)") for p in HTTP_CALL_PATTERNS)

    def test_detects_aiohttp(self):
        assert any(p.search("async with aiohttp.ClientSession() as s:") for p in HTTP_CALL_PATTERNS)

    def test_detects_retry_keyword(self):
        assert any(p.search("max_retries = 3") for p in RETRY_PATTERNS)

    def test_detects_tenacity(self):
        assert any(p.search("from tenacity import retry") for p in RETRY_PATTERNS)

    def test_detects_backoff(self):
        assert any(p.search("exponential_backoff()") for p in RETRY_PATTERNS)

    def test_detects_retry_decorator(self):
        assert any(p.search("@retry(max_attempts=3)") for p in RETRY_PATTERNS)

    def test_no_false_positive_on_unrelated(self):
        assert not any(p.search("print('hello world')") for p in HTTP_CALL_PATTERNS)


class TestCheckRetryPatterns:
    """Tests for the check_retry_patterns skill function."""

    @pytest.fixture
    def source_dir(self, tmp_path):
        """Create a temporary source directory."""
        return tmp_path

    def test_no_findings_for_empty_dir(self, source_dir):
        result = check_retry_patterns(str(source_dir))
        assert result == {"findings": []}

    def test_no_findings_when_retry_present(self, source_dir):
        code = """import requests
from tenacity import retry

@retry(max_attempts=3)
def fetch_data():
    return requests.get("http://api.example.com/data")
"""
        (source_dir / "client.py").write_text(code)
        result = check_retry_patterns(str(source_dir))
        assert result["findings"] == []

    def test_finding_when_http_without_retry(self, source_dir):
        code = """import requests

def fetch_data():
    return requests.get("http://api.example.com/data")
"""
        (source_dir / "client.py").write_text(code)
        result = check_retry_patterns(str(source_dir))
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "high"
        assert finding["category"] == "retry-pattern"
        assert "retry" in finding["title"].lower()

    def test_skips_test_files(self, source_dir):
        code = """import requests
def test_api():
    requests.get("http://localhost/test")
"""
        (source_dir / "test_api.py").write_text(code)
        result = check_retry_patterns(str(source_dir))
        assert result["findings"] == []

    def test_multiple_http_calls_produce_multiple_findings(self, source_dir):
        code = """import requests

def get_user():
    return requests.get("http://api/user")

def post_data():
    return requests.post("http://api/data", json={})
"""
        (source_dir / "api.py").write_text(code)
        result = check_retry_patterns(str(source_dir))
        assert len(result["findings"]) >= 2


class TestChaosConfig:
    """Tests for agent configuration."""

    def test_all_categories_defined(self):
        assert "retry" in ALL_CATEGORIES
        assert "circuit_breaker" in ALL_CATEGORIES
        assert "timeout" in ALL_CATEGORIES
        assert "fallback" in ALL_CATEGORIES
        assert "blast_radius" in ALL_CATEGORIES

    def test_agent_info_has_required_fields(self):
        assert "name" in AGENT_INFO
        assert "type" in AGENT_INFO
        assert AGENT_INFO["type"] == "chaos"

    def test_config_schema_is_valid(self):
        assert CONFIG_SCHEMA["type"] == "object"
        categories = CONFIG_SCHEMA["properties"]["categories"]
        assert categories["type"] == "array"
        assert "retry" in categories["items"]["enum"]
