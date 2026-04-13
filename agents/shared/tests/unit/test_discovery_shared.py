"""Unit tests for the shared discovery package."""

import json

from shared.discovery.sitemap import SiteMap
from shared.discovery.helpers import (
    is_static_path,
    is_page_path,
    filter_static_endpoints,
    extract_links,
    extract_forms,
    extract_json_urls,
)
from shared.discovery.cache import _cache_path


class TestSiteMap:
    """Tests for SiteMap dataclass."""

    def test_empty_sitemap_summary(self):
        site = SiteMap()
        assert site.summary() == "No site structure discovered."

    def test_summary_includes_technologies(self):
        site = SiteMap(technologies=["react", "next.js"])
        assert "react" in site.summary()
        assert "next.js" in site.summary()

    def test_summary_includes_api_endpoints(self):
        site = SiteMap(api_endpoints=["/api/users", "/api/auth"])
        summary = site.summary()
        assert "/api/users" in summary
        assert "/api/auth" in summary

    def test_merge_adds_new_items(self):
        a = SiteMap(urls=["/a"], api_endpoints=["/api/a"])
        b = SiteMap(urls=["/b"], api_endpoints=["/api/b"])
        added = a.merge(b)
        assert added == 2
        assert "/b" in a.urls
        assert "/api/b" in a.api_endpoints

    def test_merge_deduplicates(self):
        a = SiteMap(urls=["/a"], api_endpoints=["/api/a"])
        b = SiteMap(urls=["/a"], api_endpoints=["/api/a"])
        added = a.merge(b)
        assert added == 0
        assert len(a.urls) == 1

    def test_merge_technologies(self):
        a = SiteMap(technologies=["react"])
        b = SiteMap(technologies=["react", "vue"])
        a.merge(b)
        assert "vue" in a.technologies
        assert a.technologies.count("react") == 1

    def test_to_json_and_from_json(self):
        site = SiteMap(
            urls=["/a", "/b"],
            api_endpoints=["/api/x"],
            technologies=["react"],
            headers={"server": "nginx"},
        )
        json_str = site.to_json()
        restored = SiteMap.from_json(json_str)
        assert restored.urls == site.urls
        assert restored.api_endpoints == site.api_endpoints
        assert restored.technologies == site.technologies
        assert restored.headers == site.headers

    def test_from_json_ignores_unknown_fields(self):
        data = json.dumps({"urls": ["/x"], "unknown_field": "ignored"})
        site = SiteMap.from_json(data)
        assert site.urls == ["/x"]

    def test_deduplicate(self):
        site = SiteMap(
            urls=["/b", "/a", "/a"],
            api_endpoints=["/api/z", "/api/a", "/api/z"],
            technologies=["react", "react"],
            forms=[
                {"action": "/login", "method": "POST"},
                {"action": "/login", "method": "POST"},
            ],
        )
        site.deduplicate()
        assert site.urls == ["/a", "/b"]
        assert site.api_endpoints == ["/api/a", "/api/z"]
        assert site.technologies == ["react"]
        assert len(site.forms) == 1


class TestHelpers:
    """Tests for discovery helper functions."""

    def test_is_static_path(self):
        assert is_static_path("/bundle.js")
        assert is_static_path("/style.css")
        assert is_static_path("/image.png")
        assert is_static_path("/_next/static/chunks/main.js")
        assert not is_static_path("/api/users")
        assert not is_static_path("/health")

    def test_is_page_path(self):
        assert is_page_path("/login")
        assert is_page_path("/dashboard")
        assert is_page_path("/settings/profile")
        assert not is_page_path("/api/users")
        assert not is_page_path("/api/settings")

    def test_filter_static_endpoints(self):
        site = SiteMap(api_endpoints=["/api/users", "/bundle.js", "/login", "/api/auth"])
        filter_static_endpoints(site)
        assert "/api/users" in site.api_endpoints
        assert "/api/auth" in site.api_endpoints
        assert "/bundle.js" not in site.api_endpoints
        assert "/login" not in site.api_endpoints

    def test_extract_links(self):
        html = '<a href="/api/users">Users</a><a href="/about">About</a>'
        site = SiteMap()
        extract_links(html, "http://example.com", site)
        assert "/about" in site.urls
        assert "/api/users" in site.api_endpoints

    def test_extract_forms(self):
        html = '<form action="/api/login" method="POST"><input name="email"/></form>'
        site = SiteMap()
        extract_forms(html, "http://example.com", site)
        assert len(site.forms) == 1
        assert site.forms[0]["action"] == "/api/login"
        assert site.forms[0]["method"] == "POST"
        assert "email" in site.forms[0]["inputs"]

    def test_extract_json_urls(self):
        data = json.dumps({
            "links": {
                "self": "http://example.com/api/v1/resource",
                "next": "/api/v1/resource?page=2",
            }
        })
        site = SiteMap()
        extract_json_urls(data, "http://example.com", site)
        assert "/api/v1/resource" in site.api_endpoints


class TestCache:
    """Tests for discovery cache helpers."""

    def test_cache_path_deterministic(self):
        path1 = _cache_path("https://example.com")
        path2 = _cache_path("https://example.com")
        assert path1 == path2

    def test_cache_path_different_urls(self):
        path1 = _cache_path("https://example.com")
        path2 = _cache_path("https://other.com")
        assert path1 != path2
