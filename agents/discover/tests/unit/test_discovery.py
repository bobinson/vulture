"""Tests for the discovery module — filtering, classification, and deduplication."""

import json

import pytest

from shared.discovery.sitemap import SiteMap
from shared.discovery.helpers import (
    filter_static_endpoints,
    is_page_path,
    is_static_path,
)


# --- Static path detection ---


class TestIsStaticPath:
    """Tests for is_static_path()."""

    @pytest.mark.parametrize("path", [
        "/_next/static/chunks/main-abc.js",
        "/_next/static/1234/_buildManifest.js",
        "/_next/static/1234/_ssgManifest.js",
        "/_next/data/1234/login.json",
        "/static/logo.png",
        "/assets/style.css",
        "/favicon.ico",
        "/manifest.json",
        "/node_modules/react/index.js",
        "/sw.js",
        "/service-worker.js",
        "/workbox-abc.js",
    ])
    def test_static_paths_detected(self, path):
        assert is_static_path(path) is True

    @pytest.mark.parametrize("path", [
        "/api/users",
        "/api/auth/session",
        "/api/graphql",
        "/v1/users",
        "/graphql",
        "/api/firebase/firebaseConfig",
        "/health",
        "/login",
    ])
    def test_non_static_paths(self, path):
        assert is_static_path(path) is False

    def test_case_insensitive(self):
        assert is_static_path("/_NEXT/STATIC/chunk.JS") is True
        assert is_static_path("/ASSETS/logo.PNG") is True

    def test_extensions_comprehensive(self):
        """All common static extensions are detected."""
        for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2",
                     ".ttf", ".mp4", ".pdf", ".zip", ".gz", ".map", ".webp"):
            assert is_static_path(f"/some/file{ext}") is True, f"Failed for {ext}"


# --- Page path detection ---


class TestIsPagePath:
    """Tests for is_page_path()."""

    @pytest.mark.parametrize("path", [
        "/login",
        "/register",
        "/signup",
        "/dashboard",
        "/settings",
        "/profile",
        "/admin",
        "/discover",
        "/settings/privacy-policy",
        "/settings/tos",
        "/admin/users",
    ])
    def test_page_paths_detected(self, path):
        assert is_page_path(path) is True

    @pytest.mark.parametrize("path", [
        "/api/auth/login",
        "/api/users",
        "/api/admin/settings",
        "/v1/login",
        "/graphql",
        "/api/graphql",
    ])
    def test_api_paths_not_pages(self, path):
        assert is_page_path(path) is False

    def test_trailing_slash_normalized(self):
        assert is_page_path("/login/") is True
        assert is_page_path("/dashboard/") is True


# --- Filter static endpoints ---


class TestFilterStaticEndpoints:
    """Tests for filter_static_endpoints()."""

    def test_removes_static_and_pages(self):
        site = SiteMap(api_endpoints=[
            "/api/users",
            "/_next/data/1234/login.json",
            "/login",
            "/api/auth/session",
            "/settings",
            "/_next/static/chunks/main.js",
            "/api/graphql",
            "/register",
        ])
        filter_static_endpoints(site)
        assert "/api/users" in site.api_endpoints
        assert "/api/auth/session" in site.api_endpoints
        assert "/api/graphql" in site.api_endpoints
        # Pages and static removed
        assert "/_next/data/1234/login.json" not in site.api_endpoints
        assert "/login" not in site.api_endpoints
        assert "/settings" not in site.api_endpoints
        assert "/_next/static/chunks/main.js" not in site.api_endpoints
        assert "/register" not in site.api_endpoints

    def test_empty_list(self):
        site = SiteMap(api_endpoints=[])
        filter_static_endpoints(site)
        assert site.api_endpoints == []


# --- SiteMap deduplication ---


class TestSiteMapDeduplicate:
    """Tests for SiteMap.deduplicate()."""

    def test_removes_duplicate_urls(self):
        site = SiteMap(urls=["/login", "/login", "/api/users", "/api/users"])
        site.deduplicate()
        assert site.urls == ["/api/users", "/login"]

    def test_removes_duplicate_forms(self):
        site = SiteMap(forms=[
            {"action": "/login", "method": "POST", "inputs": ["email"]},
            {"action": "/login", "method": "POST", "inputs": ["email"]},
            {"action": "/login", "method": "GET", "inputs": []},
        ])
        site.deduplicate()
        assert len(site.forms) == 2
        methods = {f["method"] for f in site.forms}
        assert methods == {"POST", "GET"}


# --- SiteMap merge ---


class TestSiteMapMerge:
    """Tests for SiteMap.merge()."""

    def test_merge_adds_new_items(self):
        site = SiteMap(
            urls=["/login"],
            api_endpoints=["/api/users"],
        )
        other = SiteMap(
            urls=["/login", "/register"],
            api_endpoints=["/api/users", "/api/auth"],
        )
        new_count = site.merge(other)
        assert new_count == 2  # /register + /api/auth
        assert "/register" in site.urls
        assert "/api/auth" in site.api_endpoints

    def test_merge_preserves_forms(self):
        site = SiteMap(forms=[{"action": "/login", "method": "POST", "inputs": []}])
        other = SiteMap(forms=[
            {"action": "/login", "method": "POST", "inputs": []},
            {"action": "/register", "method": "POST", "inputs": ["email"]},
        ])
        site.merge(other)
        assert len(site.forms) == 2


# --- SiteMap serialization ---


class TestSiteMapSerialization:
    """Tests for SiteMap JSON serialization."""

    def test_round_trip(self):
        site = SiteMap(
            urls=["/api/users", "/login"],
            api_endpoints=["/api/users"],
            forms=[{"action": "/login", "method": "POST", "inputs": ["email"]}],
            headers={"server": "nginx"},
            technologies=["Next.js", "GraphQL"],
            disallowed_paths=["/admin"],
        )
        json_str = site.to_json()
        restored = SiteMap.from_json(json_str)
        assert restored.urls == site.urls
        assert restored.api_endpoints == site.api_endpoints
        assert restored.forms == site.forms
        assert restored.headers == site.headers
        assert restored.technologies == site.technologies
        assert restored.disallowed_paths == site.disallowed_paths


# --- Summary format ---


class TestSiteMapSummary:
    """Tests for SiteMap.summary() — LLM context formatting."""

    def test_api_endpoints_prioritized(self):
        site = SiteMap(
            urls=["/login", "/register"],
            api_endpoints=["/api/users", "/api/auth/session"],
            technologies=["Next.js"],
        )
        summary = site.summary()
        # API endpoints should appear before page URLs
        api_pos = summary.find("API endpoints")
        pages_pos = summary.find("Other pages")
        assert api_pos < pages_pos
        assert "/api/users" in summary
        assert "/api/auth/session" in summary

    def test_forms_show_inputs(self):
        site = SiteMap(forms=[
            {"action": "/api/auth/login", "method": "POST", "inputs": ["email", "password"]},
        ])
        summary = site.summary()
        assert "POST /api/auth/login" in summary
        assert "email, password" in summary

    def test_empty_summary(self):
        site = SiteMap()
        assert "No site structure discovered" in site.summary()
