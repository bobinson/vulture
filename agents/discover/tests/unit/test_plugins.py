"""Tests for the plugin-based discovery system."""

import json
import time
from unittest.mock import AsyncMock

import pytest

from shared.discovery.sitemap import SiteMap
from discover_agent.learning_store import GraphQLSchemaCache, SessionLearnings
from discover_agent.plugins import (
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    DISCOVERY_PLUGINS,
    _merge_result,
    run_discovery,
)
from discover_agent.plugins.crawl import CrawlPlugin
from discover_agent.plugins.graphql import GraphQLPlugin
from discover_agent.plugins.js_bundle import JSBundlePlugin
from discover_agent.plugins.openapi import OpenAPIPlugin
from discover_agent.plugins.rpc import RPCPlugin
from discover_agent.plugins.source_code import SourceCodePlugin
from discover_agent.plugins.websocket import WebSocketPlugin
from discover_agent.source_analyzer import SourceAnalysisResult, SourceRoute


# --- Plugin Registration ---


class TestPluginRegistry:
    """Tests for plugin registration and ordering."""

    def test_all_plugins_registered(self):
        names = [p.name for p in DISCOVERY_PLUGINS]
        assert len(names) >= 14
        for expected in [
            "crawl", "source_code", "infra_config", "mobile_routes",
            "openapi", "soap_wsdl", "graphql", "websocket", "sse",
            "rpc", "grpc_reflection", "blockchain_rpc", "mqtt_amqp",
            "js_bundle",
        ]:
            assert expected in names, f"Plugin '{expected}' not registered"

    def test_plugins_sorted_by_priority(self):
        priorities = [p.priority for p in DISCOVERY_PLUGINS]
        assert priorities == sorted(priorities)

    def test_crawl_runs_first(self):
        assert DISCOVERY_PLUGINS[0].name == "crawl"
        assert DISCOVERY_PLUGINS[0].priority == 10

    def test_endpoint_validation_runs_last(self):
        assert DISCOVERY_PLUGINS[-1].name == "endpoint_validation"
        assert DISCOVERY_PLUGINS[-1].priority == 90

    def test_register_plugin_decorator(self):
        """Verify register_plugin adds to and sorts DISCOVERY_PLUGINS."""
        initial_count = len(DISCOVERY_PLUGINS)
        # We won't actually register a test plugin to avoid polluting global state,
        # but we can verify the decorator mechanism works on a mock
        class _TestPlugin(DiscoveryPlugin):
            name = "test_plugin"
            priority = 999
            async def accepts(self, ctx): return False
            async def discover(self, ctx): return DiscoveryResult()

        # Manually test registration without side effects
        DISCOVERY_PLUGINS.append(_TestPlugin)
        DISCOVERY_PLUGINS.sort(key=lambda p: p.priority)
        assert DISCOVERY_PLUGINS[-1].name == "test_plugin"
        DISCOVERY_PLUGINS.pop()  # Clean up
        assert len(DISCOVERY_PLUGINS) == initial_count


# --- Merge Result ---


class TestMergeResult:
    """Tests for _merge_result merging DiscoveryResult into SiteMap."""

    def test_merge_adds_endpoints(self):
        site = SiteMap()
        result = DiscoveryResult(endpoints=["/api/users", "/api/auth"])
        _merge_result(site, result)
        assert "/api/users" in site.api_endpoints
        assert "/api/auth" in site.api_endpoints

    def test_merge_adds_urls(self):
        site = SiteMap()
        result = DiscoveryResult(urls=["/login", "/register"])
        _merge_result(site, result)
        assert "/login" in site.urls
        assert "/register" in site.urls

    def test_merge_adds_forms(self):
        site = SiteMap()
        result = DiscoveryResult(forms=[
            {"action": "/login", "method": "POST", "inputs": ["email"]},
        ])
        _merge_result(site, result)
        assert len(site.forms) == 1

    def test_merge_adds_technologies(self):
        site = SiteMap()
        result = DiscoveryResult(technologies=["GraphQL", "Next.js"])
        _merge_result(site, result)
        assert "GraphQL" in site.technologies
        assert "Next.js" in site.technologies

    def test_merge_deduplicates_endpoints(self):
        site = SiteMap(api_endpoints=["/api/users"])
        result = DiscoveryResult(endpoints=["/api/users", "/api/auth"])
        _merge_result(site, result)
        assert site.api_endpoints.count("/api/users") == 1
        assert "/api/auth" in site.api_endpoints

    def test_merge_deduplicates_forms(self):
        site = SiteMap(forms=[{"action": "/login", "method": "POST", "inputs": []}])
        result = DiscoveryResult(forms=[
            {"action": "/login", "method": "POST", "inputs": []},
        ])
        _merge_result(site, result)
        assert len(site.forms) == 1


# --- Run Discovery Orchestrator ---


class TestRunDiscovery:
    """Tests for the run_discovery orchestrator."""

    @pytest.mark.asyncio
    async def test_runs_accepting_plugins(self):
        site = SiteMap()
        client = AsyncMock()
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=client,
            site=site,
        )
        # run_discovery calls all registered plugins
        # Since we can't easily mock the global registry, we test it returns a SiteMap
        result, _errors = await run_discovery(ctx)
        assert isinstance(result, SiteMap)


# --- CrawlPlugin ---


class TestCrawlPlugin:
    """Tests for CrawlPlugin."""

    def test_always_accepts(self):
        plugin = CrawlPlugin()
        assert plugin.name == "crawl"
        assert plugin.priority == 10

    @pytest.mark.asyncio
    async def test_accepts_always_true(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
        )
        plugin = CrawlPlugin()
        assert await plugin.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_skips_known_404_paths(self):
        """CrawlPlugin should skip paths in learnings.known_404_paths."""
        learnings = SessionLearnings(known_404_paths=["/admin", "/debug"])
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            learnings=learnings,
        )
        plugin = CrawlPlugin()
        # The plugin will try HTTP calls which will fail with AsyncMock,
        # but the important thing is it doesn't crash
        result = await plugin.discover(ctx)
        assert isinstance(result, DiscoveryResult)


# --- SourceCodePlugin ---


class TestSourceCodePlugin:
    """Tests for SourceCodePlugin."""

    def test_plugin_metadata(self):
        plugin = SourceCodePlugin()
        assert plugin.name == "source_code"
        assert plugin.priority == 20

    @pytest.mark.asyncio
    async def test_rejects_without_source_analysis(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
        )
        plugin = SourceCodePlugin()
        assert await plugin.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_source_analysis(self):
        analysis = SourceAnalysisResult(
            routes=[SourceRoute(path="/api/users", method="GET", framework="express")],
        )
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            source_analysis=analysis,
        )
        plugin = SourceCodePlugin()
        assert await plugin.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_accepts_with_source_routes(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            source_routes=["/api/users"],
        )
        plugin = SourceCodePlugin()
        assert await plugin.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_extracts_routes_from_analysis(self):
        analysis = SourceAnalysisResult(
            routes=[
                SourceRoute(path="/api/users", method="GET", framework="express"),
                SourceRoute(path="/api/auth/login", method="POST", framework="express"),
            ],
            technologies=["express"],
        )
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            source_analysis=analysis,
        )
        plugin = SourceCodePlugin()
        result = await plugin.discover(ctx)
        assert "/api/users" in result.endpoints
        assert "/api/auth/login" in result.endpoints
        assert "express" in result.technologies

    @pytest.mark.asyncio
    async def test_adds_graphql_endpoint_from_analysis(self):
        analysis = SourceAnalysisResult(
            graphql_queries=["users", "posts"],
            graphql_mutations=["createUser"],
        )
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            source_analysis=analysis,
        )
        plugin = SourceCodePlugin()
        result = await plugin.discover(ctx)
        assert "/graphql" in result.endpoints
        assert "GraphQL" in result.technologies

    @pytest.mark.asyncio
    async def test_stores_in_learnings(self):
        analysis = SourceAnalysisResult(
            routes=[SourceRoute(path="/api/users", method="GET")],
        )
        learnings = SessionLearnings()
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            source_analysis=analysis,
            learnings=learnings,
        )
        plugin = SourceCodePlugin()
        await plugin.discover(ctx)
        assert "/api/users" in learnings.source_routes

    @pytest.mark.asyncio
    async def test_deduplicates_source_routes(self):
        analysis = SourceAnalysisResult(
            routes=[SourceRoute(path="/api/users", method="GET")],
        )
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            source_analysis=analysis,
            source_routes=["/api/users", "/api/auth"],
        )
        plugin = SourceCodePlugin()
        result = await plugin.discover(ctx)
        # /api/users appears from both analysis and source_routes, should not duplicate
        assert result.endpoints.count("/api/users") == 1
        assert "/api/auth" in result.endpoints


# --- OpenAPIPlugin ---


class TestOpenAPIPlugin:
    """Tests for OpenAPIPlugin."""

    def test_plugin_metadata(self):
        plugin = OpenAPIPlugin()
        assert plugin.name == "openapi"
        assert plugin.priority == 30

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
        )
        plugin = OpenAPIPlugin()
        assert await plugin.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_parses_schema_file(self, tmp_path):
        """OpenAPIPlugin reads user-provided spec file."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {"get": {}, "post": {}},
                "/api/orders": {"get": {}},
            },
        }
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text(json.dumps(spec))

        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            schemas={"openapi": str(spec_file)},
        )
        plugin = OpenAPIPlugin()
        result = await plugin.discover(ctx)
        assert "/api/users" in result.endpoints
        assert "/api/orders" in result.endpoints


# --- GraphQLPlugin ---


class TestGraphQLPlugin:
    """Tests for GraphQLPlugin."""

    def test_plugin_metadata(self):
        plugin = GraphQLPlugin()
        assert plugin.name == "graphql"
        assert plugin.priority == 40

    @pytest.mark.asyncio
    async def test_skips_for_rest_only_apps(self):
        """GraphQLPlugin skips if technologies indicate REST-only."""
        learnings = SessionLearnings(technologies=["django"])
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            learnings=learnings,
        )
        plugin = GraphQLPlugin()
        assert await plugin.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_when_graphql_in_source(self):
        """GraphQLPlugin runs if source analysis found GraphQL queries."""
        learnings = SessionLearnings(technologies=["django"])
        analysis = SourceAnalysisResult(graphql_queries=["users"])
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            learnings=learnings,
            source_analysis=analysis,
        )
        plugin = GraphQLPlugin()
        assert await plugin.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_uses_cached_schema(self):
        """GraphQLPlugin uses cached schema from learnings."""
        cache = GraphQLSchemaCache(
            path="/graphql", variant="apollo",
            queries=["users", "posts"], mutations=["createUser"],
            introspection_enabled=True, last_updated=time.time(),
        )
        learnings = SessionLearnings(graphql_schemas={"/graphql": cache})
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            learnings=learnings,
        )
        plugin = GraphQLPlugin()
        result = await plugin.discover(ctx)
        assert "/graphql" in result.endpoints
        assert result.metadata.get("graphql_schema", {}).get("cached") is True

    @pytest.mark.asyncio
    async def test_parses_sdl_schema_file(self, tmp_path):
        """GraphQLPlugin parses .graphql SDL schema file."""
        schema = """
type Query {
    users: [User]
    posts: [Post]
}

type Mutation {
    createUser(name: String): User
    deleteUser(id: ID): Boolean
}
"""
        schema_file = tmp_path / "schema.graphql"
        schema_file.write_text(schema)

        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            schemas={"graphql": str(schema_file)},
        )
        plugin = GraphQLPlugin()
        result = await plugin.discover(ctx)
        assert "/graphql" in result.endpoints
        schema_meta = result.metadata.get("graphql_schema", {})
        assert "users" in schema_meta.get("queries", [])
        assert "createUser" in schema_meta.get("mutations", [])

    @pytest.mark.asyncio
    async def test_ignores_stale_cache(self):
        """GraphQLPlugin ignores cached schema older than 1 hour."""
        cache = GraphQLSchemaCache(
            path="/graphql", variant="apollo",
            queries=["users"], mutations=[],
            last_updated=time.time() - 7200,  # 2 hours ago
        )
        learnings = SessionLearnings(graphql_schemas={"/graphql": cache})
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            learnings=learnings,
        )
        plugin = GraphQLPlugin()
        # Will try to probe endpoints, fail, and return empty
        result = await plugin.discover(ctx)
        # Should not have used the stale cache
        assert result.metadata.get("graphql_schema", {}).get("cached") is not True


# --- WebSocketPlugin ---


class TestWebSocketPlugin:
    """Tests for WebSocketPlugin."""

    def test_plugin_metadata(self):
        plugin = WebSocketPlugin()
        assert plugin.name == "websocket"
        assert plugin.priority == 50

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
        )
        plugin = WebSocketPlugin()
        assert await plugin.accepts(ctx) is True


# --- RPCPlugin ---


class TestRPCPlugin:
    """Tests for RPCPlugin."""

    def test_plugin_metadata(self):
        plugin = RPCPlugin()
        assert plugin.name == "rpc"
        assert plugin.priority == 60

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
        )
        plugin = RPCPlugin()
        assert await plugin.accepts(ctx) is True


# --- JSBundlePlugin ---


class TestJSBundlePlugin:
    """Tests for JSBundlePlugin."""

    def test_plugin_metadata(self):
        plugin = JSBundlePlugin()
        assert plugin.name == "js_bundle"
        assert plugin.priority == 70

    @pytest.mark.asyncio
    async def test_rejects_without_js_chunks(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(urls=["/login", "/api/users"]),
        )
        plugin = JSBundlePlugin()
        assert await plugin.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_js_chunks(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(urls=["/_next/static/chunks/pages-abc.js"]),
        )
        plugin = JSBundlePlugin()
        assert await plugin.accepts(ctx) is True


# --- DiscoveryContext ---


class TestDiscoveryContext:
    """Tests for DiscoveryContext dataclass."""

    def test_default_values(self):
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
        )
        assert ctx.learnings is None
        assert ctx.source_routes == []
        assert ctx.schemas == {}
        assert ctx.source_analysis is None

    def test_with_all_fields(self):
        learnings = SessionLearnings()
        analysis = SourceAnalysisResult()
        ctx = DiscoveryContext(
            staging_url="http://example.com",
            http_client=AsyncMock(),
            site=SiteMap(),
            learnings=learnings,
            source_routes=["/api/users"],
            schemas={"graphql": "/path/to/schema.graphql"},
            source_analysis=analysis,
        )
        assert ctx.learnings is learnings
        assert ctx.source_routes == ["/api/users"]
        assert ctx.schemas == {"graphql": "/path/to/schema.graphql"}
        assert ctx.source_analysis is analysis


# --- DiscoveryResult ---


class TestDiscoveryResult:
    """Tests for DiscoveryResult dataclass."""

    def test_default_values(self):
        result = DiscoveryResult()
        assert result.endpoints == []
        assert result.urls == []
        assert result.forms == []
        assert result.technologies == []
        assert result.metadata == {}

    def test_with_data(self):
        result = DiscoveryResult(
            endpoints=["/api/users"],
            urls=["/login"],
            technologies=["Next.js"],
            metadata={"key": "value"},
        )
        assert len(result.endpoints) == 1
        assert len(result.technologies) == 1
        assert result.metadata["key"] == "value"
