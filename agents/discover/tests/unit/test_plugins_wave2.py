"""Tests for the 8 wave-2 discovery plugins."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from shared.discovery.sitemap import SiteMap
from discover_agent.learning_store import SessionLearnings
from discover_agent.plugins import DiscoveryContext, DISCOVERY_PLUGINS
from discover_agent.plugins._shared import find_files_by_name, read_source_file
from discover_agent.plugins.env_service_urls import EnvServiceURLsPlugin
from discover_agent.plugins.nextauth_routes import NextAuthRoutesPlugin
from discover_agent.plugins.nextjs_app_router import NextJSAppRouterPlugin
from discover_agent.plugins.nextjs_config import NextJSConfigPlugin
from discover_agent.plugins.nextjs_middleware import NextJSMiddlewarePlugin
from discover_agent.plugins.oidc_wellknown import OIDCWellKnownPlugin
from discover_agent.plugins.raw_http_handlers import RawHTTPHandlersPlugin
from discover_agent.plugins.webhook_receivers import WebhookReceiversPlugin


def _make_ctx(
    staging_url: str = "http://example.com",
    source_path: str = "",
    site: SiteMap | None = None,
    learnings: SessionLearnings | None = None,
) -> DiscoveryContext:
    return DiscoveryContext(
        staging_url=staging_url,
        http_client=AsyncMock(spec=httpx.AsyncClient),
        site=site or SiteMap(),
        learnings=learnings,
        source_path=source_path,
    )


# =====================================================================
# Shared utilities
# =====================================================================


class TestReadSourceFile:
    """Tests for read_source_file() helper."""

    def test_finds_ts_extension(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text("export default {}")
        content = read_source_file(tmp_path, "next.config")
        assert content == "export default {}"

    def test_finds_js_extension(self, tmp_path: Path):
        (tmp_path / "next.config.js").write_text("module.exports = {}")
        content = read_source_file(tmp_path, "next.config")
        assert content == "module.exports = {}"

    def test_finds_mjs_extension(self, tmp_path: Path):
        (tmp_path / "next.config.mjs").write_text("export default {}")
        content = read_source_file(tmp_path, "next.config")
        assert content == "export default {}"

    def test_finds_in_src_dir(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "middleware.ts").write_text("export function middleware() {}")
        content = read_source_file(tmp_path, "middleware")
        assert content is not None
        assert "middleware" in content

    def test_returns_none_when_missing(self, tmp_path: Path):
        content = read_source_file(tmp_path, "nonexistent")
        assert content is None

    def test_finds_exact_name(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("content")
        content = read_source_file(tmp_path, "middleware.ts")
        assert content == "content"

    def test_tries_multiple_names(self, tmp_path: Path):
        (tmp_path / "config.js").write_text("found")
        content = read_source_file(tmp_path, "missing", "config")
        assert content == "found"


class TestFindFilesByName:
    """Tests for find_files_by_name() helper."""

    def test_finds_files(self, tmp_path: Path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "route.ts").write_text("")
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "route.ts").write_text("")
        results = find_files_by_name(tmp_path, "route.ts")
        assert len(results) == 2

    def test_respects_max_results(self, tmp_path: Path):
        for i in range(5):
            d = tmp_path / str(i)
            d.mkdir()
            (d / "route.ts").write_text("")
        results = find_files_by_name(tmp_path, "route.ts", max_results=3)
        assert len(results) == 3

    def test_returns_empty_for_missing(self, tmp_path: Path):
        results = find_files_by_name(tmp_path, "nonexistent.txt")
        assert results == []


# =====================================================================
# Plugin 1: NextJSConfigPlugin
# =====================================================================


class TestNextJSConfigPlugin:
    """Tests for NextJSConfigPlugin."""

    def test_metadata(self):
        p = NextJSConfigPlugin()
        assert p.name == "nextjs_config"
        assert p.priority == 21

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = NextJSConfigPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_rejects_without_config_file(self, tmp_path: Path):
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_config(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text("export default {}")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_extracts_rewrites(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text("""
export default {
  async rewrites() {
    return [
      { source: '/auth', destination: '/api/oidc/auth' },
      { source: '/token', destination: '/api/oidc/token' },
      { source: '/jwks', destination: '/api/oidc/jwks' },
    ]
  }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        result = await p.discover(ctx)
        assert "/auth" in result.endpoints
        assert "/api/oidc/auth" in result.endpoints
        assert "/token" in result.endpoints
        assert "/api/oidc/token" in result.endpoints
        assert "/jwks" in result.endpoints
        assert "Next.js" in result.technologies
        assert "nextjs_rewrites" in result.metadata
        assert len(result.metadata["nextjs_rewrites"]) == 3

    @pytest.mark.asyncio
    async def test_extracts_redirects(self, tmp_path: Path):
        (tmp_path / "next.config.mjs").write_text("""
export default {
  async redirects() {
    return [
      { source: '/old-login', destination: '/login', permanent: true },
    ]
  }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        result = await p.discover(ctx)
        assert "/old-login" in result.endpoints

    @pytest.mark.asyncio
    async def test_normalizes_params(self, tmp_path: Path):
        (tmp_path / "next.config.js").write_text("""
module.exports = {
  async rewrites() {
    return [
      { source: '/.well-known/:path*', destination: '/api/oidc/.well-known/:path*' },
      { source: '/users/:id', destination: '/api/users/:id' },
    ]
  }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        result = await p.discover(ctx)
        assert "/.well-known/{path}" in result.endpoints
        assert "/api/oidc/.well-known/{path}" in result.endpoints
        assert "/users/{id}" in result.endpoints

    @pytest.mark.asyncio
    async def test_deduplicates_endpoints(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text("""
export default {
  async rewrites() {
    return [
      { source: '/api/test', destination: '/api/test' },
    ]
  }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        result = await p.discover(ctx)
        assert result.endpoints.count("/api/test") == 1

    @pytest.mark.asyncio
    async def test_extracts_headers(self, tmp_path: Path):
        (tmp_path / "next.config.ts").write_text("""
export default {
  async headers() {
    return [
      { source: '/api/:path*', headers: [{ key: 'X-Custom', value: 'true' }] },
    ]
  }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSConfigPlugin()
        result = await p.discover(ctx)
        assert "/api/{path}" in result.endpoints


# =====================================================================
# Plugin 2: NextJSAppRouterPlugin
# =====================================================================


class TestNextJSAppRouterPlugin:
    """Tests for NextJSAppRouterPlugin."""

    def test_metadata(self):
        p = NextJSAppRouterPlugin()
        assert p.name == "nextjs_app_router"
        assert p.priority == 21

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = NextJSAppRouterPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_rejects_without_app_dir(self, tmp_path: Path):
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_app_dir(self, tmp_path: Path):
        (tmp_path / "app").mkdir()
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_accepts_with_src_app_dir(self, tmp_path: Path):
        (tmp_path / "src" / "app").mkdir(parents=True)
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_extracts_routes(self, tmp_path: Path):
        route_dir = tmp_path / "app" / "api" / "users"
        route_dir.mkdir(parents=True)
        (route_dir / "route.ts").write_text("""
export async function GET(req: Request) { return Response.json([]); }
export async function POST(req: Request) { return Response.json({}); }
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        result = await p.discover(ctx)
        assert "/api/users" in result.endpoints
        assert "Next.js App Router" in result.technologies
        routes = result.metadata.get("app_router_routes", [])
        assert len(routes) == 1
        assert "GET" in routes[0]["methods"]
        assert "POST" in routes[0]["methods"]

    @pytest.mark.asyncio
    async def test_strips_route_groups(self, tmp_path: Path):
        route_dir = tmp_path / "app" / "(auth)" / "api" / "login"
        route_dir.mkdir(parents=True)
        (route_dir / "route.ts").write_text("export async function POST() {}")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        result = await p.discover(ctx)
        assert "/api/login" in result.endpoints

    @pytest.mark.asyncio
    async def test_converts_dynamic_segments(self, tmp_path: Path):
        route_dir = tmp_path / "app" / "api" / "users" / "[id]"
        route_dir.mkdir(parents=True)
        (route_dir / "route.ts").write_text("export function GET() {}")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        result = await p.discover(ctx)
        assert "/api/users/{id}" in result.endpoints

    @pytest.mark.asyncio
    async def test_skips_slot_segments(self, tmp_path: Path):
        route_dir = tmp_path / "app" / "@modal" / "api" / "data"
        route_dir.mkdir(parents=True)
        (route_dir / "route.ts").write_text("export function GET() {}")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        result = await p.discover(ctx)
        assert "/api/data" in result.endpoints

    @pytest.mark.asyncio
    async def test_handles_const_exports(self, tmp_path: Path):
        route_dir = tmp_path / "app" / "api" / "health"
        route_dir.mkdir(parents=True)
        (route_dir / "route.ts").write_text("""
export const GET = async () => Response.json({ ok: true });
export const DELETE = async () => Response.json({ ok: true });
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        result = await p.discover(ctx)
        routes = result.metadata.get("app_router_routes", [])
        methods = routes[0]["methods"]
        assert "GET" in methods
        assert "DELETE" in methods

    @pytest.mark.asyncio
    async def test_root_route(self, tmp_path: Path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "route.ts").write_text("export function GET() {}")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSAppRouterPlugin()
        result = await p.discover(ctx)
        assert "/" in result.endpoints


# =====================================================================
# Plugin 3: NextAuthRoutesPlugin
# =====================================================================


class TestNextAuthRoutesPlugin:
    """Tests for NextAuthRoutesPlugin."""

    def test_metadata(self):
        p = NextAuthRoutesPlugin()
        assert p.name == "nextauth_routes"
        assert p.priority == 24

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = NextAuthRoutesPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_nextauth_dep(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"next-auth": "^4.0"}}')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_accepts_with_auth_core_dep(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"@auth/core": "^1.0"}}')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_accepts_with_nextauth_file(self, tmp_path: Path):
        api_dir = tmp_path / "pages" / "api" / "auth"
        api_dir.mkdir(parents=True)
        (api_dir / "[...nextauth].ts").write_text("export default NextAuth({})")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_emits_well_known_routes(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"next-auth": "^4.0"}}')
        api_dir = tmp_path / "pages" / "api" / "auth"
        api_dir.mkdir(parents=True)
        (api_dir / "[...nextauth].ts").write_text("""
export default NextAuth({
  providers: [
    GoogleProvider({ clientId: "...", clientSecret: "..." }),
  ]
})
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        result = await p.discover(ctx)
        assert "/api/auth/signin" in result.endpoints
        assert "/api/auth/signout" in result.endpoints
        assert "/api/auth/session" in result.endpoints
        assert "/api/auth/csrf" in result.endpoints
        assert "/api/auth/providers" in result.endpoints
        assert "/api/auth/error" in result.endpoints
        assert "/api/auth/callback/google" in result.endpoints
        assert "NextAuth" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_provider_ids(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"next-auth": "^4.0"}}')
        api_dir = tmp_path / "pages" / "api" / "auth"
        api_dir.mkdir(parents=True)
        (api_dir / "[...nextauth].ts").write_text("""
export default NextAuth({
  providers: [
    { id: "example-oidc", name: "ExampleProvider", type: "oauth" },
    { id: "invite-credentials", name: "Invite", type: "credentials" },
  ]
})
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        result = await p.discover(ctx)
        assert "/api/auth/callback/example-oidc" in result.endpoints
        assert "/api/auth/callback/invite-credentials" in result.endpoints
        providers = result.metadata.get("nextauth_providers", [])
        assert "example-oidc" in providers
        assert "invite-credentials" in providers

    @pytest.mark.asyncio
    async def test_detects_v5(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"@auth/core": "^1.0"}}')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        result = await p.discover(ctx)
        assert result.metadata.get("nextauth_version") == "v5"

    @pytest.mark.asyncio
    async def test_detects_v4(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"next-auth": "^4.24"}}')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        result = await p.discover(ctx)
        assert result.metadata.get("nextauth_version") == "v4"

    @pytest.mark.asyncio
    async def test_custom_base_path(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"next-auth": "^4.0"}}')
        api_dir = tmp_path / "pages" / "api" / "auth"
        api_dir.mkdir(parents=True)
        (api_dir / "[...nextauth].ts").write_text("""
export default NextAuth({
  basePath: "/custom/auth",
  providers: []
})
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        result = await p.discover(ctx)
        assert "/custom/auth/signin" in result.endpoints
        assert "/custom/auth/session" in result.endpoints

    @pytest.mark.asyncio
    async def test_factory_provider_detection(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies": {"next-auth": "^4.0"}}')
        api_dir = tmp_path / "pages" / "api" / "auth"
        api_dir.mkdir(parents=True)
        (api_dir / "[...nextauth].ts").write_text("""
import GitHubProvider from "next-auth/providers/github";
import DiscordProvider from "next-auth/providers/discord";
export default NextAuth({
  providers: [GitHubProvider({}), DiscordProvider({})]
})
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextAuthRoutesPlugin()
        result = await p.discover(ctx)
        assert "/api/auth/callback/github" in result.endpoints
        assert "/api/auth/callback/discord" in result.endpoints


# =====================================================================
# Plugin 4: OIDCWellKnownPlugin
# =====================================================================


class TestOIDCWellKnownPlugin:
    """Tests for OIDCWellKnownPlugin."""

    def test_metadata(self):
        p = OIDCWellKnownPlugin()
        assert p.name == "oidc_wellknown"
        assert p.priority == 25

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = _make_ctx()
        p = OIDCWellKnownPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_extracts_oidc_endpoints(self):
        oidc_doc = {
            "issuer": "http://example.com",
            "authorization_endpoint": "http://example.com/authorize",
            "token_endpoint": "http://example.com/token",
            "userinfo_endpoint": "http://example.com/userinfo",
            "jwks_uri": "http://example.com/.well-known/jwks.json",
        }
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = oidc_doc

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        p = OIDCWellKnownPlugin()
        result = await p.discover(ctx)
        assert "/authorize" in result.endpoints
        assert "/token" in result.endpoints
        assert "/userinfo" in result.endpoints
        assert "/.well-known/jwks.json" in result.endpoints
        assert "OIDC" in result.technologies
        assert "oidc_endpoints" in result.metadata

    @pytest.mark.asyncio
    async def test_handles_404(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 404

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        p = OIDCWellKnownPlugin()
        result = await p.discover(ctx)
        assert result.endpoints == []

    @pytest.mark.asyncio
    async def test_handles_network_error(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(side_effect=httpx.ConnectError("fail"))
        ctx = _make_ctx()
        ctx.http_client = client

        p = OIDCWellKnownPlugin()
        result = await p.discover(ctx)
        assert result.endpoints == []

    @pytest.mark.asyncio
    async def test_handles_invalid_json(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.side_effect = ValueError("bad json")

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        p = OIDCWellKnownPlugin()
        result = await p.discover(ctx)
        assert result.endpoints == []

    @pytest.mark.asyncio
    async def test_adds_full_urls(self):
        oidc_doc = {
            "token_endpoint": "http://example.com/oauth/token",
        }
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = oidc_doc

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        p = OIDCWellKnownPlugin()
        result = await p.discover(ctx)
        assert "http://example.com/oauth/token" in result.urls


# =====================================================================
# Plugin 5: RawHTTPHandlersPlugin
# =====================================================================


class TestRawHTTPHandlersPlugin:
    """Tests for RawHTTPHandlersPlugin."""

    def test_metadata(self):
        p = RawHTTPHandlersPlugin()
        assert p.name == "raw_http_handlers"
        assert p.priority == 21

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = RawHTTPHandlersPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_source_path(self):
        ctx = _make_ctx(source_path="/tmp/src")
        p = RawHTTPHandlersPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_extracts_pathname_equals(self, tmp_path: Path):
        (tmp_path / "server.ts").write_text("""
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/v1/chat/completions") {
    if (req.method === "POST") { handleChat(req, res); }
  }
  if (url.pathname === "/v1/models") {
    handleModels(req, res);
  }
});
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert "/v1/chat/completions" in result.endpoints
        assert "/v1/models" in result.endpoints
        assert "Node.js HTTP" in result.technologies
        routes = result.metadata.get("raw_http_routes", [])
        chat_route = next(r for r in routes if r["path"] == "/v1/chat/completions")
        assert chat_route["method"] == "POST"

    @pytest.mark.asyncio
    async def test_extracts_pathname_startswith(self, tmp_path: Path):
        (tmp_path / "gateway.js").write_text("""
http.createServer((req, res) => {
  if (url.pathname.startsWith("/ui/")) {
    serveUI(req, res);
  }
  if (url.pathname.startsWith("/api/v2/")) {
    handleAPI(req, res);
  }
});
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert "/ui/" in result.endpoints
        assert "/api/v2/" in result.endpoints

    @pytest.mark.asyncio
    async def test_extracts_req_url(self, tmp_path: Path):
        (tmp_path / "handler.js").write_text("""
http.createServer((req, res) => {
  if (req.url === "/health") { res.end("ok"); }
});
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert "/health" in result.endpoints

    @pytest.mark.asyncio
    async def test_detects_deno(self, tmp_path: Path):
        (tmp_path / "main.ts").write_text("""
Deno.serve((req) => {
  const url = new URL(req.url);
  if (url.pathname === "/api/hello") { return new Response("hi"); }
});
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert "/api/hello" in result.endpoints
        assert "Deno" in result.technologies

    @pytest.mark.asyncio
    async def test_detects_bun(self, tmp_path: Path):
        (tmp_path / "index.ts").write_text("""
Bun.serve({
  fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/api/status") return Response.json({ok: true});
  }
});
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert "/api/status" in result.endpoints
        assert "Bun" in result.technologies

    @pytest.mark.asyncio
    async def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('if (url.pathname === "/internal") {}')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert "/internal" not in result.endpoints

    @pytest.mark.asyncio
    async def test_deduplicates(self, tmp_path: Path):
        (tmp_path / "a.ts").write_text('if (url.pathname === "/api") {}')
        (tmp_path / "b.ts").write_text('if (url.pathname === "/api") {}')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert result.endpoints.count("/api") == 1

    @pytest.mark.asyncio
    async def test_empty_project(self, tmp_path: Path):
        ctx = _make_ctx(source_path=str(tmp_path))
        p = RawHTTPHandlersPlugin()
        result = await p.discover(ctx)
        assert result.endpoints == []


# =====================================================================
# Plugin 6: NextJSMiddlewarePlugin
# =====================================================================


class TestNextJSMiddlewarePlugin:
    """Tests for NextJSMiddlewarePlugin."""

    def test_metadata(self):
        p = NextJSMiddlewarePlugin()
        assert p.name == "nextjs_middleware"
        assert p.priority == 21

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = NextJSMiddlewarePlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_rejects_without_middleware(self, tmp_path: Path):
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_middleware(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("export function middleware() {}")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_extracts_matcher_array(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("""
export const config = {
  matcher: ['/dashboard/:path*', '/api/:path*', '/auth/:path*']
};
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        result = await p.discover(ctx)
        assert "/dashboard/{path}" in result.endpoints
        assert "/api/{path}" in result.endpoints
        assert "/auth/{path}" in result.endpoints
        assert "Next.js Middleware" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_matcher_single(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("""
export const config = { matcher: '/protected/:path*' };
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        result = await p.discover(ctx)
        assert "/protected/{path}" in result.endpoints

    @pytest.mark.asyncio
    async def test_extracts_rewrites(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("""
export function middleware(req) {
  if (req.nextUrl.pathname === '/old') {
    return NextResponse.rewrite(new URL('/new', req.url));
  }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        result = await p.discover(ctx)
        assert "/new" in result.endpoints
        assert "middleware_rewrites" in result.metadata

    @pytest.mark.asyncio
    async def test_extracts_redirects(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("""
export function middleware(req) {
  return NextResponse.redirect(new URL('/login', req.url));
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        result = await p.discover(ctx)
        assert "/login" in result.endpoints
        assert "middleware_redirects" in result.metadata

    @pytest.mark.asyncio
    async def test_deduplicates_paths(self, tmp_path: Path):
        (tmp_path / "middleware.ts").write_text("""
export const config = { matcher: ['/api/:path*'] };
export function middleware(req) {
  return NextResponse.rewrite(new URL('/api/:path*', req.url));
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = NextJSMiddlewarePlugin()
        result = await p.discover(ctx)
        assert result.endpoints.count("/api/{path}") == 1


# =====================================================================
# Plugin 7: WebhookReceiversPlugin
# =====================================================================


class TestWebhookReceiversPlugin:
    """Tests for WebhookReceiversPlugin."""

    def test_metadata(self):
        p = WebhookReceiversPlugin()
        assert p.name == "webhook_receivers"
        assert p.priority == 25

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = WebhookReceiversPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_detects_stripe_webhook(self, tmp_path: Path):
        (tmp_path / "webhook.ts").write_text("""
import Stripe from 'stripe';
export async function POST(req) {
  const event = stripe.webhooks.constructEvent(body, sig, secret);
  // handle '/api/webhook/stripe'
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        assert any("Webhook:Stripe" in t for t in result.technologies)
        assert len(result.endpoints) > 0

    @pytest.mark.asyncio
    async def test_detects_github_webhook(self, tmp_path: Path):
        hooks_dir = tmp_path / "api" / "hooks"
        hooks_dir.mkdir(parents=True)
        (hooks_dir / "github.ts").write_text("""
const sig = req.headers['x-hub-signature'];
if (sig) { verifySignature(body, sig); }
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        assert any("Webhook:GitHub" in t for t in result.technologies)

    @pytest.mark.asyncio
    async def test_detects_telegram_webhook(self, tmp_path: Path):
        (tmp_path / "bot-webhook.ts").write_text("""
import { webhookCallback } from 'grammy';
app.post('/api/telegram/webhook', webhookCallback(bot));
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        assert any("Webhook:Telegram" in t for t in result.technologies)

    @pytest.mark.asyncio
    async def test_detects_slack_webhook(self, tmp_path: Path):
        (tmp_path / "slack-callback.ts").write_text("""
if (body.type === 'url_verification') {
  return Response.json({ challenge: body.challenge });
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        assert any("Webhook:Slack" in t for t in result.technologies)

    @pytest.mark.asyncio
    async def test_detects_hmac_webhook(self, tmp_path: Path):
        wh = tmp_path / "webhooks"
        wh.mkdir()
        (wh / "handler.ts").write_text("""
const sig = crypto.createHmac('sha256', secret).update(body).digest('hex');
if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(header))) {
  throw new Error('Invalid signature');
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        assert any("Webhook:HMAC-Webhook" in t for t in result.technologies)

    @pytest.mark.asyncio
    async def test_empty_project(self, tmp_path: Path):
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        assert result.endpoints == []

    @pytest.mark.asyncio
    async def test_webhook_path_extraction(self, tmp_path: Path):
        (tmp_path / "webhook.ts").write_text("""
stripe.webhooks.constructEvent(body, sig, secret);
// route: '/api/webhook/stripe'
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = WebhookReceiversPlugin()
        result = await p.discover(ctx)
        receivers = result.metadata.get("webhook_receivers", [])
        assert len(receivers) > 0
        assert all("platform" in r for r in receivers)


# =====================================================================
# Plugin 8: EnvServiceURLsPlugin
# =====================================================================


class TestEnvServiceURLsPlugin:
    """Tests for EnvServiceURLsPlugin."""

    def test_metadata(self):
        p = EnvServiceURLsPlugin()
        assert p.name == "env_service_urls"
        assert p.priority == 26

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = EnvServiceURLsPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_extracts_oidc_issuer(self, tmp_path: Path):
        (tmp_path / ".env").write_text("OIDC_ISSUER=http://idp.example.com")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert any(".well-known/openid-configuration" in ep for ep in result.endpoints)
        assert "OIDC" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_database_tech(self, tmp_path: Path):
        (tmp_path / ".env").write_text("DATABASE_URL=postgresql://localhost:5432/mydb")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "PostgreSQL" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_redis_tech(self, tmp_path: Path):
        (tmp_path / ".env").write_text("REDIS_URL=redis://localhost:6379")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "Redis" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_vault_tech(self, tmp_path: Path):
        (tmp_path / ".env").write_text("VAULT_ADDR=http://vault.internal:8200")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "HashiCorp Vault" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_nextauth_url(self, tmp_path: Path):
        (tmp_path / ".env").write_text("NEXTAUTH_URL=http://localhost:3000")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "NextAuth" in result.technologies
        assert "http://localhost:3000" in result.urls

    @pytest.mark.asyncio
    async def test_extracts_webhook_url(self, tmp_path: Path):
        (tmp_path / ".env").write_text("STRIPE_WEBHOOK_URL=http://localhost:3000/api/webhook")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "http://localhost:3000/api/webhook" in result.urls

    @pytest.mark.asyncio
    async def test_extracts_service_url(self, tmp_path: Path):
        (tmp_path / ".env").write_text("BACKEND_API_URL=http://api.internal:8080/v2")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "http://api.internal:8080/v2" in result.urls

    @pytest.mark.asyncio
    async def test_skips_existing_urls(self, tmp_path: Path):
        (tmp_path / ".env").write_text("NEXTAUTH_URL=http://localhost:3000")
        site = SiteMap(urls=["http://localhost:3000"])
        ctx = _make_ctx(source_path=str(tmp_path), site=site)
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        # Should not duplicate
        assert result.urls.count("http://localhost:3000") == 0

    @pytest.mark.asyncio
    async def test_parses_env_example(self, tmp_path: Path):
        (tmp_path / ".env.example").write_text("DATABASE_URL=postgresql://localhost:5432/mydb")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "PostgreSQL" in result.technologies

    @pytest.mark.asyncio
    async def test_parses_yaml_env(self, tmp_path: Path):
        (tmp_path / "env.yaml").write_text("""
DATABASE_URL: postgresql://localhost:5432/mydb
REDIS_URL: redis://localhost:6379
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "PostgreSQL" in result.technologies
        assert "Redis" in result.technologies

    @pytest.mark.asyncio
    async def test_handles_quoted_values(self, tmp_path: Path):
        (tmp_path / ".env").write_text("""VAULT_ADDR="http://vault.example.com:8200"\n""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert "HashiCorp Vault" in result.technologies

    @pytest.mark.asyncio
    async def test_empty_env(self, tmp_path: Path):
        (tmp_path / ".env").write_text("# just a comment\n")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        assert result.endpoints == []
        assert result.urls == []

    @pytest.mark.asyncio
    async def test_env_map_metadata(self, tmp_path: Path):
        (tmp_path / ".env").write_text("""
DATABASE_URL=postgresql://localhost:5432/mydb
REDIS_URL=redis://localhost:6379
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = EnvServiceURLsPlugin()
        result = await p.discover(ctx)
        env_map = result.metadata.get("env_service_urls", {})
        assert "DATABASE_URL" in env_map
        assert "REDIS_URL" in env_map


# =====================================================================
# Plugin ordering — verify 22 total plugins
# =====================================================================


class TestWave2PluginOrdering:
    """Verify all 22 plugins are registered in correct priority order."""

    def test_all_22_plugins_registered(self):
        names = [p.name for p in DISCOVERY_PLUGINS]
        assert len(names) >= 22
        for expected in [
            # Wave 1
            "crawl", "source_code", "infra_config", "mobile_routes",
            "openapi", "soap_wsdl", "graphql", "websocket", "sse",
            "rpc", "grpc_reflection", "blockchain_rpc", "mqtt_amqp",
            "js_bundle",
            # Wave 2
            "nextjs_config", "nextjs_app_router", "raw_http_handlers",
            "nextjs_middleware", "nextauth_routes", "oidc_wellknown",
            "webhook_receivers", "env_service_urls",
        ]:
            assert expected in names, f"Plugin '{expected}' not registered"

    def test_priority_order(self):
        priorities = [p.priority for p in DISCOVERY_PLUGINS]
        assert priorities == sorted(priorities)

    def test_crawl_still_first(self):
        assert DISCOVERY_PLUGINS[0].name == "crawl"
        assert DISCOVERY_PLUGINS[0].priority == 10

    def test_endpoint_validation_runs_last(self):
        assert DISCOVERY_PLUGINS[-1].name == "endpoint_validation"
        assert DISCOVERY_PLUGINS[-1].priority == 90

    def test_wave2_priorities(self):
        """Wave 2 plugins have correct relative priorities."""
        name_to_pri = {p.name: p.priority for p in DISCOVERY_PLUGINS}
        assert name_to_pri["nextjs_config"] == 21
        assert name_to_pri["nextjs_app_router"] == 21
        assert name_to_pri["raw_http_handlers"] == 21
        assert name_to_pri["nextjs_middleware"] == 21
        assert name_to_pri["nextauth_routes"] == 24
        assert name_to_pri["oidc_wellknown"] == 25
        assert name_to_pri["webhook_receivers"] == 25
        assert name_to_pri["env_service_urls"] == 26
