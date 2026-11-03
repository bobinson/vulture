"""E2E: discover's source plugins read only what the audit walk reads.

Every plugin that looks at the source tree used to walk it with its own
``rglob`` / ``os.walk``, each with its own idea of what to skip -- or none at
all. A vendored package under ``node_modules``, a build output, a gitignored
generated tree, a ``.vultureignore``d recording and a symlink out of the tree
all contributed endpoints, URLs and services to the attack-surface map as if
the project served them. One plugin tested ABSOLUTE path parts against its own
skip list, so a checkout that merely sat under a directory named ``build``
contributed nothing at all.

Each plugin is driven through its real ``discover`` entry point over one tree
holding a tracked copy and several excluded copies of the same evidence, each
excluded copy carrying a marker that must never surface. The network is the
only thing stubbed: no HTTP request succeeds and no port is open.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from shared.discovery.plugin_base import DiscoveryContext
from shared.discovery.sitemap import SiteMap

TRACKED = "tracked"
# Where an excluded copy lives -> the marker its content carries.
EXCLUDED = {
    "node_modules/pkg": "vendored",
    "dist": "builtout",
    "generated": "gitignored",
    "recorded": "vultureignored",
    "linked": "symlinked",
}


def _evidence(marker: str) -> dict[str, str]:
    """One file per source plugin, every extracted value naming ``marker``."""
    return {
        f"src/{marker}_server.js": (
            "http.createServer((req, res) => {\n"
            f'  if (url.pathname === "/raw/{marker}") {{ res.end(); }}\n'
            "});\n"
        ),
        f"src/webhook_{marker}.ts": (
            "stripe.webhooks.constructEvent(body, sig, secret);\n"
            f"// route: '/api/webhook/{marker}'\n"
        ),
        f"android/{marker.capitalize()}Api.kt": (
            "interface Api {\n"
            f'    @GET("mobile/{marker}")\n'
            "    fun list(): Call<List<Item>>\n"
            "}\n"
        ),
        "deploy/docker-compose.yml": (
            "services:\n"
            "  backend:\n"
            "    environment:\n"
            f"      API_URL: http://{marker}.internal:3000\n"
        ),
        f"protos/{marker}.proto": (
            'syntax = "proto3";\n'
            f"service {marker.capitalize()}Service {{\n"
            "    rpc GetItem (GetItemRequest) returns (Item);\n"
            "}\n"
        ),
        f"config/{marker}_broker.yaml": f"broker_url: amqp://{marker}-broker:5672/\n",
        f"src/{marker}_events.js": f'const es = new EventSource("/sse/{marker}");\n',
        f"wsdl/{marker}.wsdl": (
            "<definitions>\n"
            f'  <service name="{marker}"><port>'
            f'<address location="http://{marker}.example.com/soap"/></port></service>\n'
            "</definitions>\n"
        ),
    }


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _tree(tmp_path: Path) -> Path:
    """The scan root sits under a parent directory named ``build``: the walk
    judges the tree below the root, never the directories above it."""
    root = tmp_path / "build" / "checkout"
    _write(root, _evidence(TRACKED))
    for where, marker in EXCLUDED.items():
        if where != "linked":
            _write(root / where, _evidence(marker))
    outside = tmp_path / "outside"
    _write(outside, _evidence(EXCLUDED["linked"]))
    (root / "linked").symlink_to(outside, target_is_directory=True)
    _write(root, {
        ".gitignore": "generated/\n.env\n",
        ".vultureignore": "recorded/\n",
        ".env": "GITIGNORED_API_URL=https://gitignored.example.com\n",
        ".env.example": "TRACKED_API_URL=https://tracked.example.com\n",
    })
    return root


def _ctx(root: Path) -> DiscoveryContext:
    client = AsyncMock(spec=httpx.AsyncClient)
    client.request = AsyncMock(side_effect=httpx.ConnectError("no network"))
    return DiscoveryContext(
        staging_url="http://127.0.0.1:9", http_client=client, site=SiteMap(),
        source_path=str(root),
    )


def _discover(plugin_cls, root: Path) -> str:
    """One plugin's whole result, serialised, with every port closed. Callers
    compare markers case-insensitively: a proto service is ``TrackedService``."""
    closed = AsyncMock(return_value=False)
    with patch("discover_agent.plugins.grpc_reflection.probe_port", closed), \
            patch("discover_agent.plugins.mqtt_amqp.probe_port", closed):
        result = asyncio.run(plugin_cls().discover(_ctx(root)))
    return json.dumps({
        "endpoints": result.endpoints, "urls": result.urls,
        "technologies": result.technologies, "metadata": result.metadata,
    })


def _source_plugins() -> dict[str, type]:
    from discover_agent.plugins.env_service_urls import EnvServiceURLsPlugin
    from discover_agent.plugins.grpc_reflection import GRPCReflectionPlugin
    from discover_agent.plugins.infra_config import InfraConfigPlugin
    from discover_agent.plugins.mobile_routes import MobileRoutesPlugin
    from discover_agent.plugins.mqtt_amqp import MQTTAMQPPlugin
    from discover_agent.plugins.raw_http_handlers import RawHTTPHandlersPlugin
    from discover_agent.plugins.soap_wsdl import SOAPWSDLPlugin
    from discover_agent.plugins.sse import SSEPlugin
    from discover_agent.plugins.webhook_receivers import WebhookReceiversPlugin

    return {
        "raw_http_handlers": RawHTTPHandlersPlugin,
        "webhook_receivers": WebhookReceiversPlugin,
        "mobile_routes": MobileRoutesPlugin,
        "infra_config": InfraConfigPlugin,
        "grpc_reflection": GRPCReflectionPlugin,
        "mqtt_amqp": MQTTAMQPPlugin,
        "sse": SSEPlugin,
        "soap_wsdl": SOAPWSDLPlugin,
        "env_service_urls": EnvServiceURLsPlugin,
    }


@pytest.fixture(autouse=True)
def _fresh_walk():
    from shared.tools.file_scanner import clear_caches

    clear_caches()
    yield
    clear_caches()


@pytest.mark.parametrize("name", sorted(_source_plugins()))
def test_a_plugin_reports_the_tracked_copy_and_no_excluded_one(tmp_path, name) -> None:
    out = _discover(_source_plugins()[name], _tree(tmp_path)).lower()
    assert TRACKED in out, f"{name} must still find the tracked evidence: {out}"
    leaked = [marker for marker in EXCLUDED.values() if marker in out]
    assert not leaked, f"{name} reported excluded copies {leaked}: {out}"


def test_infra_config_does_not_read_a_gitignored_env_file(tmp_path) -> None:
    from discover_agent.plugins.infra_config import InfraConfigPlugin

    out = _discover(InfraConfigPlugin, _tree(tmp_path))
    assert "gitignored.example.com" not in out


def _next_app(root: Path, marker: str) -> None:
    _write(root, {f"app/api/{marker}/route.ts": "export async function GET() {}\n"})


def test_next_app_router_skips_a_route_under_an_ignored_directory(tmp_path) -> None:
    from discover_agent.plugins.nextjs_app_router import NextJSAppRouterPlugin

    root = tmp_path / "build" / "web"
    _next_app(root, TRACKED)
    _next_app(root, "gitignored")
    _write(root, {".gitignore": "app/api/gitignored/\n"})
    out = _discover(NextJSAppRouterPlugin, root)
    assert f"/api/{TRACKED}" in out
    assert "gitignored" not in out


def test_next_app_router_reads_a_route_segment_named_with_an_ordinary_word(tmp_path) -> None:
    """`data`, `bin`, `env` and `mocks` are words a project names its
    own code with, so a route segment so named is discovered."""
    from discover_agent.plugins.nextjs_app_router import NextJSAppRouterPlugin

    root = tmp_path / "web"
    for segment in ("data", "bin", "env", "mocks"):
        _next_app(root, segment)
    out = _discover(NextJSAppRouterPlugin, root)
    for segment in ("data", "bin", "env", "mocks"):
        assert f"/api/{segment}" in out, out


def test_nextauth_reads_the_projects_catch_all_not_a_vendored_one(tmp_path) -> None:
    from discover_agent.plugins.nextauth_routes import NextAuthRoutesPlugin

    root = tmp_path / "web"
    _write(root, {
        "package.json": '{"dependencies": {"next-auth": "^4.24"}}',
        "pages/api/auth/[...nextauth].ts": "export default NextAuth({ basePath: '/api/tracked-auth' })\n",
        "node_modules/next-auth/[...nextauth].ts": "NextAuth({ basePath: '/api/vendored-auth' })\n",
    })
    out = _discover(NextAuthRoutesPlugin, root)
    assert "/api/tracked-auth" in out
    assert "vendored" not in out


def test_the_cap_stops_the_walk(tmp_path) -> None:
    """A plugin that reaches its file cap stops; it does not keep walking."""
    from discover_agent.plugins import mobile_routes

    root = tmp_path / "app"
    _write(root, {f"src/a{i:03d}.kt": f'@GET("item/{i}")\n' for i in range(5)})
    with patch.object(mobile_routes, "_MAX_MOBILE_FILES", 2):
        out = json.loads(_discover(mobile_routes.MobileRoutesPlugin, root))
    assert len(out["endpoints"]) == 2
