"""Tests for the 7 new discovery plugins."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from shared.discovery.sitemap import SiteMap
from discover_agent.learning_store import SessionLearnings
from discover_agent.plugins import DiscoveryContext
from discover_agent.plugins.blockchain_rpc import BlockchainRPCPlugin
from discover_agent.plugins.grpc_reflection import GRPCReflectionPlugin
from discover_agent.plugins.infra_config import InfraConfigPlugin
from discover_agent.plugins.mobile_routes import MobileRoutesPlugin
from discover_agent.plugins.mqtt_amqp import MQTTAMQPPlugin
from discover_agent.plugins.soap_wsdl import SOAPWSDLPlugin
from discover_agent.plugins.sse import SSEPlugin


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


# --- InfraConfigPlugin ---


class TestInfraConfigPlugin:
    """Tests for InfraConfigPlugin."""

    def test_metadata(self):
        p = InfraConfigPlugin()
        assert p.name == "infra_config"
        assert p.priority == 22

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = InfraConfigPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_source_path(self):
        ctx = _make_ctx(source_path="/tmp/src")
        p = InfraConfigPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_parses_docker_compose(self, tmp_path: Path):
        dc = tmp_path / "docker-compose.yml"
        dc.write_text("""
services:
  backend:
    ports:
      - "8080:8080"
    environment:
      API_URL: http://api.internal:3000
  frontend:
    ports:
      - "3000:80"
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = InfraConfigPlugin()
        result = await p.discover(ctx)
        assert any("docker:backend" in t for t in result.technologies)
        assert any("http://api.internal:3000" in u for u in result.urls)

    @pytest.mark.asyncio
    async def test_parses_nginx_config(self, tmp_path: Path):
        conf = tmp_path / "nginx.conf"
        conf.write_text("""
server {
    location /api {
        proxy_pass http://backend:8080;
    }
    location /ws {
        proxy_pass http://backend:8080;
    }
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = InfraConfigPlugin()
        result = await p.discover(ctx)
        assert "/api" in result.endpoints
        assert "/ws" in result.endpoints
        assert "Nginx" in result.technologies

    @pytest.mark.asyncio
    async def test_parses_env_file(self, tmp_path: Path):
        env = tmp_path / ".env"
        env.write_text("DATABASE_URL=postgresql://localhost:5432\nAPI_URL=http://localhost:8080/api")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = InfraConfigPlugin()
        result = await p.discover(ctx)
        assert any("http://localhost:8080/api" in u for u in result.urls)

    @pytest.mark.asyncio
    async def test_parses_kubernetes_ingress(self, tmp_path: Path):
        k8s = tmp_path / "ingress.yaml"
        k8s.write_text("""
kind: Ingress
spec:
  rules:
    - http:
        paths:
          - path: /api/v1
            backend:
              service:
                name: api
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = InfraConfigPlugin()
        result = await p.discover(ctx)
        assert "/api/v1" in result.endpoints
        assert "Kubernetes" in result.technologies


# --- MobileRoutesPlugin ---


class TestMobileRoutesPlugin:
    """Tests for MobileRoutesPlugin."""

    def test_metadata(self):
        p = MobileRoutesPlugin()
        assert p.name == "mobile_routes"
        assert p.priority == 23

    @pytest.mark.asyncio
    async def test_rejects_without_source_path(self):
        ctx = _make_ctx()
        p = MobileRoutesPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_extracts_retrofit(self, tmp_path: Path):
        java = tmp_path / "ApiService.java"
        java.write_text("""
@GET("/api/users")
Call<List<User>> getUsers();

@POST("/api/users")
Call<User> createUser(@Body User user);
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = MobileRoutesPlugin()
        result = await p.discover(ctx)
        assert "/api/users" in result.endpoints
        assert "Retrofit" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_alamofire(self, tmp_path: Path):
        swift = tmp_path / "API.swift"
        swift.write_text('AF.request("https://api.example.com/users")')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = MobileRoutesPlugin()
        result = await p.discover(ctx)
        assert "https://api.example.com/users" in result.urls
        assert "Alamofire" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_dart_http(self, tmp_path: Path):
        dart = tmp_path / "api.dart"
        dart.write_text('http.get("https://api.example.com/items")')
        ctx = _make_ctx(source_path=str(tmp_path))
        p = MobileRoutesPlugin()
        result = await p.discover(ctx)
        assert "https://api.example.com/items" in result.urls
        assert "Flutter" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_android_deeplinks(self, tmp_path: Path):
        manifest = tmp_path / "AndroidManifest.xml"
        manifest.write_text("""
<intent-filter>
    <data android:scheme="https" android:host="app.example.com"/>
</intent-filter>
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = MobileRoutesPlugin()
        result = await p.discover(ctx)
        assert "https://app.example.com" in result.urls


# --- SOAPWSDLPlugin ---


class TestSOAPWSDLPlugin:
    """Tests for SOAPWSDLPlugin."""

    def test_metadata(self):
        p = SOAPWSDLPlugin()
        assert p.name == "soap_wsdl"
        assert p.priority == 35

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = _make_ctx()
        p = SOAPWSDLPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_detects_wsdl_response(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {"content-type": "text/xml"}
        resp.text = '<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"></wsdl:definitions>'

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        p = SOAPWSDLPlugin()
        result = await p.discover(ctx)
        assert "SOAP/WSDL" in result.technologies

    @pytest.mark.asyncio
    async def test_scans_wsdl_files(self, tmp_path: Path):
        wsdl = tmp_path / "service.wsdl"
        wsdl.write_text("""
<definitions>
  <service name="UserService">
    <port>
      <address location="http://api.example.com/soap/users"/>
    </port>
  </service>
  <portType>
    <operation name="getUser"/>
    <operation name="createUser"/>
  </portType>
</definitions>
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        ctx.http_client.request = AsyncMock(side_effect=Exception("no network"))

        p = SOAPWSDLPlugin()
        result = await p.discover(ctx)
        assert "SOAP/WSDL" in result.technologies
        assert "http://api.example.com/soap/users" in result.urls


# --- SSEPlugin ---


class TestSSEPlugin:
    """Tests for SSEPlugin."""

    def test_metadata(self):
        p = SSEPlugin()
        assert p.name == "sse"
        assert p.priority == 55

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = _make_ctx()
        p = SSEPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_detects_sse_response(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {"content-type": "text/event-stream"}
        resp.text = "data: hello\n\n"

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        p = SSEPlugin()
        result = await p.discover(ctx)
        assert "SSE" in result.technologies
        assert any(ep in result.endpoints for ep in ["/events", "/stream", "/sse"])

    @pytest.mark.asyncio
    async def test_scans_source_for_eventsource(self, tmp_path: Path):
        js = tmp_path / "app.js"
        js.write_text('const es = new EventSource("/api/notifications");')
        ctx = _make_ctx(source_path=str(tmp_path))
        ctx.http_client.request = AsyncMock(side_effect=Exception("no network"))

        p = SSEPlugin()
        result = await p.discover(ctx)
        assert "SSE" in result.technologies
        assert "/api/notifications" in result.endpoints


# --- GRPCReflectionPlugin ---


class TestGRPCReflectionPlugin:
    """Tests for GRPCReflectionPlugin."""

    def test_metadata(self):
        p = GRPCReflectionPlugin()
        assert p.name == "grpc_reflection"
        assert p.priority == 62

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = _make_ctx()
        p = GRPCReflectionPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_scans_proto_files(self, tmp_path: Path):
        proto = tmp_path / "service.proto"
        proto.write_text("""
syntax = "proto3";
service UserService {
    rpc GetUser (GetUserRequest) returns (User);
    rpc ListUsers (ListUsersRequest) returns (UserList);
}
""")
        ctx = _make_ctx(source_path=str(tmp_path))
        p = GRPCReflectionPlugin()

        with patch("discover_agent.plugins.grpc_reflection.probe_port", return_value=False):
            result = await p.discover(ctx)

        assert "gRPC" in result.technologies
        assert "UserService" in result.metadata.get("grpc_services", [])
        assert "GetUser" in result.metadata.get("grpc_methods", [])
        assert "ListUsers" in result.metadata.get("grpc_methods", [])

    @pytest.mark.asyncio
    async def test_probes_grpc_ports(self):
        ctx = _make_ctx()

        with patch("discover_agent.plugins.grpc_reflection.probe_port") as mock_probe:
            mock_probe.side_effect = lambda h, p, **kw: p == 50051
            p = GRPCReflectionPlugin()
            result = await p.discover(ctx)
            assert 50051 in result.metadata.get("grpc_ports", [])


# --- BlockchainRPCPlugin ---


class TestBlockchainRPCPlugin:
    """Tests for BlockchainRPCPlugin."""

    def test_metadata(self):
        p = BlockchainRPCPlugin()
        assert p.name == "blockchain_rpc"
        assert p.priority == 63

    @pytest.mark.asyncio
    async def test_rejects_without_blockchain_deps(self):
        ctx = _make_ctx()
        p = BlockchainRPCPlugin()
        assert await p.accepts(ctx) is False

    @pytest.mark.asyncio
    async def test_accepts_with_blockchain_technology(self):
        ctx = _make_ctx()
        ctx.site.technologies.append("blockchain:ethereum")
        p = BlockchainRPCPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_detects_ethereum_deps(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"ethers": "^6.0"}}')

        # Mock the http client to fail all probes (no network)
        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(side_effect=httpx.ConnectError("no network"))
        ctx = _make_ctx(source_path=str(tmp_path))
        ctx.http_client = client

        with patch("discover_agent.plugins.blockchain_rpc.probe_port", return_value=False):
            p = BlockchainRPCPlugin()
            result = await p.discover(ctx)
            assert any("ethereum" in t for t in result.technologies)

    @pytest.mark.asyncio
    async def test_probes_ethereum_jsonrpc(self):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = {"jsonrpc": "2.0", "result": "0x1234"}

        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx()
        ctx.http_client = client

        with patch("discover_agent.plugins.blockchain_rpc.probe_port", return_value=False):
            p = BlockchainRPCPlugin()
            result = await p.discover(ctx)
            assert "blockchain:ethereum" in result.technologies

    @pytest.mark.asyncio
    async def test_probes_chain_ports(self, tmp_path: Path):
        # Provide ethereum deps so the plugin detects the chain
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"ethers": "^6.0"}}')

        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 404
        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(return_value=resp)
        ctx = _make_ctx(source_path=str(tmp_path))
        ctx.http_client = client

        async def _mock_probe(h, p, **kw):
            return p == 8545

        with patch("discover_agent.plugins.blockchain_rpc.probe_port", side_effect=_mock_probe):
            p = BlockchainRPCPlugin()
            result = await p.discover(ctx)
            assert 8545 in result.metadata.get("blockchain_ports", [])


# --- MQTTAMQPPlugin ---


class TestMQTTAMQPPlugin:
    """Tests for MQTTAMQPPlugin."""

    def test_metadata(self):
        p = MQTTAMQPPlugin()
        assert p.name == "mqtt_amqp"
        assert p.priority == 65

    @pytest.mark.asyncio
    async def test_always_accepts(self):
        ctx = _make_ctx()
        p = MQTTAMQPPlugin()
        assert await p.accepts(ctx) is True

    @pytest.mark.asyncio
    async def test_detects_mqtt_deps(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"mqtt": "^5.0"}}')
        ctx = _make_ctx(source_path=str(tmp_path))

        with patch("discover_agent.plugins.mqtt_amqp.probe_port", return_value=False):
            p = MQTTAMQPPlugin()
            result = await p.discover(ctx)
            assert "MQTT" in result.technologies

    @pytest.mark.asyncio
    async def test_detects_kafka_deps(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"kafkajs": "^2.0"}}')
        ctx = _make_ctx(source_path=str(tmp_path))

        with patch("discover_agent.plugins.mqtt_amqp.probe_port", return_value=False):
            p = MQTTAMQPPlugin()
            result = await p.discover(ctx)
            assert "Kafka" in result.technologies

    @pytest.mark.asyncio
    async def test_extracts_broker_urls(self, tmp_path: Path):
        conf = tmp_path / "config.yaml"
        conf.write_text("broker_url: amqp://guest:guest@rabbitmq:5672/")
        ctx = _make_ctx(source_path=str(tmp_path))

        with patch("discover_agent.plugins.mqtt_amqp.probe_port", return_value=False):
            p = MQTTAMQPPlugin()
            result = await p.discover(ctx)
            assert any("amqp://" in u for u in result.urls)


# --- Plugin ordering and registration ---


class TestPluginOrdering:
    """Verify all 14 plugins are registered in correct priority order."""

    def test_all_14_plugins_registered(self):
        from discover_agent.plugins import DISCOVERY_PLUGINS
        names = [p.name for p in DISCOVERY_PLUGINS]
        assert len(names) >= 14
        for expected in [
            "crawl", "source_code", "infra_config", "mobile_routes",
            "openapi", "soap_wsdl", "graphql", "websocket", "sse",
            "rpc", "grpc_reflection", "blockchain_rpc", "mqtt_amqp",
            "js_bundle",
        ]:
            assert expected in names, f"Plugin '{expected}' not registered"

    def test_priority_order(self):
        from discover_agent.plugins import DISCOVERY_PLUGINS
        priorities = [p.priority for p in DISCOVERY_PLUGINS]
        assert priorities == sorted(priorities)

    def test_crawl_still_first(self):
        from discover_agent.plugins import DISCOVERY_PLUGINS
        assert DISCOVERY_PLUGINS[0].name == "crawl"
        assert DISCOVERY_PLUGINS[0].priority == 10

    def test_endpoint_validation_runs_last(self):
        from discover_agent.plugins import DISCOVERY_PLUGINS
        assert DISCOVERY_PLUGINS[-1].name == "endpoint_validation"
        assert DISCOVERY_PLUGINS[-1].priority == 90
