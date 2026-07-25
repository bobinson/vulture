"""GRPCReflectionPlugin — discover gRPC services via reflection and .proto files.

Tries gRPC reflection (if grpcio is available), parses .proto files from
source code, and probes common gRPC ports (50051, 50052, 9090).
"""

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import probe_port

logger = logging.getLogger(__name__)

_GRPC_PORTS = [50051, 50052, 9090]

_PROTO_SERVICE_RE = re.compile(r"""service\s+(\w+)\s*\{""")
_PROTO_RPC_RE = re.compile(r"""rpc\s+(\w+)\s*\(""")


@register_plugin
class GRPCReflectionPlugin(DiscoveryPlugin):
    """Discover gRPC services via reflection, .proto parsing, and port probing."""

    name = "grpc_reflection"
    priority = 62

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        parsed = urlparse(ctx.staging_url)
        host = parsed.hostname or "localhost"

        # 1. Try gRPC reflection (optional dependency)
        await _try_grpc_reflection(host, result)

        # 2. Parse .proto files from source
        if ctx.source_path:
            _scan_proto_files(Path(ctx.source_path), result)

        # 3. Probe common gRPC ports
        await _probe_grpc_ports(host, result)

        return result


async def _try_grpc_reflection(host: str, result: DiscoveryResult) -> None:
    """Attempt gRPC reflection to enumerate services.

    Runs blocking gRPC calls in a thread executor to avoid blocking the event loop.
    """
    try:
        import grpc  # type: ignore[import-untyped]
        from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("grpcio/grpc-reflection not available, skipping reflection")
        return

    import asyncio

    def _reflect_sync(port: int) -> tuple[int, list[str]] | None:
        try:
            channel = grpc.insecure_channel(f"{host}:{port}")
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            request = reflection_pb2.ServerReflectionRequest(list_services="")
            responses = stub.ServerReflectionInfo(iter([request]))
            for resp in responses:
                if resp.HasField("list_services_response"):
                    services = [s.name for s in resp.list_services_response.service]
                    channel.close()
                    return port, services
            channel.close()
        except Exception:
            pass
        return None

    loop = asyncio.get_running_loop()
    for port in _GRPC_PORTS:
        found = await loop.run_in_executor(None, _reflect_sync, port)
        if found:
            p, services = found
            result.metadata.setdefault("grpc_services", []).extend(services)
            result.technologies.append("gRPC")
            result.endpoints.append(f"grpc://{host}:{p}")
            logger.info("gRPC reflection: %d services on port %d", len(services), p)
            break


def _scan_proto_files(root: Path, result: DiscoveryResult) -> None:
    """Parse .proto files for service and RPC method definitions."""
    count = 0
    for fpath in root.rglob("*.proto"):
        if count >= 20:
            break
        try:
            content = fpath.read_text(errors="replace")
        except Exception:
            continue
        count += 1

        services = _PROTO_SERVICE_RE.findall(content)
        methods = _PROTO_RPC_RE.findall(content)

        if services:
            result.metadata.setdefault("grpc_services", []).extend(services)
            result.metadata.setdefault("grpc_methods", []).extend(methods)
            if "gRPC" not in result.technologies:
                result.technologies.append("gRPC")
            logger.info(
                "Proto file %s: %d services, %d methods",
                fpath.name, len(services), len(methods),
            )


async def _probe_grpc_ports(host: str, result: DiscoveryResult) -> None:
    """Probe common gRPC ports to detect running services."""
    for port in _GRPC_PORTS:
        if await probe_port(host, port, timeout=3.0):
            result.metadata.setdefault("grpc_ports", []).append(port)
            if "gRPC" not in result.technologies:
                result.technologies.append("gRPC")
            logger.info("gRPC port open: %s:%d", host, port)
