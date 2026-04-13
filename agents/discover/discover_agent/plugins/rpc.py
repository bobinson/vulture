"""RPCPlugin — probe gRPC-Web, JSON-RPC, tRPC, and WS JSON-RPC endpoints.

Detects RPC frameworks from content-type headers and error responses.
Includes WebSocket JSON-RPC probing for blockchain nodes (Substrate/Polkadot).
"""

import asyncio
import json
import logging

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_GRPC_PATHS = [
    "/grpc",
    "/grpc-web",
    "/api/grpc",
]

_JSONRPC_PATHS = [
    "/rpc",
    "/jsonrpc",
    "/api/rpc",
    "/api/jsonrpc",
    "/json-rpc",
]

_TRPC_PATHS = [
    "/trpc",
    "/api/trpc",
]


@register_plugin
class RPCPlugin(DiscoveryPlugin):
    """Discover gRPC-Web, JSON-RPC, and tRPC endpoints."""

    name = "rpc"
    priority = 60

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")
        already_found = set(ctx.site.api_endpoints)

        await _probe_grpc_web(ctx.http_client, base, already_found, result)
        await _probe_jsonrpc(ctx.http_client, base, already_found, result)
        await _probe_trpc(ctx.http_client, base, already_found, result)
        await _probe_ws_jsonrpc(base, already_found, result)

        return result


async def _probe_grpc_web(
    client, base: str, already_found: set[str], result: DiscoveryResult,
) -> None:
    """Probe for gRPC-Web endpoints."""
    for path in _GRPC_PATHS:
        if path in already_found:
            continue
        try:
            resp = await client.post(
                f"{base}{path}",
                content=b"",
                headers={
                    "Content-Type": "application/grpc-web+proto",
                    "X-Grpc-Web": "1",
                },
                timeout=5.0,
            )
            ct = resp.headers.get("content-type", "")
            # gRPC-Web responds with grpc content types
            if "grpc" in ct:
                result.endpoints.append(path)
                result.urls.append(path)
                result.technologies.append("gRPC-Web")
                logger.info("gRPC-Web endpoint found: %s", path)
                return

            # Some gRPC proxies return specific status codes
            if resp.status_code == 415:  # Unsupported Media Type
                grpc_status = resp.headers.get("grpc-status", "")
                if grpc_status:
                    result.endpoints.append(path)
                    result.urls.append(path)
                    result.technologies.append("gRPC-Web")
                    return
        except Exception:
            pass


async def _probe_jsonrpc(
    client, base: str, already_found: set[str], result: DiscoveryResult,
) -> None:
    """Probe for JSON-RPC endpoints."""
    rpc_request = {
        "jsonrpc": "2.0",
        "method": "system.listMethods",
        "params": [],
        "id": 1,
    }

    for path in _JSONRPC_PATHS:
        if path in already_found:
            continue
        try:
            resp = await client.post(
                f"{base}{path}",
                json=rpc_request,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.status_code not in (200, 400):
                continue

            ct = resp.headers.get("content-type", "")
            if "json" not in ct:
                continue

            data = resp.json()
            # JSON-RPC responses have "jsonrpc", "id", and either "result" or "error"
            if "jsonrpc" in data or ("error" in data and "id" in data):
                result.endpoints.append(path)
                result.urls.append(path)
                result.technologies.append("JSON-RPC")
                logger.info("JSON-RPC endpoint found: %s", path)

                # Extract available methods if system.listMethods worked
                methods = data.get("result", [])
                if isinstance(methods, list) and methods:
                    result.metadata["jsonrpc_methods"] = methods
                return
        except Exception:
            pass


async def _probe_trpc(
    client, base: str, already_found: set[str], result: DiscoveryResult,
) -> None:
    """Probe for tRPC endpoints."""
    for path in _TRPC_PATHS:
        if path in already_found:
            continue
        try:
            # tRPC uses dot-notation procedure names
            resp = await client.get(
                f"{base}{path}/healthcheck",
                timeout=5.0,
            )

            # tRPC returns JSON with specific shape
            if resp.status_code in (200, 400, 404, 500):
                ct = resp.headers.get("content-type", "")
                if "json" not in ct:
                    continue

                data = resp.json()
                # tRPC v10 wraps in {"result": {"data": ...}}
                if "result" in data:
                    result.endpoints.append(path)
                    result.urls.append(path)
                    result.technologies.append("tRPC")
                    logger.info("tRPC endpoint found: %s", path)
                    return

                # tRPC error responses include specific shape
                if isinstance(data, list) and data:
                    item = data[0]
                    if isinstance(item, dict) and "error" in item:
                        error = item["error"]
                        if isinstance(error, dict) and "code" in error:
                            result.endpoints.append(path)
                            result.urls.append(path)
                            result.technologies.append("tRPC")
                            return
        except Exception:
            pass


async def _probe_ws_jsonrpc(
    base: str, already_found: set[str], result: DiscoveryResult,
) -> None:
    """Probe for JSON-RPC over WebSocket (Substrate/Polkadot nodes)."""
    from discover_agent.plugins._shared import to_ws_url

    ws_url = to_ws_url(base)
    rpc_request = json.dumps({
        "jsonrpc": "2.0",
        "method": "rpc_methods",
        "params": [],
        "id": 1,
    })

    try:
        import websockets
        async with websockets.connect(
            ws_url, open_timeout=5, close_timeout=2,
        ) as ws:
            await ws.send(rpc_request)
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            data = json.loads(raw)
            if "jsonrpc" in data or ("error" in data and "id" in data):
                result.endpoints.append("/")
                result.urls.append("/")
                result.technologies.append("JSON-RPC/WebSocket")
                logger.info("JSON-RPC/WebSocket endpoint found at %s", ws_url)
                methods = data.get("result", [])
                if isinstance(methods, list) and methods:
                    result.metadata["jsonrpc_ws_methods"] = methods
                    # Detect Substrate node from method names
                    method_names = [m if isinstance(m, str) else "" for m in methods]
                    if any(m.startswith("system_") for m in method_names):
                        result.technologies.append("Substrate")
                        logger.info("Substrate node detected via WS JSON-RPC")
    except Exception:
        pass
