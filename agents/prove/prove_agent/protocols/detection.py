"""Target capability detection — probes HTTP, WebSocket, and JSON-RPC support.

Runs once at startup to determine which protocols the target supports,
avoiding wasted iterations with wrong protocols during verification.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from prove_agent.strategies.base import ProbeProtocol

logger = logging.getLogger(__name__)

# Ports commonly used by blockchain/RPC nodes
_WS_RPC_PORTS = frozenset({9944, 9933, 8546, 8545, 26657})

_DETECT_TIMEOUT = 10.0


@dataclass
class TargetCapabilities:
    """Detected protocol capabilities of a target."""

    http: bool = False
    websocket: bool = False
    jsonrpc_http: bool = False
    jsonrpc_ws: bool = False
    grpc: bool = False
    sse: bool = False
    mqtt_ws: bool = False
    primary: ProbeProtocol = ProbeProtocol.HTTP
    rpc_methods: list[str] = field(default_factory=list)
    grpc_services: list[str] = field(default_factory=list)


def to_ws_url(http_url: str, path: str = "") -> str:
    """Convert an HTTP URL to its WebSocket equivalent.

    http:// → ws://, https:// → wss://
    """
    parsed = urlparse(http_url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.hostname or ""
    port_part = f":{parsed.port}" if parsed.port else ""
    ws_path = path or parsed.path or ""
    return f"{ws_scheme}://{host}{port_part}{ws_path}"


def is_ws_rpc_target(url: str) -> bool:
    """Port-based heuristic for WebSocket JSON-RPC targets."""
    parsed = urlparse(url)
    return parsed.port in _WS_RPC_PORTS if parsed.port else False


async def detect_capabilities(staging_url: str) -> tuple[TargetCapabilities, str]:
    """Probe a target to detect supported protocols.

    Detection sequence:
      1. HTTP GET → http=True if any response
      2. JSON-RPC POST → jsonrpc_http=True if valid JSON-RPC response
      3. WebSocket connect → websocket=True if handshake succeeds
         → then JSON-RPC over WS → jsonrpc_ws=True if valid response
      4. Primary = jsonrpc_ws > jsonrpc_http > websocket > http

    Returns (capabilities, human-readable summary).
    """
    caps = TargetCapabilities()
    parts: list[str] = []
    ws_url = to_ws_url(staging_url)

    # Run independent probes concurrently.
    # return_exceptions=True prevents one probe's failure from cancelling others.
    http_r, rpc_r, ws_r, grpc_r, sse_r, mqtt_r = await asyncio.gather(
        _probe_http(staging_url),
        _probe_jsonrpc_http(staging_url),
        _probe_websocket(ws_url),
        _probe_grpc(staging_url),
        _probe_sse(staging_url),
        _probe_mqtt_ws(staging_url),
        return_exceptions=True,
    )

    # Log raw probe results for diagnostics when detection fails
    logger.info(
        "probe_results http=%r rpc=%r ws=%r grpc=%r sse=%r mqtt=%r",
        http_r, rpc_r, ws_r, grpc_r, sse_r, mqtt_r,
    )

    # 1. HTTP — use bool() to handle exception objects from gather gracefully
    caps.http = bool(http_r) and not isinstance(http_r, BaseException)
    if caps.http:
        parts.append("HTTP")

    # 2. JSON-RPC over HTTP
    if isinstance(rpc_r, tuple):
        rpc_ok, methods = rpc_r
        caps.jsonrpc_http = rpc_ok
        if rpc_ok:
            caps.rpc_methods = methods
            parts.append("JSON-RPC/HTTP")

    # 3. WebSocket + JSON-RPC/WS (depends on WS result)
    caps.websocket = bool(ws_r) and not isinstance(ws_r, BaseException)
    if caps.websocket:
        parts.append("WebSocket")
        ws_rpc_ok, ws_methods = await _probe_jsonrpc_ws(ws_url)
        caps.jsonrpc_ws = ws_rpc_ok
        if ws_rpc_ok:
            if not caps.rpc_methods:
                caps.rpc_methods = ws_methods
            parts.append("JSON-RPC/WS")
    elif is_ws_rpc_target(staging_url):
        ws_rpc_ok, ws_methods = await _probe_jsonrpc_ws(ws_url)
        if ws_rpc_ok:
            caps.websocket = True
            caps.jsonrpc_ws = True
            caps.rpc_methods = ws_methods
            parts.append("WebSocket")
            parts.append("JSON-RPC/WS")

    # 4. gRPC
    caps.grpc = bool(grpc_r) and not isinstance(grpc_r, BaseException)
    if caps.grpc:
        parts.append("gRPC")

    # 5. SSE
    caps.sse = bool(sse_r) and not isinstance(sse_r, BaseException)
    if caps.sse:
        parts.append("SSE")

    # 6. MQTT/WS
    caps.mqtt_ws = bool(mqtt_r) and not isinstance(mqtt_r, BaseException)
    if caps.mqtt_ws:
        parts.append("MQTT/WS")

    # Determine primary protocol (best → worst)
    if caps.jsonrpc_ws:
        caps.primary = ProbeProtocol.JSONRPC
    elif caps.grpc:
        caps.primary = ProbeProtocol.GRPC
    elif caps.jsonrpc_http:
        caps.primary = ProbeProtocol.JSONRPC
    elif caps.websocket:
        caps.primary = ProbeProtocol.WEBSOCKET
    else:
        caps.primary = ProbeProtocol.HTTP

    summary = f"Detected protocols: {', '.join(parts) if parts else 'none'} (primary: {caps.primary.value})"
    logger.info(summary)
    return caps, summary


async def _probe_http(url: str) -> bool:
    """Check if target responds to HTTP."""
    try:
        async with httpx.AsyncClient(timeout=_DETECT_TIMEOUT) as client:
            resp = await client.get(url, follow_redirects=True)
            return resp.status_code > 0
    except BaseException as exc:
        logger.warning("HTTP probe failed for %s: %s: %s", url, type(exc).__name__, exc)
        return False


async def _probe_jsonrpc_http(url: str) -> tuple[bool, list[str]]:
    """Check if target speaks JSON-RPC over HTTP POST."""
    payload = {
        "jsonrpc": "2.0",
        "method": "rpc_methods",
        "params": [],
        "id": 1,
    }
    try:
        async with httpx.AsyncClient(timeout=_DETECT_TIMEOUT) as client:
            resp = await client.post(
                url, json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code not in (200, 400):
                return False, []
            ct = resp.headers.get("content-type", "")
            if "json" not in ct:
                return False, []
            data = resp.json()
            if "jsonrpc" in data or ("error" in data and "id" in data):
                methods = data.get("result", [])
                if isinstance(methods, list):
                    return True, methods
                return True, []
            return False, []
    except BaseException as exc:
        logger.debug("JSON-RPC/HTTP probe failed for %s: %s", url, exc)
        return False, []


async def _probe_websocket(ws_url: str) -> bool:
    """Check if target accepts WebSocket connections."""
    try:
        import websockets
        async with websockets.connect(
            ws_url, open_timeout=_DETECT_TIMEOUT, close_timeout=2,
        ):
            return True
    except BaseException as exc:
        logger.debug("WebSocket probe failed for %s: %s", ws_url, exc)
        return False


async def _probe_jsonrpc_ws(ws_url: str) -> tuple[bool, list[str]]:
    """Check if target speaks JSON-RPC over WebSocket."""
    import json as _json

    payload = _json.dumps({
        "jsonrpc": "2.0",
        "method": "rpc_methods",
        "params": [],
        "id": 1,
    })
    try:
        import websockets
        async with websockets.connect(
            ws_url, open_timeout=_DETECT_TIMEOUT, close_timeout=2,
        ) as ws:
            await ws.send(payload)
            raw = await asyncio.wait_for(ws.recv(), timeout=_DETECT_TIMEOUT)
            data = _json.loads(raw)
            if "jsonrpc" in data or ("error" in data and "id" in data):
                methods = data.get("result", [])
                if isinstance(methods, list):
                    return True, methods
                return True, []
            return False, []
    except BaseException as exc:
        logger.debug("JSON-RPC/WS probe failed for %s: %s", ws_url, exc)
        return False, []


async def _probe_grpc(url: str) -> bool:
    """Check if target responds to gRPC HTTP/2 probes."""
    try:
        async with httpx.AsyncClient(http2=True, timeout=_DETECT_TIMEOUT) as client:
            resp = await client.post(
                url,
                content=b"\x00\x00\x00\x00\x00",
                headers={
                    "Content-Type": "application/grpc",
                    "TE": "trailers",
                },
            )
            ct = resp.headers.get("content-type", "")
            return "grpc" in ct or bool(resp.headers.get("grpc-status"))
    except BaseException as exc:
        logger.debug("gRPC probe failed for %s: %s", url, exc)
        return False


async def _probe_sse(url: str) -> bool:
    """Check if target serves SSE on common paths."""
    try:
        async with httpx.AsyncClient(timeout=_DETECT_TIMEOUT) as client:
            for path in ("/events", "/stream", "/sse"):
                try:
                    resp = await client.get(
                        f"{url.rstrip('/')}{path}",
                        headers={"Accept": "text/event-stream"},
                    )
                    ct = resp.headers.get("content-type", "")
                    if "text/event-stream" in ct:
                        return True
                except BaseException:
                    pass
    except BaseException as exc:
        logger.debug("SSE probe failed for %s: %s", url, exc)
    return False


async def _probe_mqtt_ws(url: str) -> bool:
    """Check if target has MQTT over WebSocket on port 9001."""
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 9001),
            timeout=_DETECT_TIMEOUT,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except BaseException as exc:
        logger.debug("MQTT/WS probe failed for %s: %s", url, exc)
        return False


