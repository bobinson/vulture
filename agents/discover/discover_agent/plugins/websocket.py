"""WebSocketPlugin — probe common WebSocket paths and detect frameworks.

Probes /ws, /socket.io, /cable, etc. Uses actual WebSocket connections
where possible, falling back to HTTP upgrade header probing.
Detects Socket.IO, ActionCable, Phoenix Channel frameworks.
"""

import logging

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_WS_PATHS = [
    "/ws",
    "/wss",
    "/socket",
    "/socket.io",
    "/socket.io/",
    "/sockjs",
    "/cable",
    "/channels",
    "/hub",
    "/signalr",
    "/realtime",
    "/live",
    "/events",
    "/api/ws",
    "/api/socket",
    "/api/realtime",
    "/graphql",  # GraphQL subscriptions often over WS
]

_WS_FRAMEWORKS = {
    "socket.io": "Socket.IO",
    "sockjs": "SockJS",
    "cable": "ActionCable",
    "channels": "Django Channels",
    "signalr": "SignalR",
    "phoenix": "Phoenix Channel",
}


@register_plugin
class WebSocketPlugin(DiscoveryPlugin):
    """Discover WebSocket endpoints and real-time communication frameworks."""

    name = "websocket"
    priority = 50

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")
        already_found = set(ctx.site.api_endpoints)

        for path in _WS_PATHS:
            if path in already_found:
                continue
            detected = await _probe_ws_path(ctx.http_client, base, path, result)
            if detected:
                already_found.add(path)

        return result


async def _probe_ws_path(
    client, base: str, path: str, result: DiscoveryResult,
) -> bool:
    """Probe a single WebSocket path. Returns True if detected."""
    # Phase 1: Try actual WebSocket connection (definitive)
    ws_detected = await _try_ws_connect(base, path, result)
    if ws_detected:
        return True

    # Phase 2: Fall back to HTTP upgrade header probing
    url = f"{base}{path}"
    try:
        resp = await client.get(
            url,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            },
            timeout=5.0,
        )

        # 101 Switching Protocols = definite WebSocket
        if resp.status_code == 101:
            result.endpoints.append(path)
            result.urls.append(path)
            _detect_ws_framework(path, resp, result)
            logger.info("WebSocket endpoint confirmed: %s (101)", path)
            return True

        # 400 with "upgrade" mention = likely WebSocket but bad handshake
        if resp.status_code == 400:
            body = resp.text[:500].lower()
            if "upgrade" in body or "websocket" in body:
                result.endpoints.append(path)
                result.urls.append(path)
                _detect_ws_framework(path, resp, result)
                logger.info("WebSocket endpoint likely: %s (400 + upgrade hint)", path)
                return True

        # Check if response indicates WebSocket support
        upgrade_header = resp.headers.get("upgrade", "").lower()
        if "websocket" in upgrade_header:
            result.endpoints.append(path)
            result.urls.append(path)
            _detect_ws_framework(path, resp, result)
            return True

        # Socket.IO polling transport fallback
        if "socket.io" in path:
            return await _probe_socketio_polling(client, base, path, result)

        return False
    except Exception:
        return False


async def _try_ws_connect(
    base: str, path: str, result: DiscoveryResult,
) -> bool:
    """Try actual WebSocket connection using websockets library."""
    from discover_agent.plugins._shared import to_ws_url

    ws_url = to_ws_url(base, path)
    try:
        import websockets
        async with websockets.connect(
            ws_url, open_timeout=5, close_timeout=2,
        ):
            result.endpoints.append(path)
            result.urls.append(path)
            result.technologies.append("WebSocket")
            result.metadata[f"ws_confirmed_{path}"] = True
            logger.info("WebSocket endpoint confirmed via connect: %s", path)
            return True
    except Exception:
        return False


async def _probe_socketio_polling(
    client, base: str, path: str, result: DiscoveryResult,
) -> bool:
    """Probe Socket.IO via HTTP long-polling transport."""
    try:
        poll_url = f"{base}{path.rstrip('/')}/?transport=polling&EIO=4"
        resp = await client.get(poll_url, timeout=5.0)
        if resp.status_code == 200:
            body = resp.text[:200]
            # Socket.IO polling returns a session ID
            if body and (body.startswith("0{") or "sid" in body):
                result.endpoints.append(path)
                result.urls.append(path)
                result.technologies.append("Socket.IO")
                logger.info("Socket.IO polling endpoint: %s", path)
                return True
        return False
    except Exception:
        return False


def _detect_ws_framework(path: str, resp, result: DiscoveryResult) -> None:
    """Detect which WebSocket framework is in use."""
    path_lower = path.lower()
    for keyword, framework in _WS_FRAMEWORKS.items():
        if keyword in path_lower:
            result.technologies.append(framework)
            return

    # Check response headers for framework hints
    server = resp.headers.get("server", "").lower()
    if "cowboy" in server:
        result.technologies.append("Phoenix Channel")
    elif "puma" in server:
        result.technologies.append("ActionCable")

    result.technologies.append("WebSocket")
