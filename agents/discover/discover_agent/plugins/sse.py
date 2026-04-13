"""SSEPlugin — discover Server-Sent Events endpoints.

Probes common SSE paths with ``Accept: text/event-stream`` and detects SSE
patterns in source code (EventSource, StreamingResponse, etc.).
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import probe_endpoint

logger = logging.getLogger(__name__)

_SSE_PATHS = [
    "/events",
    "/stream",
    "/sse",
    "/api/events",
    "/api/stream",
    "/notifications",
    "/updates",
    "/api/sse",
    "/feed",
    "/live",
]

_SSE_SOURCE_RE = re.compile(
    r"""(?:EventSource|text/event-stream|StreamingResponse|Sse|event-stream)""",
    re.IGNORECASE,
)

_SSE_ENDPOINT_RE = re.compile(
    r"""(?:EventSource)\s*\(\s*["']([^"']+)["']""",
)

_MAX_SOURCE_FILES = 50


@register_plugin
class SSEPlugin(DiscoveryPlugin):
    """Discover Server-Sent Events endpoints via probing and source analysis."""

    name = "sse"
    priority = 55

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")
        already_found = set(ctx.site.api_endpoints)

        # 1. Probe SSE paths with Accept: text/event-stream
        await _probe_sse_paths(ctx.http_client, base, already_found, result)

        # 2. Detect SSE endpoints from source code
        if ctx.source_path:
            _scan_source_for_sse(Path(ctx.source_path), result)

        return result


async def _probe_sse_paths(
    client, base: str, already_found: set[str], result: DiscoveryResult,
) -> None:
    """Probe common SSE paths."""
    headers = {"Accept": "text/event-stream"}
    for path in _SSE_PATHS:
        if path in already_found:
            continue
        ok, resp = await probe_endpoint(
            client, f"{base}{path}", headers=headers, timeout=5.0,
        )
        if not ok or resp is None:
            continue
        if resp.status_code >= 400:
            continue

        ct = resp.headers.get("content-type", "")
        body = resp.text[:500]

        is_sse = (
            "text/event-stream" in ct
            or body.startswith("data:")
            or body.startswith("event:")
        )
        if is_sse:
            result.endpoints.append(path)
            result.urls.append(path)
            result.technologies.append("SSE")
            result.metadata.setdefault("sse_endpoints", []).append(path)
            logger.info("SSE endpoint found: %s", path)


_SSE_EXTENSIONS = frozenset({".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".java", ".rs"})


def _scan_source_for_sse(root: Path, result: DiscoveryResult) -> None:
    """Scan source code for SSE patterns."""
    scanned = 0
    for fpath in root.rglob("*"):
        if scanned >= _MAX_SOURCE_FILES:
            break
        if not fpath.is_file() or fpath.suffix.lower() not in _SSE_EXTENSIONS:
            continue
        try:
            content = fpath.read_text(errors="replace")
        except Exception:
            continue
        scanned += 1
        _check_sse_content(content, result)


def _check_sse_content(content: str, result: DiscoveryResult) -> None:
    """Check a single file's content for SSE patterns."""
    if not _SSE_SOURCE_RE.search(content):
        return
    if "SSE" not in result.technologies:
        result.technologies.append("SSE")
    for m in _SSE_ENDPOINT_RE.finditer(content):
        path = m.group(1)
        if path.startswith("/") and path not in result.endpoints:
            result.endpoints.append(path)
            result.metadata.setdefault("sse_endpoints", []).append(path)
