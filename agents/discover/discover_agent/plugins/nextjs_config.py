"""NextJSConfigPlugin — discover endpoints from next.config.ts/js rewrites and redirects.

Parses ``next.config.*`` to extract rewrite source/destination pairs,
redirect patterns, and security headers — making invisible OIDC/auth
rewrites discoverable.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import read_source_file

logger = logging.getLogger(__name__)

_SOURCE_RE = re.compile(r"""source:\s*['"]([^'"]+)['"]""")
_DESTINATION_RE = re.compile(r"""destination:\s*['"]([^'"]+)['"]""")
_NEXTJS_PARAM_RE = re.compile(r":(\w+)\*?")

_BLOCK_RE = re.compile(r"(rewrites|redirects|headers)\s*(?:\(\)|:|\s*=>)")


@register_plugin
class NextJSConfigPlugin(DiscoveryPlugin):
    """Discover endpoints from next.config.ts/js rewrites and redirects."""

    name = "nextjs_config"
    priority = 21

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        if not ctx.source_path:
            return False
        root = Path(ctx.source_path)
        return read_source_file(root, "next.config") is not None

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        content = read_source_file(root, "next.config")
        if not content:
            return result

        rewrites = _extract_rewrites(content)
        redirects = _extract_redirects(content)
        headers = _extract_header_paths(content)

        seen: set[str] = set()
        for rw in rewrites:
            _add_unique(result.endpoints, seen, _normalize_path(rw["source"]))
            _add_unique(result.endpoints, seen, _normalize_path(rw["destination"]))
        for rd in redirects:
            _add_unique(result.endpoints, seen, _normalize_path(rd))
        for hp in headers:
            _add_unique(result.endpoints, seen, _normalize_path(hp))

        result.technologies.append("Next.js")
        if rewrites:
            result.metadata["nextjs_rewrites"] = rewrites
        if redirects:
            result.metadata["nextjs_redirects"] = redirects

        if result.endpoints:
            logger.info("NextJSConfig: found %d endpoints", len(result.endpoints))
        return result


def _normalize_path(path: str) -> str:
    """Convert Next.js ``:param`` / ``:path*`` → ``{param}`` / ``{path}``."""
    return _NEXTJS_PARAM_RE.sub(r"{\1}", path)


def _extract_rewrites(content: str) -> list[dict]:
    """Extract source/destination rewrite pairs."""
    rewrites: list[dict] = []
    lines = content.splitlines()
    block = ""
    pending_source: str | None = None

    for line in lines:
        bm = _BLOCK_RE.search(line)
        if bm:
            block = bm.group(1)

        if block == "rewrites":
            sm = _SOURCE_RE.search(line)
            dm = _DESTINATION_RE.search(line)
            if sm:
                pending_source = sm.group(1)
            if dm and pending_source:
                rewrites.append({"source": pending_source, "destination": dm.group(1)})
                pending_source = None
    return rewrites


def _extract_redirects(content: str) -> list[str]:
    """Extract redirect source patterns."""
    redirects: list[str] = []
    lines = content.splitlines()
    block = ""

    for line in lines:
        bm = _BLOCK_RE.search(line)
        if bm:
            block = bm.group(1)
        if block == "redirects":
            sm = _SOURCE_RE.search(line)
            if sm:
                redirects.append(sm.group(1))
    return redirects


def _extract_header_paths(content: str) -> list[str]:
    """Extract paths from headers blocks."""
    paths: list[str] = []
    lines = content.splitlines()
    block = ""

    for line in lines:
        bm = _BLOCK_RE.search(line)
        if bm:
            block = bm.group(1)
        if block == "headers":
            sm = _SOURCE_RE.search(line)
            if sm:
                paths.append(sm.group(1))
    return paths


def _add_unique(endpoints: list[str], seen: set[str], path: str) -> None:
    """Add path to endpoints if not already present."""
    if path and path not in seen:
        endpoints.append(path)
        seen.add(path)
