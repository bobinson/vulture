"""NextJSMiddlewarePlugin — discover endpoints from Next.js middleware.ts.

Extracts ``matcher`` config, ``NextResponse.rewrite()`` targets, and
``NextResponse.redirect()`` targets from the project's middleware file.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import read_source_file

logger = logging.getLogger(__name__)

_MATCHER_ARRAY_RE = re.compile(r"""matcher:\s*\[([^\]]+)\]""", re.DOTALL)
_MATCHER_SINGLE_RE = re.compile(r"""matcher:\s*['"]([^'"]+)['"]""")
_MATCHER_ITEM_RE = re.compile(r"""['"]([^'"]+)['"]""")
_REWRITE_RE = re.compile(
    r"""NextResponse\.rewrite\s*\(\s*new\s+URL\s*\(\s*['"]([^'"]+)['"]"""
)
_REDIRECT_RE = re.compile(
    r"""NextResponse\.redirect\s*\(\s*new\s+URL\s*\(\s*['"]([^'"]+)['"]"""
)
_NEXTJS_PARAM_RE = re.compile(r":(\w+)\*?")


@register_plugin
class NextJSMiddlewarePlugin(DiscoveryPlugin):
    """Discover endpoints from Next.js middleware.ts matcher and rewrites."""

    name = "nextjs_middleware"
    priority = 21

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        if not ctx.source_path:
            return False
        root = Path(ctx.source_path)
        return read_source_file(root, "middleware") is not None

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        content = read_source_file(root, "middleware")
        if not content:
            return result

        matchers = _extract_matchers(content)
        rewrites = _extract_rewrites(content)
        redirects = _extract_redirects(content)

        seen: set[str] = set()
        for path in matchers + rewrites + redirects:
            normalized = _normalize_path(path)
            if normalized and normalized not in seen:
                result.endpoints.append(normalized)
                seen.add(normalized)

        result.technologies.append("Next.js Middleware")
        if matchers:
            result.metadata["middleware_matchers"] = matchers
        if rewrites:
            result.metadata["middleware_rewrites"] = rewrites
        if redirects:
            result.metadata["middleware_redirects"] = redirects

        if result.endpoints:
            logger.info("NextJSMiddleware: found %d endpoints", len(result.endpoints))
        return result


def _normalize_path(path: str) -> str:
    """Convert Next.js ``:param`` / ``:path*`` → ``{param}`` / ``{path}``."""
    return _NEXTJS_PARAM_RE.sub(r"{\1}", path)


def _extract_matchers(content: str) -> list[str]:
    """Extract matcher patterns from middleware config."""
    matchers: list[str] = []
    array_match = _MATCHER_ARRAY_RE.search(content)
    if array_match:
        inner = array_match.group(1)
        for m in _MATCHER_ITEM_RE.finditer(inner):
            matchers.append(m.group(1))
        return matchers

    single_match = _MATCHER_SINGLE_RE.search(content)
    if single_match:
        matchers.append(single_match.group(1))
    return matchers


def _extract_rewrites(content: str) -> list[str]:
    """Extract NextResponse.rewrite targets."""
    return [m.group(1) for m in _REWRITE_RE.finditer(content)]


def _extract_redirects(content: str) -> list[str]:
    """Extract NextResponse.redirect targets."""
    return [m.group(1) for m in _REDIRECT_RE.finditer(content)]
