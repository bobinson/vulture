"""JSBundlePlugin — extract API routes from compiled JavaScript bundles.

Moves _discover_js_api_routes from discovery.py. Scans JS chunks
for fetch/axios calls, API route strings, and endpoint config variables.
"""

import logging
import re

from shared.discovery.helpers import is_static_path as _is_static_path
from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_JS_API_ROUTE_RE = re.compile(
    r"""["'](/(?:api|v[0-9]+|graphql|rest|rpc|auth|webhook)[a-zA-Z0-9_/\-.]*)["']""",
)
_JS_FETCH_URL_RE = re.compile(
    r"""(?:fetch|axios|http|request|\.(?:get|post|put|delete|patch))\s*\(\s*["'`](/[a-zA-Z0-9_/\-.]+)["'`]""",
    re.IGNORECASE,
)
_JS_ENDPOINT_RE = re.compile(
    r"""(?:endpoint|baseUrl|apiUrl|API_URL|BASE_URL|url)\s*[:=]\s*["'`](/[a-zA-Z0-9_/\-.]+)["'`]""",
    re.IGNORECASE,
)


@register_plugin
class JSBundlePlugin(DiscoveryPlugin):
    """Extract API routes from compiled JavaScript bundles."""

    name = "js_bundle"
    priority = 70

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        # Only run if JS bundles were found in URLs
        return any(
            u.lower().endswith(".js") and "chunk" in u.lower()
            for u in ctx.site.urls
        )

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")

        js_urls = [
            u for u in ctx.site.urls
            if u.lower().endswith(".js")
            and "chunk" in u.lower()
            and not any(skip in u.lower() for skip in ("webpack", "polyfill", "framework"))
        ]

        # Prioritize page-specific chunks
        page_chunks = [u for u in js_urls if "/pages/" in u]
        other_chunks = [u for u in js_urls if "/pages/" not in u]
        js_to_scan = (page_chunks[:10] + other_chunks[:5])[:15]

        if not js_to_scan:
            return result

        found: set[str] = set()
        for js_path in js_to_scan:
            try:
                resp = await ctx.http_client.get(f"{base}{js_path}", timeout=8.0)
                if resp.status_code != 200:
                    continue
                text = resp.text
                if len(text) > 500_000:
                    text = text[:500_000]

                for pattern in (_JS_API_ROUTE_RE, _JS_FETCH_URL_RE, _JS_ENDPOINT_RE):
                    for m in pattern.finditer(text):
                        path = m.group(1)
                        if not _is_static_path(path) and len(path) >= 4:
                            found.add(path)
            except Exception:
                pass

        for ep in found:
            result.endpoints.append(ep)
            result.urls.append(ep)

        if found:
            logger.info("JS bundle analysis found %d API endpoints", len(found))

        return result
