"""PlaywrightDeepPlugin — Playwright-based deep discovery (priority 75).

Uses headless Chromium to browse the target site, intercept XHR/fetch/WebSocket
traffic, and discover endpoints invisible to static crawling. Skipped when
cache is fresh with good coverage.
"""

import asyncio
import logging

from shared.discovery.cache import is_cache_fresh, load_cached_discovery
from shared.discovery.helpers import is_static_path
from shared.discovery.plugin_base import (
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
)

logger = logging.getLogger(__name__)


@register_plugin
class PlaywrightDeepPlugin(DiscoveryPlugin):
    """Playwright-based deep discovery — intercept real browser API calls."""

    name = "playwright_deep"
    priority = 75

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        """Skip when cache is fresh with good API endpoint coverage."""
        cached = load_cached_discovery(ctx.staging_url)
        cache_fresh = is_cache_fresh(ctx.staging_url, max_age_seconds=3600)
        if cache_fresh and cached and len(cached.api_endpoints) >= 10:
            return False
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        """Run Playwright deep discovery and return discovered endpoints."""
        try:
            from discover_agent.deep_discovery import deep_discover
        except ImportError:
            logger.info("Playwright not available, skipping deep discovery")
            return DiscoveryResult()

        seed_paths = [u for u in ctx.site.urls if not is_static_path(u)][:15]
        try:
            deep_site = await asyncio.wait_for(
                deep_discover(ctx.staging_url, seed_paths=seed_paths),
                timeout=25.0,  # Must be under runner's 30s per-plugin timeout
            )
            return DiscoveryResult(
                endpoints=list(deep_site.api_endpoints),
                urls=list(deep_site.urls),
                forms=list(deep_site.forms),
                technologies=list(deep_site.technologies),
            )
        except asyncio.TimeoutError:
            logger.warning("Deep discovery timed out after 25s")
            return DiscoveryResult()
        except Exception as exc:
            logger.warning("Deep discovery failed: %s", exc)
            return DiscoveryResult()
