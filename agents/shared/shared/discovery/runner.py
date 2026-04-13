"""Discovery runner — orchestrates plugins by priority tier."""

from __future__ import annotations

import asyncio
import itertools
import logging

from shared.discovery.plugin_base import (
    DISCOVERY_PLUGINS,
    DiscoveryContext,
    DiscoveryPlugin,
    merge_result,
)
from shared.discovery.sitemap import SiteMap

logger = logging.getLogger(__name__)

_PLUGIN_TIMEOUT = 30.0  # Max seconds per plugin


async def run_discovery(ctx: DiscoveryContext) -> tuple[SiteMap, list[str]]:
    """Orchestrator: run all applicable plugins, grouped by priority tier.

    Same-priority plugins run concurrently; cross-tier ordering is preserved.
    Each plugin has a timeout to prevent a hung plugin from blocking the pipeline.

    Returns (site_map, failed_plugins) so callers can surface errors.
    """
    # Sort by class attribute — no need to instantiate
    sorted_plugins = sorted(DISCOVERY_PLUGINS, key=lambda c: c.priority)
    failed_plugins: list[str] = []

    for _priority, group in itertools.groupby(sorted_plugins, key=lambda c: c.priority):
        tier_plugins = list(group)

        async def _run_plugin(plugin_cls: type[DiscoveryPlugin]) -> None:
            plugin = plugin_cls()
            try:
                if not await plugin.accepts(ctx):
                    return
                logger.info(
                    "Running discovery plugin: %s (priority=%d)",
                    plugin.name, plugin.priority,
                )
                result = await asyncio.wait_for(
                    plugin.discover(ctx), timeout=_PLUGIN_TIMEOUT,
                )
                merge_result(ctx.site, result)
            except asyncio.TimeoutError:
                logger.warning("Plugin %s timed out after %.0fs", plugin.name, _PLUGIN_TIMEOUT)
                failed_plugins.append(f"{plugin.name} (timeout)")
            except Exception as exc:
                logger.warning("Plugin %s failed: %s", plugin.name, exc)
                failed_plugins.append(f"{plugin.name} ({exc})")

        await asyncio.gather(*[_run_plugin(pc) for pc in tier_plugins])

    if failed_plugins:
        logger.info("Plugins with errors: %s", ", ".join(failed_plugins))

    ctx.site.deduplicate()
    return ctx.site, failed_plugins
