"""Shared discovery package for endpoint detection and site mapping.

Used by both the discover agent (standalone discovery) and the prove agent
(verification with pre-built site maps).
"""

from shared.discovery.sitemap import SiteMap
from shared.discovery.plugin_base import (
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
    DISCOVERY_PLUGINS,
)
from shared.discovery.runner import run_discovery
from shared.discovery.cache import (
    load_cached_discovery,
    save_discovery_cache,
    is_cache_fresh,
)

__all__ = [
    "SiteMap",
    "DiscoveryContext",
    "DiscoveryPlugin",
    "DiscoveryResult",
    "register_plugin",
    "DISCOVERY_PLUGINS",
    "run_discovery",
    "load_cached_discovery",
    "save_discovery_cache",
    "is_cache_fresh",
]
