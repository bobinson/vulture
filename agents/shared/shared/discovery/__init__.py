"""Shared discovery package for endpoint detection and site mapping.

Used by both the discover agent (standalone discovery) and the prove agent
(verification with pre-built site maps).
"""

from shared.discovery.cache import (
    is_cache_fresh,
    load_cached_discovery,
    save_discovery_cache,
)
from shared.discovery.plugin_base import (
    DISCOVERY_PLUGINS,
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
)
from shared.discovery.runner import run_discovery
from shared.discovery.sitemap import SiteMap

__all__ = [
    "DISCOVERY_PLUGINS",
    "DiscoveryContext",
    "DiscoveryPlugin",
    "DiscoveryResult",
    "SiteMap",
    "is_cache_fresh",
    "load_cached_discovery",
    "register_plugin",
    "run_discovery",
    "save_discovery_cache",
]
