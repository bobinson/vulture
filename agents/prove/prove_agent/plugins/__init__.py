"""Compatibility shim — discovery plugins have moved to discover_agent.plugins.

All 22+ discovery plugins now live in ``discover_agent.plugins``.
This module re-exports the shared discovery types so existing prove_agent
code that imports from ``prove_agent.plugins`` continues to work.
"""

from shared.discovery.sitemap import SiteMap  # noqa: F401
from shared.discovery.plugin_base import (  # noqa: F401
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    DISCOVERY_PLUGINS,
    register_plugin,
    merge_result as _merge_result,
)
from shared.discovery.runner import run_discovery  # noqa: F401
