"""Staging site discovery — backward-compatible shim.

Discovery plugins, deep discovery, LLM endpoint suggestion, and endpoint
validation have all moved to ``discover_agent``.  This module retains only
re-exports for shared types and the ``discover_incremental`` helper used
during verification.
"""

from __future__ import annotations

import logging

from shared.discovery.sitemap import SiteMap  # noqa: F401
from shared.discovery.cache import (  # noqa: F401
    load_cached_discovery,
    save_discovery_cache,
    is_cache_fresh,
)
from shared.discovery.helpers import (  # noqa: F401
    extract_forms as _extract_forms,
    extract_json_urls as _extract_json_urls,
    extract_links as _extract_links,
)

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0


async def discover_incremental(
    staging_url: str,
    known_urls: list[str],
) -> SiteMap:
    """Run incremental discovery — crawl newly found pages for more links."""
    site = SiteMap()
    base = staging_url.rstrip("/")

    async with httpx.AsyncClient(
        timeout=_TIMEOUT, follow_redirects=True,
    ) as client:
        for url_path in known_urls[:20]:
            try:
                full_url = f"{base}{url_path}"
                resp = await client.get(full_url)
                ct = resp.headers.get("content-type", "")
                if "text/html" in ct and resp.status_code == 200:
                    _extract_links(resp.text, base, site)
                    _extract_forms(resp.text, base, site)
                elif "json" in ct:
                    site.api_endpoints.append(url_path)
                    _extract_json_urls(resp.text, base, site)
                site.urls.append(url_path)
            except Exception:
                pass

    site.deduplicate()

    cached = load_cached_discovery(staging_url)
    if cached:
        cached.merge(site)
        cached.deduplicate()
        save_discovery_cache(staging_url, cached)
    else:
        save_discovery_cache(staging_url, site)

    return site
