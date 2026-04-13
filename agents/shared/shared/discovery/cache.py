"""Discovery cache — persist and reload SiteMap results across sessions."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlparse

from shared.discovery.sitemap import SiteMap

logger = logging.getLogger(__name__)

_CACHE_DIR = os.environ.get(
    "VULTURE_DISCOVERY_CACHE",
    os.path.join(os.path.expanduser("~"), ".vulture", "discovery"),
)


def _cache_path(target_url: str) -> Path:
    """Get cache file path for a target URL."""
    url_hash = hashlib.sha256(target_url.encode()).hexdigest()[:16]
    hostname = urlparse(target_url).hostname or "unknown"
    return Path(_CACHE_DIR) / f"{hostname}_{url_hash}.json"


def load_cached_discovery(target_url: str) -> SiteMap | None:
    """Load previously discovered site map from cache."""
    path = _cache_path(target_url)
    if not path.exists():
        return None
    try:
        data = path.read_text()
        site = SiteMap.from_json(data)
        logger.info(
            "Loaded cached discovery: %d urls, %d api endpoints",
            len(site.urls), len(site.api_endpoints),
        )
        return site
    except Exception as exc:
        logger.warning("Failed to load discovery cache: %s", exc)
        return None


def is_cache_fresh(target_url: str, max_age_seconds: int = 3600) -> bool:
    """Check if cached discovery is recent enough to skip deep discovery."""
    path = _cache_path(target_url)
    if not path.exists():
        return False
    try:
        age = time.time() - path.stat().st_mtime
        return age < max_age_seconds
    except Exception:
        return False


def save_discovery_cache(target_url: str, site: SiteMap) -> None:
    """Save discovered site map to cache."""
    path = _cache_path(target_url)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(site.to_json())
        logger.info("Saved discovery cache: %s", path)
    except Exception as exc:
        logger.warning("Failed to save discovery cache: %s", exc)
