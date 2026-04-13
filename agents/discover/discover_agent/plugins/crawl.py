"""CrawlPlugin — homepage, robots.txt, sitemaps, common paths, HTML link extraction.

Moves _discover_homepage, _discover_robots, _discover_sitemaps,
_discover_common_paths from discovery.py. Filters known_404_paths
from learnings and records reachable endpoints.
"""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from shared.discovery.sitemap import SiteMap
from shared.discovery.helpers import (
    COMMON_PATHS,
    extract_forms,
    extract_headers,
    extract_json_urls,
    extract_links,
    extract_technologies,
    is_static_path,
)
from discover_agent.learning_store import record_known_404, record_reachable_endpoint
from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_CRAWL_CONCURRENCY = 10  # Max concurrent HTTP probes for common paths


@register_plugin
class CrawlPlugin(DiscoveryPlugin):
    """Basic HTTP crawling: homepage, robots.txt, sitemaps, common paths."""

    name = "crawl"
    priority = 10

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True  # Always runs

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")
        client = ctx.http_client

        # Build set of known 404s to skip
        known_404s: set[str] = set()
        if ctx.learnings:
            known_404s = set(ctx.learnings.known_404_paths)

        await _crawl_homepage(client, base, ctx.site, result)
        sitemap_urls = await _crawl_robots(client, base, ctx.site, result)
        await _crawl_sitemaps(client, base, ctx.site, sitemap_urls, result)
        await _crawl_common_paths(
            client, base, ctx.site, known_404s, result,
            ctx.learnings, rate_limit=ctx.rate_limit,
        )

        return result


async def _crawl_homepage(
    client, base: str, site: SiteMap, result: DiscoveryResult,
) -> None:
    """Fetch homepage and extract links, forms, headers, technologies."""
    try:
        resp = await client.get(base)
        extract_headers(resp, site)
        extract_technologies(resp, resp.text, site)
        if "text/html" in resp.headers.get("content-type", ""):
            extract_links(resp.text, base, site)
            extract_forms(resp.text, base, site)
        result.urls.append("/")
    except Exception as exc:
        logger.warning("Homepage fetch failed: %s", exc)


async def _crawl_robots(
    client, base: str, site: SiteMap, result: DiscoveryResult,
) -> list[str]:
    """Parse robots.txt for disallowed paths and sitemap references."""
    sitemap_urls: list[str] = []
    try:
        resp = await client.get(f"{base}/robots.txt")
        if resp.status_code != 200:
            return sitemap_urls
        for line in resp.text.splitlines():
            line = line.strip()
            lower = line.lower()
            if lower.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    site.disallowed_paths.append(path)
                    result.urls.append(path)
            elif lower.startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result.urls.append(path)
            elif lower.startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                if url.startswith("//"):
                    url = "https:" + url
                elif not url.startswith("http"):
                    # "Sitemap: /sitemap.xml" → resolve relative to base
                    raw = line.split(" ", 1)[1].strip() if " " in line else url
                    url = urljoin(base + "/", raw)
                sitemap_urls.append(url)
        result.urls.append("/robots.txt")
    except Exception as exc:
        logger.warning("robots.txt fetch failed: %s", exc)
    return sitemap_urls


async def _crawl_sitemaps(
    client, base: str, site: SiteMap,
    sitemap_urls: list[str], result: DiscoveryResult,
) -> None:
    """Parse sitemap XML files to extract URLs."""
    if not sitemap_urls:
        sitemap_urls = [f"{base}/sitemap.xml"]

    for smap_url in sitemap_urls[:5]:
        try:
            resp = await client.get(smap_url)
            if resp.status_code != 200:
                continue
            _parse_sitemap_xml(resp.text, base, result)
            result.urls.append(urlparse(smap_url).path or "/sitemap.xml")
        except Exception as exc:
            logger.warning("Sitemap fetch failed (%s): %s", smap_url, exc)


_MAX_SITEMAP_SIZE = 5_000_000  # 5 MB — reject oversized sitemaps to prevent entity expansion


def _parse_sitemap_xml(xml_text: str, base: str, result: DiscoveryResult) -> None:
    """Extract URLs from sitemap XML (handles both sitemap and sitemapindex)."""
    if len(xml_text) > _MAX_SITEMAP_SIZE:
        logger.warning("Sitemap too large (%d bytes), skipping", len(xml_text))
        return
    try:
        root = ElementTree.fromstring(xml_text)  # noqa: S314 — size-capped above
    except ElementTree.ParseError:
        return

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for loc in root.iter(f"{ns}loc"):
        if loc.text:
            url = loc.text.strip()
            parsed = urlparse(url)
            result.urls.append(parsed.path or "/")


async def _crawl_common_paths(
    client, base: str, site: SiteMap,
    known_404s: set[str], result: DiscoveryResult,
    learnings=None, *, rate_limit: float = 0.0,
) -> None:
    """Probe common paths concurrently, skipping known 404s."""
    existing = set(site.urls) | set(result.urls)
    paths_to_probe = [
        p for p in COMMON_PATHS if p not in existing and p not in known_404s
    ]
    if not paths_to_probe:
        return

    sem = asyncio.Semaphore(_CRAWL_CONCURRENCY)

    async def _probe_one(path: str) -> None:
        async with sem:
            if rate_limit > 0:
                await asyncio.sleep(rate_limit)
            try:
                resp = await client.get(f"{base}{path}", follow_redirects=False)
                if resp.status_code in (301, 302, 303, 307, 308):
                    result.urls.append(path)
                    location = resp.headers.get("location", "")
                    if location:
                        loc_path = urlparse(location).path
                        if loc_path:
                            result.urls.append(loc_path)
                    if learnings is not None:
                        record_reachable_endpoint(learnings, path)
                elif resp.status_code < 300:
                    result.urls.append(path)
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or ("xml" in ct and "html" not in ct):
                        result.endpoints.append(path)
                        if "json" in ct:
                            extract_json_urls(resp.text, base, site)
                    if "text/html" in ct and resp.status_code == 200:
                        extract_links(resp.text, base, site)
                        extract_forms(resp.text, base, site)
                    if learnings is not None:
                        record_reachable_endpoint(learnings, path)
                elif resp.status_code == 404:
                    if learnings is not None:
                        record_known_404(learnings, path)
            except Exception:
                pass

    await asyncio.gather(*[_probe_one(p) for p in paths_to_probe])
