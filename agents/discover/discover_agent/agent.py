"""Discover agent orchestration — endpoint discovery and attack surface mapping.

Pipeline:
  1. Validate target URL
  2. Register all discovery plugins (22 original + Playwright + LLM + Validation)
  3. Load cross-session learnings
  4. Load cached SiteMap (skip if no_cache)
  5. Optional source analysis
  6. Run ALL plugins via run_discovery()
  7. Merge cached results
  8. Filter static endpoints + deduplicate
  9. Save discovery cache + learnings
  10. Analyze security exposures → findings
  11. Emit discover_result (includes site_map_json + learnings_context)
  12. Emit result + agent_end
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from collections.abc import Generator
from typing import Any

import httpx

from shared.discovery.cache import (
    is_cache_fresh,
    load_cached_discovery,
    save_discovery_cache,
)
from shared.discovery.helpers import filter_static_endpoints
from shared.discovery.plugin_base import DiscoveryContext
from shared.discovery.runner import run_discovery
from shared.discovery.sitemap import SiteMap
from shared.transport.event_emitter import AgUiEventEmitter

from discover_agent.findings import analyze_security_exposures
from discover_agent.learning_store import (
    format_learnings_context,
    load_learnings,
    save_learnings,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_BACKEND_URL = os.environ.get("VULTURE_BACKEND_URL", "http://backend:28080")
_ROUTE_PREFIXES = {"api", "routes", "views", "endpoints", "controllers", "handlers", "pages"}


def _extract_routes_from_findings(findings: list[dict[str, Any]]) -> list[str]:
    """Extract candidate API routes from scan finding file paths."""
    routes: list[str] = []
    seen: set[str] = set()
    for f in findings:
        fp = f.get("file_path", "")
        if not fp:
            continue
        fp = fp.lstrip(".")
        if not fp.startswith("/"):
            fp = "/" + fp
        parts = fp.split("/")
        for i, part in enumerate(parts):
            lower = re.sub(r"\.\w+$", "", part.lower())
            if lower in _ROUTE_PREFIXES:
                route = "/" + "/".join(parts[i:])
                route = re.sub(r"\.\w+$", "", route)
                if route not in seen:
                    seen.add(route)
                    routes.append(route)
                break
    return routes


def _fetch_scan_findings(source_path: str) -> list[dict[str, Any]]:
    """Fetch prior scan findings from the backend memory API (2s timeout)."""
    if not source_path:
        return []
    try:
        resp = httpx.get(
            f"{_BACKEND_URL}/api/memories/by-path",
            params={"path": source_path, "limit": 200},
            timeout=2.0,
        )
        if resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except (ValueError, TypeError):
            return []
        return data if isinstance(data, list) else data.get("memories", [])
    except Exception as exc:
        logger.warning("Failed to fetch scan findings: %s", exc)
    return []


def _ensure_plugins_registered() -> None:
    """Import discover_agent.plugins to trigger @register_plugin decorators.

    The discovery plugins live in discover_agent.plugins and register themselves
    on import. We import the package once to populate DISCOVERY_PLUGINS.
    Raises RuntimeError if no plugins are registered after import.
    """
    from shared.discovery.plugin_base import DISCOVERY_PLUGINS
    if DISCOVERY_PLUGINS:
        return
    import discover_agent.plugins  # noqa: F401 — triggers registration
    if not DISCOVERY_PLUGINS:
        raise RuntimeError(
            "No discovery plugins registered after importing discover_agent.plugins. "
            "Check plugin files for import errors."
        )


def run_discover(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the discover pipeline and yield SSE events."""
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    target_url = config.get("target_url", "")
    no_cache = config.get("no_cache", False)
    schemas = config.get("schemas", {})
    rate_limit = float(config.get("rate_limit", 0))

    # Use source_path from config if provided, else use the function param
    effective_source = config.get("source_path", "") or source_path

    if not target_url:
        yield emitter.text_message("ERROR: target_url is required in config")
        yield emitter.run_finished("failed")
        return

    _ensure_plugins_registered()
    yield emitter.text_message(f"Starting discovery against {target_url}")

    # Load cross-session learnings
    learnings = load_learnings(target_url)
    learnings_ctx = format_learnings_context(learnings)
    if learnings_ctx:
        yield emitter.text_message(
            f"Loaded prior learnings: {len(learnings.insights)} insights, "
            f"{len(learnings.endpoint_behaviors)} endpoint behaviors"
        )

    # Load cached discovery (skip if no_cache)
    cached = None if no_cache else load_cached_discovery(target_url)
    cache_fresh = not no_cache and is_cache_fresh(target_url, max_age_seconds=3600)

    if cached and cache_fresh:
        yield emitter.text_message(
            f"Found fresh cache: {len(cached.api_endpoints)} endpoints, "
            f"{len(cached.urls)} URLs"
        )

    # Scan results enrichment (three paths)
    ignore_scan = config.get("ignore_scan_results", False)
    scan_routes: list[str] = []
    if not ignore_scan:
        config_scan = config.get("scan_findings", [])
        if config_scan:
            scan_routes = _extract_routes_from_findings(config_scan)
            if scan_routes:
                yield emitter.text_message(
                    f"Enriched with {len(scan_routes)} routes from pipeline scan findings"
                )
        elif effective_source:
            backend_findings = _fetch_scan_findings(effective_source)
            if backend_findings:
                scan_routes = _extract_routes_from_findings(backend_findings)
                if scan_routes:
                    yield emitter.text_message(
                        f"Enriched with {len(scan_routes)} routes from backend scan findings"
                    )
    else:
        yield emitter.text_message("Scan results ignored (ignore_scan_results=true)")

    # Source analysis (if source_path provided)
    source_routes: list[str] = list(learnings.source_routes)  # warm start
    source_routes.extend(scan_routes)
    source_analysis = None
    if effective_source:
        yield emitter.text_message(f"Analyzing source code at {effective_source}")
        try:
            from discover_agent.source_analyzer import analyze_source
            source_analysis = analyze_source(effective_source)
            if source_analysis and source_analysis.routes:
                source_routes.extend(r.path for r in source_analysis.routes)
                yield emitter.text_message(
                    f"Source analysis: {len(source_analysis.routes)} routes from "
                    f"{source_analysis.framework or 'unknown'} codebase"
                )
        except ImportError:
            yield emitter.text_message(
                "Source analyzer not available, proceeding with URL-only discovery"
            )
        except Exception as exc:
            logger.warning("Source analysis failed: %s", exc)
            yield emitter.text_message(f"Source analysis failed: {exc}")

    # Run plugin-based discovery (all 25 plugins)
    yield emitter.text_message("Running plugin-based discovery pipeline...")
    site = SiteMap()
    failed_plugins: list[str] = []
    loop = asyncio.new_event_loop()
    try:
        site, failed_plugins = loop.run_until_complete(
            _run_discovery_pipeline(
                target_url,
                site=site,
                source_routes=source_routes,
                schemas=schemas,
                source_analysis=source_analysis,
                source_path=effective_source,
                rate_limit=rate_limit,
                learnings=learnings,
            )
        )
    except Exception as exc:
        logger.warning("Discovery pipeline failed: %s", exc)
        yield emitter.text_message(f"Discovery pipeline error: {exc}")
    finally:
        loop.close()

    if failed_plugins:
        yield emitter.text_message(
            f"Warning: {len(failed_plugins)} plugin(s) failed: "
            + ", ".join(failed_plugins)
        )

    # Merge cached results
    if cached:
        site.merge(cached)

    site.deduplicate()
    filter_static_endpoints(site)

    # Save to cache
    save_discovery_cache(target_url, site)

    # Save cross-session learnings
    learnings.source_routes = source_routes[-500:]
    existing_tech = set(learnings.technologies)
    for t in site.technologies:
        if t not in existing_tech:
            learnings.technologies.append(t)
    save_learnings(target_url, learnings)

    yield emitter.text_message(
        f"Discovery complete: {len(site.api_endpoints)} API endpoints, "
        f"{len(site.urls)} URLs, {len(site.forms)} forms, "
        f"{len(site.technologies)} technologies"
    )

    # Analyze security exposures
    yield emitter.text_message("Analyzing discovered surface for security exposures...")
    security_findings = analyze_security_exposures(site, target_url)

    # Filter out known findings if not no_cache
    prior_titles = set()
    if prior_findings and not no_cache:
        prior_titles = {f.get("title", "") for f in prior_findings}
        before = len(security_findings)
        security_findings = [
            f for f in security_findings if f["title"] not in prior_titles
        ]
        filtered = before - len(security_findings)
        if filtered:
            yield emitter.text_message(
                f"Filtered {filtered} previously reported findings"
            )

    # Emit individual findings
    for finding in security_findings:
        yield emitter.finding_event(
            severity=finding["severity"],
            category=finding["category"],
            title=finding["title"],
            description=finding["description"],
            recommendation=finding.get("recommendation", ""),
        )

    # Emit discover_result event with full SiteMap + learnings context
    yield emitter.discover_result_event(
        target_url=target_url,
        site_map=site,
        learnings_context=format_learnings_context(learnings),
    )

    # Emit final result
    score = _compute_discovery_score(site, security_findings)
    summary = (
        f"Discovered {len(site.api_endpoints)} API endpoints, "
        f"{len(site.urls)} URLs, {len(site.forms)} forms. "
        f"Found {len(security_findings)} security exposures."
    )
    finding_dicts = [
        {
            "severity": f["severity"],
            "category": f["category"],
            "title": f["title"],
            "description": f["description"],
            "recommendation": f.get("recommendation", ""),
        }
        for f in security_findings
    ]
    yield emitter.result_event(finding_dicts, summary, score)
    yield emitter.run_finished("completed")


async def _run_discovery_pipeline(
    target_url: str,
    *,
    site: SiteMap,
    source_routes: list[str],
    schemas: dict[str, str],
    source_analysis: object | None,
    source_path: str,
    rate_limit: float = 0.0,
    learnings: object | None = None,
) -> tuple[SiteMap, list[str]]:
    """Run the shared plugin-based discovery pipeline.

    Returns (site_map, failed_plugins).
    """
    async with httpx.AsyncClient(
        timeout=_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": "Vulture-Discover/1.0"},
    ) as client:
        ctx = DiscoveryContext(
            staging_url=target_url,
            http_client=client,
            site=site,
            source_routes=source_routes,
            schemas=schemas,
            source_analysis=source_analysis,
            source_path=source_path,
            rate_limit=rate_limit,
            learnings=learnings,
        )
        return await run_discovery(ctx)


def _compute_discovery_score(
    site: SiteMap,
    findings: list[dict[str, Any]],
) -> float:
    """Compute a discovery coverage score (0.0 to 1.0).

    Higher score = better coverage with fewer exposures.
    """
    coverage_points = min(
        len(site.api_endpoints) * 2 + len(site.urls) + len(site.forms) * 3,
        100,
    )
    severity_penalty = {
        "critical": 20, "high": 10, "medium": 5, "low": 2,
    }
    penalty = sum(
        severity_penalty.get(f.get("severity", "low"), 0)
        for f in findings
    )
    raw = max(0, coverage_points - penalty)
    return round(min(raw / 100.0, 1.0), 2)
