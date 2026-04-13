"""EndpointValidationPlugin — validate discovered endpoints exist (priority 90).

Runs last in the pipeline. Validates all previously discovered API endpoints
via HTTP GET (removes 404s) and probes for hidden HTTP methods via OPTIONS.
"""

import asyncio
import logging
import re

from shared.discovery.helpers import is_static_path
from shared.discovery.plugin_base import (
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
)

logger = logging.getLogger(__name__)

_VALIDATION_CONCURRENCY = 20
_VALIDATION_TIMEOUT = 5.0


@register_plugin
class EndpointValidationPlugin(DiscoveryPlugin):
    """Validate discovered API endpoints and probe for hidden methods."""

    name = "endpoint_validation"
    priority = 90

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        """Run if there are API endpoints to validate."""
        return len(ctx.site.api_endpoints) > 0

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        """Validate endpoints and probe API methods."""
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")

        # Phase 1: Validate existing endpoints (remove 404s)
        invalid = await _validate_endpoints_parallel(
            ctx.http_client, base, ctx.site.api_endpoints,
        )
        if invalid:
            ctx.site.api_endpoints = [
                ep for ep in ctx.site.api_endpoints if ep not in invalid
            ]
            logger.info("Removed %d invalid endpoints (404)", len(invalid))

        # Phase 2: Probe API methods on known endpoints
        await _probe_api_methods(ctx.http_client, base, ctx.site, result)

        return result


async def _validate_endpoints_parallel(
    client, base: str, endpoints: list[str],
) -> set[str]:
    """Validate discovered API endpoints exist (parallel GET, keep unless 404)."""
    if not endpoints:
        return set()

    param_eps = {ep for ep in endpoints if "{" in ep}
    checkable = [ep for ep in endpoints if ep not in param_eps][:50]

    sem = asyncio.Semaphore(_VALIDATION_CONCURRENCY)

    async def _check(ep: str) -> tuple[str, bool]:
        async with sem:
            try:
                resp = await client.get(
                    f"{base}{ep}", timeout=_VALIDATION_TIMEOUT,
                )
                return ep, resp.status_code != 404
            except Exception:
                return ep, True  # Assume valid on error

    tasks = [_check(ep) for ep in checkable]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    invalid = set()
    for r in results:
        if isinstance(r, tuple) and not r[1]:
            invalid.add(r[0])
            logger.debug("Endpoint returned 404: %s", r[0])

    return invalid


_MUTATION_KEYWORDS = (
    "create", "add", "submit", "upload", "send", "register",
    "login", "auth", "search", "query", "graphql",
)


async def _probe_api_methods(
    client, base: str, site, result: DiscoveryResult,
) -> None:
    """Probe discovered API endpoints with OPTIONS and POST to find hidden methods."""
    endpoints_to_probe = [
        ep for ep in site.api_endpoints
        if ep.startswith("/api/") or ep.startswith("/v1/") or ep.startswith("/v2/")
    ][:20]

    for ep in endpoints_to_probe:
        url = f"{base}{ep}"
        try:
            resp = await client.options(url, timeout=_VALIDATION_TIMEOUT)
            allow = resp.headers.get("allow", "")
            if allow:
                methods = [m.strip().upper() for m in allow.split(",")]
                if any(m in methods for m in ("POST", "PUT", "DELETE", "PATCH")):
                    logger.debug("OPTIONS %s allows: %s", ep, allow)
        except Exception:
            pass

        if any(kw in ep.lower() for kw in _MUTATION_KEYWORDS):
            try:
                resp = await client.post(
                    url, json={}, timeout=_VALIDATION_TIMEOUT,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code not in (404, 405):
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct and ep not in site.api_endpoints:
                        result.endpoints.append(ep)
            except Exception:
                pass
