"""OIDCWellKnownPlugin — probe .well-known/openid-configuration for OIDC endpoints.

Fetches the OIDC discovery document and extracts authorization, token,
userinfo, JWKS, and other standard endpoints. Also probes the OAuth 2.0
authorization server metadata endpoint.
"""

import logging
from urllib.parse import urlparse

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import probe_endpoint

logger = logging.getLogger(__name__)

_OIDC_PATH = "/.well-known/openid-configuration"
_OAUTH_PATH = "/.well-known/oauth-authorization-server"

_OIDC_ENDPOINT_FIELDS = [
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "revocation_endpoint",
    "introspection_endpoint",
    "end_session_endpoint",
    "registration_endpoint",
]


@register_plugin
class OIDCWellKnownPlugin(DiscoveryPlugin):
    """Probe OIDC .well-known endpoint for discoverable auth endpoints."""

    name = "oidc_wellknown"
    priority = 25

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()

        oidc_map = await _probe_oidc(ctx)
        oauth_map = await _probe_oauth(ctx)

        endpoints_map = {**oauth_map, **oidc_map}
        if not endpoints_map:
            return result

        seen: set[str] = set()
        for field, url in endpoints_map.items():
            path = _url_to_path(url)
            if path and path not in seen:
                result.endpoints.append(path)
                seen.add(path)
            if url and url not in result.urls:
                result.urls.append(url)

        result.technologies.append("OIDC")
        result.metadata["oidc_endpoints"] = endpoints_map

        logger.info("OIDCWellKnown: found %d endpoints", len(result.endpoints))
        return result


async def _probe_oidc(ctx: DiscoveryContext) -> dict[str, str]:
    """Probe the OIDC discovery document."""
    url = ctx.staging_url.rstrip("/") + _OIDC_PATH
    return await _fetch_discovery(ctx, url)


async def _probe_oauth(ctx: DiscoveryContext) -> dict[str, str]:
    """Probe the OAuth 2.0 authorization server metadata."""
    url = ctx.staging_url.rstrip("/") + _OAUTH_PATH
    return await _fetch_discovery(ctx, url)


async def _fetch_discovery(ctx: DiscoveryContext, url: str) -> dict[str, str]:
    """Fetch a discovery document and extract endpoint fields."""
    reachable, resp = await probe_endpoint(ctx.http_client, url)
    if not reachable or not resp or resp.status_code != 200:
        return {}

    try:
        data = resp.json()
    except Exception:
        return {}

    if not isinstance(data, dict):
        return {}

    endpoints: dict[str, str] = {}
    for field in _OIDC_ENDPOINT_FIELDS:
        val = data.get(field)
        if isinstance(val, str) and val:
            endpoints[field] = val
    return endpoints


def _url_to_path(url: str) -> str:
    """Convert a full URL to just the path component."""
    try:
        parsed = urlparse(url)
        return parsed.path or ""
    except Exception:
        return ""
