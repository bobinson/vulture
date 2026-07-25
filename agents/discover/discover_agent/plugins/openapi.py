"""OpenAPIPlugin — discover and parse OpenAPI/Swagger specifications.

Moves _discover_openapi from discovery.py and adds support for
user-provided spec files via ctx.schemas["openapi"].
"""

import json
import logging

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/.well-known/openapi.json", "/docs/openapi.json",
    "/api/openapi.json", "/api/swagger.json",
]


@register_plugin
class OpenAPIPlugin(DiscoveryPlugin):
    """Discover and parse OpenAPI/Swagger API specifications."""

    name = "openapi"
    priority = 30

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True  # Always attempt — specs are common

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")

        # Try user-provided schema file first
        schema_path = ctx.schemas.get("openapi")
        if schema_path:
            _parse_schema_file(schema_path, result)
            if result.endpoints:
                return result

        # Probe common spec endpoints
        await _probe_spec_urls(ctx.http_client, base, result)

        return result


async def _probe_spec_urls(client, base: str, result: DiscoveryResult) -> None:
    """Try to fetch OpenAPI/Swagger spec from common URL paths."""
    for path in _SPEC_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code != 200:
                continue
            ct = resp.headers.get("content-type", "")
            if "json" not in ct:
                continue
            spec = resp.json()
            _extract_from_spec(spec, path, result)
            return  # Found a spec, done
        except Exception:
            pass


def _extract_from_spec(spec: dict, spec_path: str, result: DiscoveryResult) -> None:
    """Extract endpoints from an OpenAPI/Swagger spec dict."""
    paths = spec.get("paths", {})
    for api_path, methods in paths.items():
        result.endpoints.append(api_path)
        for method in methods:
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                result.urls.append(api_path)

    base_path = spec.get("basePath", "")
    if base_path and base_path != "/":
        result.endpoints.append(base_path)

    result.technologies.append(f"OpenAPI ({spec_path})")


def _parse_schema_file(schema_path: str, result: DiscoveryResult) -> None:
    """Parse a user-provided OpenAPI spec file from disk."""
    try:
        with open(schema_path, "r") as f:
            content = f.read()

        # Try JSON first
        try:
            spec = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            # Try YAML if available
            try:
                import yaml
                spec = yaml.safe_load(content)
            except (ImportError, Exception):
                logger.warning("Cannot parse OpenAPI schema: %s", schema_path)
                return

        if not isinstance(spec, dict):
            return

        _extract_from_spec(spec, schema_path, result)
        logger.info("Parsed OpenAPI schema from file: %s (%d endpoints)", schema_path, len(result.endpoints))
    except Exception as exc:
        logger.warning("Failed to read OpenAPI schema file %s: %s", schema_path, exc)
