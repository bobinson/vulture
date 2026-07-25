"""GraphQLPlugin — introspection, fallback probing, schema file parsing.

Detects GraphQL endpoints via introspection query, falls back to
error-message probing (Apollo "Did you mean?" parsing), probes common
query/mutation names, and detects GraphQL variant. Caches schema
information in learnings.graphql_schemas.
"""

import json
import logging
import re
import time

from discover_agent.learning_store import GraphQLSchemaCache
from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

logger = logging.getLogger(__name__)

_GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]

_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}"""

# Common queries to probe when introspection is disabled
_COMMON_QUERIES = [
    "{ __typename }",
    '{ user(id: "1") { id } }',
    "{ users { id } }",
    "{ me { id } }",
    "{ viewer { id } }",
    "{ currentUser { id } }",
    "{ products { id } }",
    "{ posts { id } }",
    "{ orders { id } }",
]

# Apollo "Did you mean" regex
_DID_YOU_MEAN_RE = re.compile(r'Did you mean "(\w+)"', re.IGNORECASE)
_FIELD_SUGGESTION_RE = re.compile(r'"(\w+)"', re.IGNORECASE)


@register_plugin
class GraphQLPlugin(DiscoveryPlugin):
    """Discover GraphQL endpoints and extract schema information."""

    name = "graphql"
    priority = 40

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        # Skip if technologies clearly indicate no GraphQL
        if ctx.learnings and ctx.learnings.technologies:
            techs = {t.lower() for t in ctx.learnings.technologies}
            # Skip if purely REST-only frameworks with no GraphQL signals
            rest_only = {"django", "flask", "express"}
            if techs & rest_only and "graphql" not in " ".join(techs):
                # Check if there are any GraphQL hints from source analysis
                if not (ctx.source_analysis and ctx.source_analysis.graphql_queries):
                    return False
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")

        # Check for user-provided GraphQL schema file
        schema_path = ctx.schemas.get("graphql")
        if schema_path:
            _parse_schema_file(schema_path, result, ctx.learnings)
            if result.endpoints:
                return result

        # Check cached schema from learnings
        if ctx.learnings and ctx.learnings.graphql_schemas:
            cached = _use_cached_schema(ctx.learnings.graphql_schemas, result)
            if cached:
                return result

        # Probe each potential GraphQL path
        for gql_path in _GQL_PATHS:
            schema_cache = await _probe_graphql_endpoint(
                ctx.http_client, base, gql_path, result,
            )
            if schema_cache:
                # Cache in learnings
                if ctx.learnings is not None:
                    ctx.learnings.graphql_schemas[gql_path] = schema_cache
                break  # Found a working GraphQL endpoint

        return result


async def _probe_graphql_endpoint(
    client, base: str, path: str, result: DiscoveryResult,
) -> GraphQLSchemaCache | None:
    """Probe a single GraphQL endpoint path. Returns cache if found."""
    url = f"{base}{path}"

    # Try introspection first
    schema_cache = await _try_introspection(client, url, path)
    if schema_cache:
        result.endpoints.append(path)
        result.technologies.append(f"GraphQL ({schema_cache.variant or 'unknown'})")
        result.metadata["graphql_schema"] = {
            "path": path,
            "queries": schema_cache.queries,
            "mutations": schema_cache.mutations,
            "introspection_enabled": True,
        }
        return schema_cache

    # Try a simple query to detect if endpoint exists
    exists, variant = await _detect_graphql_endpoint(client, url)
    if not exists:
        return None

    # Endpoint exists but introspection disabled — use fallback probing
    result.endpoints.append(path)
    result.technologies.append(f"GraphQL ({variant or 'no-introspection'})")

    schema_cache = GraphQLSchemaCache(
        path=path, variant=variant, introspection_enabled=False,
        last_updated=time.time(),
    )

    # Probe common queries to discover available fields
    await _probe_common_queries(client, url, schema_cache, result)

    return schema_cache


async def _try_introspection(
    client, url: str, path: str,
) -> GraphQLSchemaCache | None:
    """Attempt full introspection query."""
    try:
        resp = await client.post(
            url,
            json={"query": _INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if "errors" in data and not data.get("data"):
            return None

        schema = data.get("data", {}).get("__schema", {})
        if not schema:
            return None

        # Extract types, queries, mutations
        types_list = schema.get("types", [])
        type_names = [t["name"] for t in types_list if not t["name"].startswith("__")]
        queries = []
        mutations = []
        subscriptions = []

        for t in types_list:
            if t["name"] == "Query" and t.get("fields"):
                queries = [f["name"] for f in t["fields"]]
            elif t["name"] == "Mutation" and t.get("fields"):
                mutations = [f["name"] for f in t["fields"]]
            elif t["name"] == "Subscription" and t.get("fields"):
                subscriptions = [f["name"] for f in t["fields"]]

        # Detect variant from response headers
        variant = _detect_variant_from_headers(resp.headers)

        cache = GraphQLSchemaCache(
            path=path, variant=variant,
            queries=queries, mutations=mutations,
            subscriptions=subscriptions, types=type_names,
            introspection_enabled=True, last_updated=time.time(),
        )

        logger.info(
            "GraphQL introspection succeeded at %s: %d queries, %d mutations",
            path, len(queries), len(mutations),
        )
        return cache
    except Exception as exc:
        logger.debug("Introspection failed at %s: %s", url, exc)
        return None


async def _detect_graphql_endpoint(
    client, url: str,
) -> tuple[bool, str]:
    """Detect if a URL is a GraphQL endpoint without introspection."""
    try:
        resp = await client.post(
            url,
            json={"query": "{ __typename }"},
            headers={"Content-Type": "application/json"},
            timeout=5.0,
        )
        if resp.status_code not in (200, 400):
            return False, ""

        ct = resp.headers.get("content-type", "")
        if "json" not in ct:
            return False, ""

        data = resp.json()
        # GraphQL endpoints return {"data": ...} or {"errors": ...}
        if "data" in data or "errors" in data:
            variant = _detect_variant_from_headers(resp.headers)
            return True, variant
        return False, ""
    except Exception:
        return False, ""


async def _probe_common_queries(
    client, url: str, cache: GraphQLSchemaCache, result: DiscoveryResult,
) -> None:
    """Probe common GraphQL queries to discover available fields."""
    for query in _COMMON_QUERIES:
        try:
            resp = await client.post(
                url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.status_code != 200:
                continue
            data = resp.json()

            # Success — field exists
            if data.get("data") and not data.get("errors"):
                # Extract field name from query
                field_match = re.search(r"\{\s*(\w+)", query)
                if field_match:
                    cache.queries.append(field_match.group(1))
                continue

            # Parse "Did you mean" suggestions from errors
            errors = data.get("errors", [])
            for err in errors:
                msg = err.get("message", "")
                for m in _DID_YOU_MEAN_RE.finditer(msg):
                    suggested = m.group(1)
                    if suggested not in cache.queries and suggested != "__typename":
                        cache.queries.append(suggested)
        except Exception:
            pass

    if cache.queries:
        logger.info("GraphQL probing found queries: %s", ", ".join(cache.queries))


def _detect_variant_from_headers(headers) -> str:
    """Detect GraphQL server variant from response headers."""
    for key, val in headers.items():
        lower_key = key.lower()
        lower_val = val.lower() if isinstance(val, str) else ""
        if "apollo" in lower_key or "apollo" in lower_val:
            return "apollo"
        if "hasura" in lower_key or "hasura" in lower_val:
            return "hasura"
    return ""


def _use_cached_schema(
    schemas: dict[str, GraphQLSchemaCache], result: DiscoveryResult,
) -> bool:
    """Use cached GraphQL schema if available and fresh (< 1 hour)."""
    for path, cache in schemas.items():
        age = time.time() - cache.last_updated
        if age < 3600:  # 1 hour
            result.endpoints.append(path)
            result.technologies.append(f"GraphQL ({cache.variant or 'cached'})")
            result.metadata["graphql_schema"] = {
                "path": path,
                "queries": cache.queries,
                "mutations": cache.mutations,
                "cached": True,
            }
            logger.info("Using cached GraphQL schema for %s", path)
            return True
    return False


def _parse_schema_file(
    schema_path: str, result: DiscoveryResult,
    learnings=None,
) -> None:
    """Parse a user-provided GraphQL schema file (SDL or JSON)."""
    try:
        with open(schema_path, "r") as f:
            content = f.read()
    except Exception as exc:
        logger.warning("Failed to read GraphQL schema file %s: %s", schema_path, exc)
        return

    queries: list[str] = []
    mutations: list[str] = []
    types: list[str] = []

    # Try JSON introspection result
    try:
        data = json.loads(content)
        schema = data.get("data", data).get("__schema", data.get("__schema", {}))
        if schema:
            for t in schema.get("types", []):
                name = t.get("name", "")
                if name.startswith("__"):
                    continue
                types.append(name)
                if name == "Query" and t.get("fields"):
                    queries = [f["name"] for f in t["fields"]]
                elif name == "Mutation" and t.get("fields"):
                    mutations = [f["name"] for f in t["fields"]]
    except (json.JSONDecodeError, ValueError):
        # Parse as SDL
        import re as _re
        type_pattern = _re.compile(r"type\s+(Query|Mutation)\s*\{([^}]*)\}", _re.MULTILINE | _re.DOTALL)
        field_pattern = _re.compile(r"^\s*(\w+)\s*[:(]", _re.MULTILINE)
        for m in type_pattern.finditer(content):
            type_name = m.group(1)
            body = m.group(2)
            fields = field_pattern.findall(body)
            if type_name == "Query":
                queries.extend(fields)
            elif type_name == "Mutation":
                mutations.extend(fields)

    if queries or mutations:
        result.endpoints.append("/graphql")
        result.technologies.append("GraphQL (schema-file)")
        result.metadata["graphql_schema"] = {
            "path": "/graphql",
            "queries": queries,
            "mutations": mutations,
            "from_file": True,
        }

        # Cache in learnings
        if learnings is not None:
            learnings.graphql_schemas["/graphql"] = GraphQLSchemaCache(
                path="/graphql", queries=queries, mutations=mutations,
                types=types, introspection_enabled=False,
                last_updated=time.time(),
            )

        logger.info(
            "Parsed GraphQL schema file: %d queries, %d mutations",
            len(queries), len(mutations),
        )
