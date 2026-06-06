"""Intelligent API endpoint analyzer — classify, prioritize, and deep-test endpoints.

Combines rule-based classification with LLM analysis to understand each
endpoint's role, auth requirements, and security testing priority.
Inspired by prior deployments using a mapper + strategist agent pattern.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 8.0


@dataclass
class EndpointProfile:
    """Rich profile of an API endpoint for testing prioritization."""

    path: str
    endpoint_type: str = "rest"  # rest, graphql, websocket, rpc, auth, admin, config
    methods: list[str] = field(default_factory=list)
    auth_required: bool | None = None  # None = unknown
    response_type: str = ""  # json, html, xml, text
    security_priority: int = 0  # 0=low, 1=medium, 2=high, 3=critical
    test_vectors: list[str] = field(default_factory=list)
    notes: str = ""


# Classification rules — patterns that identify endpoint types
_AUTH_PATTERNS = re.compile(
    r"/auth/|/login|/logout|/signin|/signout|/register|/signup|"
    r"/token|/oauth|/callback|/session|/password|/verify|/confirm",
    re.IGNORECASE,
)
_ADMIN_PATTERNS = re.compile(r"/admin|/manage|/dashboard", re.IGNORECASE)
_CONFIG_PATTERNS = re.compile(
    r"/config|/settings|/env|/debug|/status|/health|/info|/metrics|/version",
    re.IGNORECASE,
)
_FILE_PATTERNS = re.compile(
    r"/upload|/download|/file|/image|/media|/attachment|/export|/import",
    re.IGNORECASE,
)
_USER_DATA_PATTERNS = re.compile(
    r"/users?|/profile|/account|/me$|/preferences",
    re.IGNORECASE,
)
_PAYMENT_PATTERNS = re.compile(
    r"/payment|/checkout|/order|/cart|/stripe|/billing|/subscription",
    re.IGNORECASE,
)

# Security priority scoring
_PRIORITY_RULES = [
    (_AUTH_PATTERNS, 3, "auth", ["auth_bypass", "brute_force", "credential_stuffing"]),
    (_ADMIN_PATTERNS, 3, "admin", ["auth_bypass", "privilege_escalation", "info_disclosure"]),
    (_PAYMENT_PATTERNS, 3, "rest", ["auth_bypass", "idor", "injection"]),
    (_FILE_PATTERNS, 2, "rest", ["path_traversal", "upload_bypass", "ssrf"]),
    (_USER_DATA_PATTERNS, 2, "rest", ["idor", "auth_bypass", "info_disclosure"]),
    (_CONFIG_PATTERNS, 2, "config", ["info_disclosure", "auth_bypass", "secrets_leak"]),
]


def classify_endpoint(path: str) -> EndpointProfile:
    """Classify an endpoint using rule-based analysis."""
    profile = EndpointProfile(path=path)

    lower = path.lower()

    # GraphQL
    if "graphql" in lower or "gql" in lower:
        profile.endpoint_type = "graphql"
        profile.security_priority = 2
        profile.test_vectors = ["introspection", "injection", "dos_query", "auth_bypass"]
        return profile

    # WebSocket
    if lower.startswith("/ws") or "websocket" in lower:
        profile.endpoint_type = "websocket"
        profile.security_priority = 1
        profile.test_vectors = ["injection", "auth_bypass"]
        return profile

    # RPC
    if "/rpc" in lower or "/jsonrpc" in lower:
        profile.endpoint_type = "rpc"
        profile.security_priority = 2
        profile.test_vectors = ["method_enumeration", "injection", "auth_bypass"]
        return profile

    # Apply priority rules
    for pattern, priority, ep_type, vectors in _PRIORITY_RULES:
        if pattern.search(lower):
            profile.endpoint_type = ep_type
            profile.security_priority = max(profile.security_priority, priority)
            profile.test_vectors.extend(v for v in vectors if v not in profile.test_vectors)

    # Default REST endpoint
    if not profile.test_vectors:
        profile.endpoint_type = "rest"
        profile.security_priority = 1
        profile.test_vectors = ["auth_bypass", "injection", "info_disclosure"]

    return profile


async def analyze_endpoints(
    staging_url: str,
    api_endpoints: list[str],
) -> list[EndpointProfile]:
    """Analyze and prioritize all discovered API endpoints.

    Returns profiles sorted by security priority (highest first).
    """
    base = staging_url.rstrip("/")
    profiles: list[EndpointProfile] = []

    # Phase 1: Rule-based classification
    for ep in api_endpoints:
        profiles.append(classify_endpoint(ep))

    # Phase 2: Parallel endpoint probing to determine auth and response type
    async with httpx.AsyncClient(
        timeout=_TIMEOUT, follow_redirects=True,
    ) as client:
        tasks = [_probe_endpoint(client, base, p) for p in profiles[:40]]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Phase 3: GraphQL introspection for GraphQL endpoints
    gql_profiles = [p for p in profiles if p.endpoint_type == "graphql"]
    if gql_profiles:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, follow_redirects=True,
        ) as client:
            for gp in gql_profiles[:3]:
                await _introspect_graphql(client, base, gp)

    # Sort by priority (critical first)
    profiles.sort(key=lambda p: -p.security_priority)
    return profiles


async def _probe_endpoint(
    client: httpx.AsyncClient, base: str, profile: EndpointProfile,
) -> None:
    """Probe a single endpoint to determine auth requirements and response type."""
    try:
        resp = await client.get(
            f"{base}{profile.path}",
            headers={"Accept": "application/json"},
        )
        ct = resp.headers.get("content-type", "")

        # Determine response type
        if "json" in ct:
            profile.response_type = "json"
        elif "html" in ct:
            profile.response_type = "html"
        elif "xml" in ct:
            profile.response_type = "xml"
        else:
            profile.response_type = "text"

        # Determine auth requirements
        if resp.status_code in (401, 403):
            profile.auth_required = True
            # 401/403 on sensitive endpoints = higher priority
            if profile.security_priority < 2:
                profile.security_priority = 2
        elif resp.status_code == 200:
            profile.auth_required = False
            # 200 on auth-expected endpoints = potential bypass
            if _AUTH_PATTERNS.search(profile.path) or _ADMIN_PATTERNS.search(profile.path):
                profile.notes = "Returns 200 without auth — potential bypass"
                profile.security_priority = 3

        # Record allowed methods
        profile.methods.append("GET")

        # Check for interesting headers
        if "x-ratelimit-limit" in resp.headers:
            profile.notes += " Rate-limited."
        allow = resp.headers.get("allow", "")
        if allow:
            profile.methods = [m.strip() for m in allow.split(",")]

    except Exception:
        pass


async def _introspect_graphql(
    client: httpx.AsyncClient, base: str, profile: EndpointProfile,
) -> None:
    """Run GraphQL introspection to discover queries and mutations."""
    query = '{"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}'
    try:
        resp = await client.post(
            f"{base}{profile.path}",
            content=query,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data.get("data", {}):
                schema = data["data"]["__schema"]
                types = schema.get("types", [])
                # Count user-defined types (not __* introspection types)
                user_types = [t for t in types if not t.get("name", "").startswith("__")]
                mutation_type = schema.get("mutationType")
                profile.notes += f" GraphQL: {len(user_types)} types"
                if mutation_type:
                    profile.notes += ", mutations enabled"
                    profile.security_priority = 3  # Mutations = high risk
                profile.test_vectors.extend([
                    "batch_query", "nested_query_dos", "mutation_auth_bypass",
                ])
            elif "errors" in data:
                profile.notes += " GraphQL introspection disabled"
    except Exception:
        pass


def format_endpoint_analysis(profiles: list[EndpointProfile]) -> str:
    """Format endpoint analysis as context for LLM prompts."""
    parts = ["ENDPOINT SECURITY ANALYSIS (prioritized):"]

    priority_labels = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}

    for p in profiles[:30]:
        label = priority_labels.get(p.security_priority, "LOW")
        auth = "auth:yes" if p.auth_required else "auth:no" if p.auth_required is False else "auth:unknown"
        methods_str = ",".join(p.methods) if p.methods else "unknown"
        parts.append(
            f"  [{label}] {p.path} type={p.endpoint_type} {auth} "
            f"methods={methods_str} resp={p.response_type}"
        )
        if p.test_vectors:
            parts.append(f"    Test: {', '.join(p.test_vectors[:5])}")
        if p.notes:
            parts.append(f"    Notes: {p.notes.strip()}")

    return "\n".join(parts)
