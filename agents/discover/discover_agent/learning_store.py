"""Cross-session learning persistence for prove agent.

Stores and retrieves learnings from previous prove sessions so the agent
improves over time. Inspired by prior deployments using a retrospective pattern:
  execute → reflect → extract learnings → persist → load next session.

Storage: ~/.vulture/learnings/{hostname}.json
"""

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_LEARNINGS_DIR = os.environ.get(
    "VULTURE_LEARNINGS_DIR",
    os.path.join(os.path.expanduser("~"), ".vulture", "learnings"),
)

_MAX_LEARNINGS = 200  # Cap stored learnings per host
_MAX_ENDPOINT_BEHAVIORS = 500
_MAX_PROBE_PATTERNS = 100


@dataclass
class EndpointBehavior:
    """Observed behavior of an API endpoint across sessions."""

    path: str
    methods_allowed: list[str] = field(default_factory=list)
    auth_required: bool = False
    response_types: list[str] = field(default_factory=list)  # json, html, xml
    rate_limited: bool = False
    vulnerabilities_found: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    last_tested: float = 0.0


@dataclass
class ProbePattern:
    """A successful probe pattern that found a vulnerability."""

    finding_category: str
    method: str
    url_pattern: str  # e.g. "/api/auth/*" or "/api/users/{id}"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    success_count: int = 0
    last_used: float = 0.0


@dataclass
class GraphQLSchemaCache:
    """Cached GraphQL schema information per endpoint path."""

    path: str
    variant: str = ""  # apollo, hasura, relay
    queries: list[str] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    subscriptions: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)
    introspection_enabled: bool = False
    last_updated: float = 0.0


@dataclass
class SessionLearnings:
    """Learnings from a single prove session."""

    # General insights (text)
    insights: list[str] = field(default_factory=list)
    # Endpoint behavior observations
    endpoint_behaviors: dict[str, EndpointBehavior] = field(default_factory=dict)
    # Successful probe patterns
    successful_probes: list[ProbePattern] = field(default_factory=list)
    # Auth flow information
    auth_endpoints: list[str] = field(default_factory=list)
    auth_type: str = ""  # jwt, session, api_key, oauth
    # Technology stack insights
    technologies: list[str] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)
    # Stats
    total_findings_tested: int = 0
    verified_count: int = 0
    false_positive_count: int = 0
    last_session: float = 0.0
    # GraphQL schema knowledge (per endpoint path)
    graphql_schemas: dict[str, GraphQLSchemaCache] = field(default_factory=dict)
    # Source-code-discovered routes (persisted for warm start)
    source_routes: list[str] = field(default_factory=list)
    # Confirmed 404 paths (skip on next session)
    known_404_paths: list[str] = field(default_factory=list)
    # Confirmed reachable endpoints
    reachable_endpoints: list[str] = field(default_factory=list)
    # Detected protocol capabilities for warm start
    target_protocols: dict[str, bool] = field(default_factory=dict)
    primary_protocol: str = ""
    # Extended discovery learnings
    grpc_services: list[str] = field(default_factory=list)
    blockchain_chain: str = ""
    mqtt_topics: list[str] = field(default_factory=list)
    soap_endpoints: list[str] = field(default_factory=list)
    sse_endpoints: list[str] = field(default_factory=list)
    infra_ports: list[int] = field(default_factory=list)


def _learnings_path(staging_url: str) -> Path:
    hostname = urlparse(staging_url).hostname or "unknown"
    return Path(_LEARNINGS_DIR) / f"{hostname}.json"


def load_learnings(staging_url: str) -> SessionLearnings:
    """Load accumulated learnings for a target host."""
    path = _learnings_path(staging_url)
    if not path.exists():
        return SessionLearnings()
    try:
        data = json.loads(path.read_text())
        learnings = SessionLearnings()
        learnings.insights = data.get("insights", [])
        learnings.auth_endpoints = data.get("auth_endpoints", [])
        learnings.auth_type = data.get("auth_type", "")
        learnings.technologies = data.get("technologies", [])
        learnings.framework_hints = data.get("framework_hints", [])
        learnings.total_findings_tested = data.get("total_findings_tested", 0)
        learnings.verified_count = data.get("verified_count", 0)
        learnings.false_positive_count = data.get("false_positive_count", 0)
        learnings.last_session = data.get("last_session", 0.0)

        for path_key, eb_data in data.get("endpoint_behaviors", {}).items():
            learnings.endpoint_behaviors[path_key] = EndpointBehavior(
                path=eb_data.get("path", path_key),
                methods_allowed=eb_data.get("methods_allowed", []),
                auth_required=eb_data.get("auth_required", False),
                response_types=eb_data.get("response_types", []),
                rate_limited=eb_data.get("rate_limited", False),
                vulnerabilities_found=eb_data.get("vulnerabilities_found", []),
                false_positives=eb_data.get("false_positives", []),
                last_tested=eb_data.get("last_tested", 0.0),
            )

        for pp_data in data.get("successful_probes", []):
            learnings.successful_probes.append(ProbePattern(
                finding_category=pp_data.get("finding_category", ""),
                method=pp_data.get("method", "GET"),
                url_pattern=pp_data.get("url_pattern", ""),
                headers=pp_data.get("headers", {}),
                body_template=pp_data.get("body_template", ""),
                success_count=pp_data.get("success_count", 0),
                last_used=pp_data.get("last_used", 0.0),
            ))

        # Deserialize GraphQL schema caches
        for gql_path, gql_data in data.get("graphql_schemas", {}).items():
            learnings.graphql_schemas[gql_path] = GraphQLSchemaCache(
                path=gql_data.get("path", gql_path),
                variant=gql_data.get("variant", ""),
                queries=gql_data.get("queries", []),
                mutations=gql_data.get("mutations", []),
                subscriptions=gql_data.get("subscriptions", []),
                types=gql_data.get("types", []),
                introspection_enabled=gql_data.get("introspection_enabled", False),
                last_updated=gql_data.get("last_updated", 0.0),
            )

        # Deserialize new list fields
        learnings.source_routes = data.get("source_routes", [])
        learnings.known_404_paths = data.get("known_404_paths", [])
        learnings.reachable_endpoints = data.get("reachable_endpoints", [])
        learnings.target_protocols = data.get("target_protocols", {})
        learnings.primary_protocol = data.get("primary_protocol", "")

        # Extended discovery fields
        learnings.grpc_services = data.get("grpc_services", [])
        learnings.blockchain_chain = data.get("blockchain_chain", "")
        learnings.mqtt_topics = data.get("mqtt_topics", [])
        learnings.soap_endpoints = data.get("soap_endpoints", [])
        learnings.sse_endpoints = data.get("sse_endpoints", [])
        learnings.infra_ports = data.get("infra_ports", [])

        logger.info(
            "Loaded learnings: %d insights, %d endpoint behaviors, %d probes",
            len(learnings.insights),
            len(learnings.endpoint_behaviors),
            len(learnings.successful_probes),
        )
        return learnings
    except Exception as exc:
        logger.warning("Failed to load learnings: %s", exc)
        return SessionLearnings()


def save_learnings(staging_url: str, learnings: SessionLearnings) -> None:
    """Persist learnings for a target host."""
    path = _learnings_path(staging_url)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Cap collections to prevent unbounded growth
        learnings.insights = learnings.insights[-_MAX_LEARNINGS:]
        if len(learnings.endpoint_behaviors) > _MAX_ENDPOINT_BEHAVIORS:
            # Keep most recently tested
            sorted_eps = sorted(
                learnings.endpoint_behaviors.items(),
                key=lambda x: x[1].last_tested,
                reverse=True,
            )
            learnings.endpoint_behaviors = dict(sorted_eps[:_MAX_ENDPOINT_BEHAVIORS])
        learnings.successful_probes = learnings.successful_probes[-_MAX_PROBE_PATTERNS:]
        learnings.last_session = time.time()

        # Cap new list fields
        learnings.source_routes = learnings.source_routes[-500:]
        learnings.known_404_paths = learnings.known_404_paths[-500:]
        learnings.reachable_endpoints = learnings.reachable_endpoints[-500:]
        learnings.grpc_services = learnings.grpc_services[-100:]
        learnings.mqtt_topics = learnings.mqtt_topics[-100:]
        learnings.soap_endpoints = learnings.soap_endpoints[-100:]
        learnings.sse_endpoints = learnings.sse_endpoints[-100:]
        learnings.infra_ports = learnings.infra_ports[-100:]

        data = {
            "insights": learnings.insights,
            "endpoint_behaviors": {
                k: asdict(v) for k, v in learnings.endpoint_behaviors.items()
            },
            "successful_probes": [asdict(p) for p in learnings.successful_probes],
            "auth_endpoints": learnings.auth_endpoints,
            "auth_type": learnings.auth_type,
            "technologies": learnings.technologies,
            "framework_hints": learnings.framework_hints,
            "total_findings_tested": learnings.total_findings_tested,
            "verified_count": learnings.verified_count,
            "false_positive_count": learnings.false_positive_count,
            "last_session": learnings.last_session,
            "graphql_schemas": {
                k: asdict(v) for k, v in learnings.graphql_schemas.items()
            },
            "source_routes": learnings.source_routes,
            "known_404_paths": learnings.known_404_paths,
            "reachable_endpoints": learnings.reachable_endpoints,
            "target_protocols": learnings.target_protocols,
            "primary_protocol": learnings.primary_protocol,
            "grpc_services": learnings.grpc_services,
            "blockchain_chain": learnings.blockchain_chain,
            "mqtt_topics": learnings.mqtt_topics,
            "soap_endpoints": learnings.soap_endpoints,
            "sse_endpoints": learnings.sse_endpoints,
            "infra_ports": learnings.infra_ports,
        }
        path.write_text(json.dumps(data, indent=2))
        logger.info("Saved learnings to %s", path)
    except Exception as exc:
        logger.warning("Failed to save learnings: %s", exc)


def record_endpoint_behavior(
    learnings: SessionLearnings,
    path: str,
    *,
    method: str = "",
    auth_required: bool | None = None,
    response_type: str = "",
    rate_limited: bool | None = None,
    vulnerability: str = "",
    false_positive: str = "",
) -> None:
    """Record observed behavior for an endpoint."""
    eb = learnings.endpoint_behaviors.get(path)
    if not eb:
        eb = EndpointBehavior(path=path)
        learnings.endpoint_behaviors[path] = eb

    if method and method not in eb.methods_allowed:
        eb.methods_allowed.append(method)
    if auth_required is not None:
        eb.auth_required = auth_required
    if response_type and response_type not in eb.response_types:
        eb.response_types.append(response_type)
    if rate_limited is not None:
        eb.rate_limited = rate_limited
    if vulnerability and vulnerability not in eb.vulnerabilities_found:
        eb.vulnerabilities_found.append(vulnerability)
    if false_positive and false_positive not in eb.false_positives:
        eb.false_positives.append(false_positive)
    eb.last_tested = time.time()


def record_successful_probe(
    learnings: SessionLearnings,
    finding_category: str,
    method: str,
    url_pattern: str,
    headers: dict[str, str] | None = None,
    body_template: str = "",
) -> None:
    """Record a probe pattern that successfully found a vulnerability."""
    # Check if pattern already exists
    for p in learnings.successful_probes:
        if p.url_pattern == url_pattern and p.method == method:
            p.success_count += 1
            p.last_used = time.time()
            return

    learnings.successful_probes.append(ProbePattern(
        finding_category=finding_category,
        method=method,
        url_pattern=url_pattern,
        headers=headers or {},
        body_template=body_template,
        success_count=1,
        last_used=time.time(),
    ))


def format_learnings_context(learnings: SessionLearnings) -> str:
    """Format learnings as context for LLM prompts."""
    parts = []

    if learnings.auth_type:
        parts.append(f"Auth type: {learnings.auth_type}")
    if learnings.auth_endpoints:
        parts.append("Auth endpoints: " + ", ".join(learnings.auth_endpoints[:5]))
    if learnings.technologies:
        parts.append("Tech stack: " + ", ".join(learnings.technologies))
    if learnings.framework_hints:
        parts.append("Framework hints: " + ", ".join(learnings.framework_hints[:5]))

    if learnings.successful_probes:
        parts.append("Successful probe patterns from prior sessions:")
        for p in sorted(learnings.successful_probes, key=lambda x: -x.success_count)[:10]:
            parts.append(f"  {p.method} {p.url_pattern} ({p.finding_category}, used {p.success_count}x)")

    # Endpoint insights
    known_vulns = [
        (ep, eb) for ep, eb in learnings.endpoint_behaviors.items()
        if eb.vulnerabilities_found
    ]
    if known_vulns:
        parts.append("Known vulnerable endpoints:")
        for ep, eb in known_vulns[:10]:
            parts.append(f"  {ep}: {', '.join(eb.vulnerabilities_found)}")

    known_fps = [
        (ep, eb) for ep, eb in learnings.endpoint_behaviors.items()
        if eb.false_positives
    ]
    if known_fps:
        parts.append("Known false positives (skip these):")
        for ep, eb in known_fps[:10]:
            parts.append(f"  {ep}: {', '.join(eb.false_positives)}")

    if learnings.insights:
        parts.append("Prior session insights:")
        for insight in learnings.insights[-10:]:
            parts.append(f"  - {insight}")

    return "\n".join(parts) if parts else ""


def record_known_404(learnings: SessionLearnings, path: str) -> None:
    """Record a path that returned 404 so it can be skipped next session."""
    if path not in learnings.known_404_paths:
        learnings.known_404_paths.append(path)
    # Remove from reachable if it was previously reachable
    if path in learnings.reachable_endpoints:
        learnings.reachable_endpoints.remove(path)


def record_reachable_endpoint(learnings: SessionLearnings, path: str) -> None:
    """Record a path confirmed reachable (non-404 response)."""
    if path not in learnings.reachable_endpoints:
        learnings.reachable_endpoints.append(path)
    # Remove from known 404s if previously marked
    if path in learnings.known_404_paths:
        learnings.known_404_paths.remove(path)
