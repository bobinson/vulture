"""Verification-scoped learning store for prove agent.

The full cross-session learning store (with persistence, endpoint behaviors,
GraphQL schemas, source routes, etc.) now lives in discover_agent.learning_store.

This module keeps only the dataclass definitions needed by prove_agent internals
(api_prober.py, strategies) so prove has zero dependency on discover_agent at
the Python import level. Prove calls discover via HTTP, not via import.
"""

import time
from dataclasses import dataclass, field


@dataclass
class EndpointBehavior:
    """Observed behavior of an API endpoint."""

    path: str
    methods_allowed: list[str] = field(default_factory=list)
    auth_required: bool = False
    response_types: list[str] = field(default_factory=list)
    rate_limited: bool = False
    vulnerabilities_found: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    last_tested: float = 0.0


@dataclass
class ProbePattern:
    """A successful probe pattern that found a vulnerability."""

    finding_category: str
    method: str
    url_pattern: str
    headers: dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    success_count: int = 0
    last_used: float = 0.0


@dataclass
class GraphQLSchemaCache:
    """Cached GraphQL schema information per endpoint path."""

    path: str
    variant: str = ""
    queries: list[str] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    subscriptions: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)
    introspection_enabled: bool = False
    last_updated: float = 0.0


@dataclass
class SessionLearnings:
    """Session-scoped learnings for prove agent.

    This is a minimal in-memory version. The full persistent store
    now lives in discover_agent.learning_store.
    """

    insights: list[str] = field(default_factory=list)
    endpoint_behaviors: dict[str, EndpointBehavior] = field(default_factory=dict)
    successful_probes: list[ProbePattern] = field(default_factory=list)
    auth_endpoints: list[str] = field(default_factory=list)
    auth_type: str = ""
    technologies: list[str] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)
    total_findings_tested: int = 0
    verified_count: int = 0
    false_positive_count: int = 0
    last_session: float = 0.0
    graphql_schemas: dict[str, GraphQLSchemaCache] = field(default_factory=dict)
    source_routes: list[str] = field(default_factory=list)
    known_404_paths: list[str] = field(default_factory=list)
    reachable_endpoints: list[str] = field(default_factory=list)
    target_protocols: dict[str, bool] = field(default_factory=dict)
    primary_protocol: str = ""
    grpc_services: list[str] = field(default_factory=list)
    blockchain_chain: str = ""
    mqtt_topics: list[str] = field(default_factory=list)
    soap_endpoints: list[str] = field(default_factory=list)
    sse_endpoints: list[str] = field(default_factory=list)
    infra_ports: list[int] = field(default_factory=list)


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

    if learnings.successful_probes:
        parts.append("Successful probe patterns from prior sessions:")
        for p in sorted(learnings.successful_probes, key=lambda x: -x.success_count)[:10]:
            parts.append(f"  {p.method} {p.url_pattern} ({p.finding_category}, used {p.success_count}x)")

    known_vulns = [
        (ep, eb) for ep, eb in learnings.endpoint_behaviors.items()
        if eb.vulnerabilities_found
    ]
    if known_vulns:
        parts.append("Known vulnerable endpoints:")
        for ep, eb in known_vulns[:10]:
            parts.append(f"  {ep}: {', '.join(eb.vulnerabilities_found)}")

    if learnings.insights:
        parts.append("Prior session insights:")
        for insight in learnings.insights[-10:]:
            parts.append(f"  - {insight}")

    return "\n".join(parts) if parts else ""


def record_known_404(learnings: SessionLearnings, path: str) -> None:
    """Record a path that returned 404."""
    if path not in learnings.known_404_paths:
        learnings.known_404_paths.append(path)
    if path in learnings.reachable_endpoints:
        learnings.reachable_endpoints.remove(path)


def record_reachable_endpoint(learnings: SessionLearnings, path: str) -> None:
    """Record a path confirmed reachable."""
    if path not in learnings.reachable_endpoints:
        learnings.reachable_endpoints.append(path)
    if path in learnings.known_404_paths:
        learnings.known_404_paths.remove(path)
