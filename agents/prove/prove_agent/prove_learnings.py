"""Slim verification-only learning store for prove agent.

Full cross-session learnings (discovery, endpoint behaviors, GraphQL schemas,
source routes, etc.) now live in discover_agent.learning_store. Prove keeps
only session-scoped probe patterns and cross-finding insights.
"""

import time
from dataclasses import dataclass, field

from prove_agent.learning_store import ProbePattern


@dataclass
class ProveSessionLearnings:
    """Session-scoped learnings for the prove verification pipeline.

    Unlike the full SessionLearnings in discover_agent.learning_store,
    this only tracks probe patterns and cross-finding insights within
    a single prove session. Not persisted to disk.
    """

    insights: list[str] = field(default_factory=list)
    successful_probes: list[ProbePattern] = field(default_factory=list)
    total_findings_tested: int = 0
    verified_count: int = 0


def record_successful_probe(
    learnings: ProveSessionLearnings,
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
