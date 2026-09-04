"""SOC2 Compliance agent definition."""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_kwargs import shared_audit_kwargs
from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from soc2_agent.clauses import SKILL_MAP
from soc2_agent.config import ALL_CATEGORIES
from soc2_agent.skills import SKILL_TOOLS

INSTRUCTIONS = """You are a SOC2 Compliance Auditor. Analyze source code for SOC2 trust service criteria.
Check for: access logging (CC6), encryption practices, change management (CC8),
monitoring capabilities (CC7), and data retention policies.
Report findings with severity, affected file, compliance reference, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the SOC2 compliance audit and yield SSE events."""
    # `clauses` is the canonical schema field (SOC2 domain term); keep
    # `categories` as a backward-compat fallback for any older payloads.
    categories = config.get("clauses", config.get("categories", ALL_CATEGORIES))

    _shared = shared_audit_kwargs(config, source_path, prior_findings, "soc2")
    
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="SOC2 clauses",
        **_shared,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        # Conform BOTH tiers to the vocabulary /info advertises. The skill
        # tier violated it too: measured on one target this agent emitted
        # suffixed and separator-variant forms of its own declared names.
        category_enum=frozenset(ALL_CATEGORIES),
    )
