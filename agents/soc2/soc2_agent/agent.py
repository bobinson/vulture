"""SOC2 Compliance agent definition."""

from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from soc2_agent.clauses import CLAUSE_MAP
from soc2_agent.config import ALL_CLAUSES
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
    clauses = config.get("clauses", ALL_CLAUSES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "soc2", preloaded=preloaded, max_findings=max_f)

    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=clauses,
        skill_map=CLAUSE_MAP,
        domain_label="SOC2 clauses",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
    )
