"""NIST SSDF v1.1 agent definition."""

from collections.abc import Generator
from typing import Any

from shared.audit_kwargs import shared_audit_kwargs
from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from ssdf_agent.config import ALL_CATEGORIES
from ssdf_agent.practice_groups import SKILL_MAP
from ssdf_agent.skills import SKILL_TOOLS

INSTRUCTIONS = """You are a NIST SP 800-218 SSDF v1.1 Auditor. Analyze source code and project artifacts
for Secure Software Development Framework compliance.
Check for: security policies (PO), code protection (PS), secure development practices (PW),
and vulnerability response processes (RV).
Report findings with severity, affected file, SSDF practice reference, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the SSDF compliance audit and yield SSE events."""
    # `practice_groups` is the canonical schema field (SSDF domain term);
    # keep `categories` as a backward-compat fallback for older payloads.
    categories = config.get("practice_groups", config.get("categories", ALL_CATEGORIES))

    _shared = shared_audit_kwargs(config, source_path, prior_findings, "ssdf")
    
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="SSDF practice groups",
        **_shared,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        # Conform emitted categories to the vocabulary /info advertises.
        # Measured: 30 of 56 rows (including all 9 skill rows) carried a
        # category outside this set; the specific practice id is kept in
        # `practice` so nothing is lost.
        category_enum=frozenset(ALL_CATEGORIES),
    )
