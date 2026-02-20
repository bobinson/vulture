"""CWE Weakness Auditor agent definition."""

from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from cwe_agent.config import ALL_CATEGORIES
from cwe_agent.skills import SKILL_MAP, SKILL_TOOLS

INSTRUCTIONS = """You are a CWE (Common Weakness Enumeration) Security Auditor using CWE v4.19.1.
Analyze source code for weaknesses cataloged in the CWE database.
Check for: injection (CWE-78/79/89/94), buffer handling (CWE-119/120/125/787),
authentication (CWE-287/306/798), cryptography (CWE-326/327/330),
input validation (CWE-20/22/434/611), resource management (CWE-400/404/476/770),
information exposure (CWE-200/209/532), access control (CWE-269/284/862/863),
error handling (CWE-252/754/755), and concurrency (CWE-362/367).
Report findings with severity, CWE ID, affected file, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the CWE weakness audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "cwe", preloaded=preloaded, max_findings=max_f)

    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="CWE categories",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
    )
