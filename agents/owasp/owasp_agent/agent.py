"""OWASP Security agent definition."""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from owasp_agent.config import ALL_CATEGORIES
from owasp_agent.skills import SKILL_MAP, SKILL_TOOLS

INSTRUCTIONS = """You are an OWASP Security Auditor. Analyze source code for OWASP Top 10 vulnerabilities:
A01 Access Control, A02 Crypto Failures, A03 Injection, A04 Insecure Design,
A05 Security Misconfiguration, A06 Vulnerable Components, A07 Auth Failures,
A08 Data Integrity, A09 Logging Failures, A10 SSRF.
Report findings with severity, affected file, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the OWASP security audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "owasp", preloaded=preloaded, max_findings=max_f)

    use_llm_val = config.get("use_llm")
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="OWASP categories",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
    )
