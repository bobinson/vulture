"""Chaos Engineering agent definition."""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from chaos_agent.config import ALL_CATEGORIES
from chaos_agent.skills import SKILL_MAP, SKILL_TOOLS

INSTRUCTIONS = """You are a Chaos Engineering Auditor. Analyze source code for resilience patterns.
Check for: retry logic, circuit breakers, timeout handling, fallback mechanisms, and blast radius isolation.
Report findings with severity, affected file, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the chaos engineering audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "chaos", preloaded=preloaded, max_findings=max_f)

    use_llm_val = config.get("use_llm")
    # Feature 0046: per-audit override for L5 LLM judge.
    _v = config.get("validate")
    validate_use_llm_val = _v.get("llm") if isinstance(_v, dict) else None
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="resilience categories",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
        validate_use_llm=validate_use_llm_val if isinstance(validate_use_llm_val, bool) else None,
    )
