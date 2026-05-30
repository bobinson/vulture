"""NIST SSDF v1.1 agent definition."""

from collections.abc import Generator
from typing import Any

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
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "ssdf", preloaded=preloaded, max_findings=max_f)

    use_llm_val = config.get("use_llm")
    # Feature 0046: per-audit override for L5 LLM judge.
    _v = config.get("validate")
    validate_use_llm_val = _v.get("llm") if isinstance(_v, dict) else None
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="SSDF practice groups",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
        validate_use_llm=validate_use_llm_val if isinstance(validate_use_llm_val, bool) else None,
    )
