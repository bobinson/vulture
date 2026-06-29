"""XSS vulnerability scanner agent definition."""

from collections.abc import Generator
from pathlib import Path
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from xss_agent.config import ALL_CATEGORIES
from xss_agent.skills import SKILL_MAP, SKILL_TOOLS

# Instructions live in a sibling .md file so the XSS detector's pattern
# scanner doesn't match its own LLM-prompt copy (the prompt has to mention
# things like '|safe' and 'dangerouslySetInnerHTML' as detection targets,
# which would otherwise fire as critical findings on this file). The .md
# extension is excluded from CODE_EXTENSIONS in shared.tools.file_scanner.
INSTRUCTIONS = (Path(__file__).parent / "INSTRUCTIONS.md").read_text(encoding="utf-8")


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the XSS vulnerability audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(
        source_path, "xss", preloaded=preloaded, max_findings=max_f,
    )

    use_llm_val = config.get("use_llm")
    # Feature 0046: per-audit override for L5 LLM judge.
    _v = config.get("validate")
    validate_use_llm_val = _v.get("llm") if isinstance(_v, dict) else None
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="XSS categories",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
        validate_use_llm=validate_use_llm_val if isinstance(validate_use_llm_val, bool) else None,
        # 0059: honor per-audit Tier-3 toggle (config > VULTURE_LLM_TIER3 > OFF)
        llm_tier3=config.get("llm_tier3"),
    )
