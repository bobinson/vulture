"""XSS vulnerability scanner agent definition."""

from collections.abc import Generator
from pathlib import Path
from typing import Any

from shared.audit_kwargs import shared_audit_kwargs
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

    _shared = shared_audit_kwargs(config, source_path, prior_findings, "xss")
    
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="XSS categories",
        **_shared,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
    )
