"""DO-178C Compliance audit agent definition."""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context
from shared.transport.event_emitter import AgUiEventEmitter

from do178c_agent.config import ALL_CATEGORIES, dal_skip
from do178c_agent.skills import SKILL_MAP, SKILL_TOOLS

INSTRUCTIONS = """You are a DO-178C Software Assurance Auditor. Analyze source code against
RTCA DO-178C/ED-12C objectives for the specified Design Assurance Level (DAL).
Focus on: dead/deactivated code, MC/DC structural coverage gaps, recursion and
unbounded loops, dynamic memory allocation, requirements traceability, and
deterministic timing. Report findings with severity appropriate to the DAL level,
affected file, DO-178C table/objective reference, and actionable recommendations."""


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the DO-178C compliance audit and yield SSE events."""
    dal = config.get("dal_level", "C")
    requested = config.get("categories", ALL_CATEGORIES)
    categories = [c for c in requested if not dal_skip(dal, c)]

    # DAL E (or any config that filters out all categories) has no applicable
    # objectives. Emit start/result/end with zero findings instead of passing
    # an empty category list to run_combined_audit.
    if not categories:
        emitter = AgUiEventEmitter(run_id)
        yield emitter.run_started()
        yield emitter.text_message(
            f"DAL {dal}: no applicable DO-178C objectives — audit complete."
        )
        yield emitter.result_event(findings=[], summary="No applicable objectives for this DAL.", score=100.0)
        yield emitter.run_finished()
        return

    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "do178c", preloaded=preloaded, max_findings=max_f)

    use_llm_val = config.get("use_llm")
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="DO-178C objectives",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=INSTRUCTIONS,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
    )
