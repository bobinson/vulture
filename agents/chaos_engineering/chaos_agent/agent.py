"""Chaos Engineering agent definition."""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_kwargs import shared_audit_kwargs
from shared.audit_runner import run_combined_audit
from shared.llm.provider import (
    get_max_findings,  # noqa: F401  (module attribute: the fleet tests monkeypatch it)
)
from shared.prompt.manifests.generate import domain_instructions
from shared.tools.memory_client import (
    build_prior_context,  # noqa: F401  (module attribute: the fleet tests monkeypatch it)
)

from chaos_agent.config import ALL_CATEGORIES
from chaos_agent.skills import SKILL_MAP, SKILL_TOOLS

# NOT the prompt source any more — feature 0089 Phase 2.5 moved that to the
# fragment `domains/chaos`, named at the `run_combined_audit` call below and
# rendered by `domain_instructions()` (see its note in
# `shared/prompt/manifests/generate.py`). This literal stays as the
# transcription's INDEPENDENT oracle: `test_0089_manifest_generate.py` reads it
# out of this file by AST and asserts the fragment equals it byte for byte, so
# it is the one assertion that can still see the fragment drift from the prompt
# this agent shipped. Do not reword, reformat or delete it: edit the fragment,
# then this, together.
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

    _shared = shared_audit_kwargs(config, source_path, prior_findings, "chaos")
    
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="resilience categories",
        **_shared,
        skill_tools=SKILL_TOOLS,
        instructions=domain_instructions(
            "domains/chaos",
        ),
        model=os.environ.get("VULTURE_LLM_MODEL"),
        # Conform BOTH tiers to the vocabulary /info advertises. The skill
        # tier violated it too: measured on one target this agent emitted
        # suffixed and separator-variant forms of its own declared names.
        category_enum=frozenset(ALL_CATEGORIES),
    )
