"""ASVS Compliance Auditor agent definition.

Implements the two-phase audit pipeline:
  Phase 1 (Skills): single consolidated `check_asvs_requirements` skill
                    with per-requirement dispatch registry.
  Phase 2 (LLM):    self-learning analysis with ASVS catalog context.
"""

import os
from collections.abc import Generator
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from asvs_agent.catalog import build_catalog_context, load_catalog
from asvs_agent.config import ALL_CATEGORIES
from asvs_agent.skills import SKILL_MAP, SKILL_TOOLS

# Prioritize critical chapters in the LLM context budget: V6/V7/V9/V10/V11
_CRITICAL_CHAPTERS = {"V6", "V7", "V9", "V10", "V11"}


def _prioritized_req_ids(limit: int = 60) -> list[str]:
    catalog = load_catalog()
    prio: list[tuple[int, str]] = []
    for rid, e in catalog.items():
        if e.get("detectability") != "static":
            continue
        rank = 0 if e.get("chapter_id") in _CRITICAL_CHAPTERS else 1
        prio.append((rank, rid))
    prio.sort()
    return [rid for _, rid in prio[:limit]]


INSTRUCTIONS = """You are an ASVS (Application Security Verification Standard)
auditor using OWASP ASVS v5.0.0 — 345 requirements across 17 chapters and 3
verification levels (L1, L2, L3).

## Your Role (LLM Phase)

The skill phase already ran a deterministic regex-based audit over the
source tree. You augment it with deeper semantic analysis that regex
cannot perform:

1. **Data-flow tracing**: follow user input through function calls,
   assignments, and returns to identify ASVS violations spanning
   multiple lines.
2. **Cross-file analysis**: detect violations that span multiple files
   (e.g., an auth-required middleware omitted from a route registration).
3. **Framework-aware detection**: understand Django/Flask/Express/Spring
   patterns and map them to ASVS requirements.
4. **Confidence calibration**: rate each finding's confidence.
5. **Novel pattern discovery**: find violation variants regex missed.

## Self-Learning Protocol

When prior findings are provided:
- SKIP known issues already in prior context.
- BOOST confidence on patterns similar to previously verified findings.
- DEMOTE confidence on patterns matching previously false-positive ones.
- Report only genuinely NEW findings.

## Reporting Format

For each finding, provide:
- severity: critical / high / medium / low.
- category: ASVS-V{X}.{Y}.{Z} (use the most specific ASVS req ID).
- title: concise description of the violation.
- description: detailed explanation with data-flow trace.
- file_path, line_start, line_end.
- recommendation: actionable fix.
- linked_cwe (optional): if the req maps to a CWE in our crosswalk, cite it.

Cite ASVS req IDs in the form 'ASVS-V{X}.{Y}.{Z}' so findings can be
grouped by chapter in the frontend.
"""


def _build_llm_catalog_context() -> str:
    return build_catalog_context(_prioritized_req_ids(60), max_chars=3000)


def run_audit(
    run_id: str,
    source_path: str,
    config: dict,
    prior_findings: list[dict[str, Any]] | None = None,
) -> Generator[str, None, None]:
    """Execute the ASVS audit and yield SSE events."""
    categories = config.get("categories", ALL_CATEGORIES)
    preloaded = prior_findings if prior_findings else None
    max_f = get_max_findings()
    context = build_prior_context(source_path, "asvs", preloaded=preloaded, max_findings=max_f)

    catalog_ctx = _build_llm_catalog_context()
    enhanced_instructions = INSTRUCTIONS
    if catalog_ctx:
        enhanced_instructions += (
            "\n\n## ASVS Catalog Reference\n"
            "Use this catalog data to identify requirement violations:\n\n"
            + catalog_ctx
        )

    use_llm_val = config.get("use_llm")
    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="ASVS requirements",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=enhanced_instructions,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
    )
