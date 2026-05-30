"""ASVS Compliance Auditor agent definition.

Implements the two-phase audit pipeline:
  Phase 1 (Skills): single consolidated `check_asvs_requirements` skill
                    with per-requirement dispatch registry.
  Phase 2 (LLM):    self-learning analysis with ASVS catalog context.
"""

import logging
import os
from collections.abc import Generator
from functools import lru_cache
from typing import Any

from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_context_window, get_max_findings
from shared.tools.memory_client import build_prior_context

from asvs_agent.catalog import build_catalog_context, load_catalog
from asvs_agent.config import ALL_CATEGORIES
from asvs_agent.skills import SKILL_MAP, SKILL_TOOLS

_log = logging.getLogger(__name__)


def _safe_build_prior_context(
    source_path: str,
    preloaded: list[dict[str, Any]] | None,
    max_findings: int,
) -> str:
    """Fetch prior-findings context, degrading gracefully on memory-API errors.

    A down memory service must not block audits — we log the failure and
    continue without prior context. Phase 1 skill scan is unaffected;
    Phase 2 LLM simply loses the "known issues" hint and may re-report.
    """
    try:
        return build_prior_context(
            source_path, "asvs",
            preloaded=preloaded, max_findings=max_findings,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "memory_api_unavailable source=%s err=%s — audit continues without prior context",
            source_path, exc,
        )
        return ""

# Prioritize critical chapters in the LLM context budget: V6/V7/V9/V10/V11
_CRITICAL_CHAPTERS = {"V6", "V7", "V9", "V10", "V11"}


def _req_sort_key(rid: str) -> tuple[int, ...]:
    """Numeric tuple for ASVS Shortcode (V{C}.{S}.{R}) — avoids lexical
    string sort that would rank V10 before V6."""
    try:
        return tuple(int(x) for x in rid[1:].split("."))
    except (ValueError, IndexError):
        return (999, 999, 999)


def _prioritized_req_ids(limit: int = 60) -> list[str]:
    """Select static-detectable reqs balanced across critical chapters.

    Critical = V6/V7/V9/V10/V11 (auth/session/tokens/oauth/crypto). We
    round-robin within critical chapters so the LLM sees diverse
    context instead of 60× V6 reqs. Non-critical static reqs fill
    remaining budget.
    """
    catalog = load_catalog()
    by_chapter: dict[str, list[str]] = {}
    non_critical: list[str] = []
    for rid, e in catalog.items():
        if e.get("detectability") != "static":
            continue
        ch = e.get("chapter_id", "")
        if ch in _CRITICAL_CHAPTERS:
            by_chapter.setdefault(ch, []).append(rid)
        else:
            non_critical.append(rid)
    for ch in by_chapter:
        by_chapter[ch].sort(key=_req_sort_key)
    non_critical.sort(key=_req_sort_key)

    selected: list[str] = []
    chapter_order = sorted(by_chapter, key=lambda c: int(c[1:]))
    # Round-robin across critical chapters until limit reached.
    i = 0
    while len(selected) < limit and any(by_chapter.values()):
        ch = chapter_order[i % len(chapter_order)]
        if by_chapter[ch]:
            selected.append(by_chapter[ch].pop(0))
        i += 1
        if i > limit * 10:  # safety net
            break
    # Top up with non-critical if room remains.
    for rid in non_critical:
        if len(selected) >= limit:
            break
        selected.append(rid)
    return selected


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


@lru_cache(maxsize=4)
def _build_llm_catalog_context(ctx_window: int = 32_000) -> str:
    """Build the ASVS catalog reference string injected into LLM instructions.

    Scales the catalog budget to the model's context window so small models
    (32K Ollama) see fewer reqs (~40 entries × ~2000 chars) while large
    models (200K+ Claude/Gemini) get the full 60-req ~3000-char view. The
    resulting string is a stable prefix — Anthropic/OpenAI prompt-caching
    relies on byte-level stability across audits to get cache hits.

    Cached with ``lru_cache(maxsize=4)`` so repeated audits with the same
    ctx_window reuse the exact-same string instance (and thus the same
    prompt-cache key at Anthropic).
    """
    if ctx_window <= 32_000:
        limit, max_chars = 40, 2000
    elif ctx_window <= 128_000:
        limit, max_chars = 60, 3000
    else:
        limit, max_chars = 80, 4000
    return build_catalog_context(_prioritized_req_ids(limit), max_chars=max_chars)


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
    context = _safe_build_prior_context(source_path, preloaded, max_f)

    model = os.environ.get("VULTURE_LLM_MODEL")
    # Scale catalog context to the active model's window so small local
    # models don't waste budget on requirements they won't have room to
    # analyze anyway.
    catalog_ctx = _build_llm_catalog_context(get_context_window(model))
    enhanced_instructions = INSTRUCTIONS
    if catalog_ctx:
        enhanced_instructions += (
            "\n\n## ASVS Catalog Reference\n"
            "Use this catalog data to identify requirement violations:\n\n"
            + catalog_ctx
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
        domain_label="ASVS requirements",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=enhanced_instructions,
        model=model,
        use_llm=use_llm_val if isinstance(use_llm_val, bool) else None,
        validate_use_llm=validate_use_llm_val if isinstance(validate_use_llm_val, bool) else None,
    )
