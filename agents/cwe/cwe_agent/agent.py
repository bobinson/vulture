"""CWE Weakness Auditor agent definition.

Implements a two-phase audit pipeline:
  Phase 1 (Skills): 22 concurrent skills including catalog-driven detector
  Phase 2 (LLM): Self-learning analysis with catalog context injection
"""

import asyncio
import os
from collections.abc import Generator
from typing import Any

from shared.llm import health as _health
from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context

from cwe_agent.catalog import build_catalog_context, get_static_detectable
from cwe_agent.config import ALL_CATEGORIES
from cwe_agent.skills import SKILL_MAP, SKILL_TOOLS

# Collect CWE IDs covered by catalog for LLM context
_CATALOG_CWE_IDS = [e["id"] for e in get_static_detectable(min_score=0.3)][:80]

INSTRUCTIONS = """You are a CWE (Common Weakness Enumeration) Security Auditor using CWE v4.19.1.

## Catalog Coverage
The CWE v4.19.1 catalog contains 846 software-relevant weaknesses. The skill phase
already ran 22 concurrent detectors covering:
- 21 dedicated skills with hand-crafted regex patterns (~86 CWE IDs)
- 1 catalog-driven generic detector using keyword matching (~400+ CWE IDs)

## Your Role (LLM Phase)
You augment the skill phase with deeper semantic analysis that regex cannot perform:
1. **Data flow tracing**: Follow user input through function calls, assignments, returns
2. **Cross-file analysis**: Detect weaknesses spanning multiple files (e.g., auth bypass)
3. **Context-aware detection**: Understand framework patterns, ORM usage, middleware chains
4. **Confidence calibration**: Rate each finding's confidence based on catalog metadata
5. **Novel pattern discovery**: Find weakness variants not covered by skill regex

## Self-Learning Protocol
When prior findings are provided:
- SKIP known issues (already reported in prior context)
- BOOST confidence when you see patterns similar to previously confirmed findings
- DEMOTE confidence when patterns match previously false-positive findings
- LEARN from prior finding descriptions to refine your detection heuristics
- Report only genuinely NEW findings not covered by the skill phase

## CWE Categories (22)
- Injection: CWE-78/79/89/94/113/134/918/1321/1427
- Buffer handling: CWE-120/125/190/416/787
- Authentication: CWE-287/306/521/798
- Cryptography: CWE-326/327/328/330
- Input validation: CWE-20/22/352/434/502/611
- Resource management: CWE-400/404/467/476/770
- Information exposure: CWE-200/209/312/532
- Access control: CWE-269/639/862/863
- Error handling: CWE-252/390/754/755
- Concurrency: CWE-362/367/662/833
- Web security: CWE-113/384/601/614/1004
- Configuration: CWE-295/319/326/668/732/1188/1295
- Dependency security: CWE-494/506/829/1104
- Data handling: CWE-134/681/704/838/1321
- Memory safety: CWE-401/415/457/467/562/824
- Path equivalence: CWE-42/43/46/48/49/50/51/52/54/55/56/57 (filename string-equivalence tricks)
- Divide by zero: CWE-369 (C/C++/Go/Rust)
- Dangerous function: CWE-242/676 (gets/strcpy/system/eval family)
- Insufficient logging: CWE-778 (except/catch without log)
- Uncaught exception: CWE-248 (Java throws Exception / Python except Exception: pass)
- Weak entropy: CWE-331/332 (random.random/Math.random flowing into token|key|nonce...)
- Catalog generic: 400+ additional CWEs via keyword matching + rollup for Class/Pillar parents

## Reporting Format
For each finding, provide:
- severity: critical/high/medium/low based on catalog consequence impact
- category: CWE-XXX (use the most specific applicable CWE ID)
- title: Concise description of the weakness
- description: Detailed explanation with data flow trace
- file_path: Affected file
- line_start/line_end: Location
- recommendation: Actionable fix with code example when possible"""


def _build_llm_catalog_context() -> str:
    """Build catalog context section for LLM instructions."""
    return build_catalog_context(_CATALOG_CWE_IDS, max_chars=3000)


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("true", "1", "yes")


def _probe_llm_health() -> Any:
    """Run the async provider health probe from this sync generator.

    Feature 0057 P1a fix: CWE runs the LLM phase by default and has ALREADY
    decided it wants the LLM — so the probe must key on *provider/model
    availability*, NOT on the global ``VULTURE_USE_LLM`` flag (which defaults
    ``false`` for the agent-cwe service). ``check_llm_health`` short-circuits
    to ``provider=disabled / reachable=False`` whenever ``VULTURE_USE_LLM !=
    "true"`` (health.py); left alone, that would silently keep CWE skills-only
    even with a perfectly usable model configured, defeating R1.

    We therefore force ``VULTURE_USE_LLM=true`` for the duration of the probe
    only, so it proceeds to the real provider-reachability checks, then restore
    the original value. The actual LLM-phase toggle is still CWE-scoped via
    ``_resolve_cwe_llm`` / the per-request override — this does not flip the
    global default for any other agent.

    Calls ``health.check_llm_health`` via the module attribute so test
    monkeypatching of the source module takes effect regardless of import
    style. Returns the status object, or None if the probe itself errors
    (treated as unreachable by the caller).
    """
    _sentinel = object()
    _prev = os.environ.get("VULTURE_USE_LLM", _sentinel)
    os.environ["VULTURE_USE_LLM"] = "true"
    try:
        return asyncio.run(_health.check_llm_health())
    except Exception:  # noqa: BLE001 — any probe failure ⇒ treat as no model
        return None
    finally:
        if _prev is _sentinel:
            os.environ.pop("VULTURE_USE_LLM", None)
        else:
            os.environ["VULTURE_USE_LLM"] = _prev


def _resolve_cwe_llm(config: dict) -> tuple[bool, str | None]:
    """Feature 0057 P1a: resolve the CWE agent's effective LLM toggle.

    CWE runs the LLM phase BY DEFAULT (model-gated). Resolution order:
      1. ``VULTURE_CWE_DISABLE_LLM`` escape hatch → always skills-only.
      2. Explicit per-request ``use_llm`` bool wins over the default.
      3. Default (unset) → want LLM on.
      4. If LLM is wanted, gate on provider availability: an unreachable
         model degrades gracefully to skills-only + a notice (R5, exit 0).

    Returns ``(effective_use_llm, notice_or_None)``.
    """
    if _env_truthy("VULTURE_CWE_DISABLE_LLM"):
        return False, None

    requested = config.get("use_llm")
    want_llm = requested if isinstance(requested, bool) else True
    if not want_llm:
        return False, None

    status = _probe_llm_health()
    reachable = bool(getattr(status, "reachable", False))
    if reachable:
        return True, None

    # Graceful degradation: keep the audit running skills-only with an
    # explicit notice so the Mode-E no-key user still gets a clean result.
    base = (
        status.message() if status is not None and hasattr(status, "message")
        else "LLM unavailable — no usable model configured."
    )
    notice = f"{base} Running skills-only (no LLM phase)."
    return False, notice


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

    # Inject catalog context into LLM instructions for deeper analysis
    catalog_ctx = _build_llm_catalog_context()
    enhanced_instructions = INSTRUCTIONS
    if catalog_ctx:
        enhanced_instructions += (
            "\n\n## CWE Catalog Reference\n"
            "Use this catalog data to identify weakness patterns:\n\n"
            + catalog_ctx
        )

    # Feature 0057 P1a: CWE runs the LLM phase by default, model-gated.
    effective_use_llm, llm_notice = _resolve_cwe_llm(config)

    # Feature 0046 / 0057 P1b: per-audit override for the L5 LLM judge.
    # When LLM is on and the request doesn't specify, L5 defaults ON for CWE
    # (the generate-verify control on LLM findings — R4).
    _v = config.get("validate")
    explicit_l5 = _v.get("llm") if isinstance(_v, dict) else None
    if isinstance(explicit_l5, bool):
        validate_use_llm = explicit_l5
    else:
        validate_use_llm = effective_use_llm

    if llm_notice:
        from shared.transport.event_emitter import AgUiEventEmitter
        yield AgUiEventEmitter(run_id).text_message(llm_notice)

    yield from run_combined_audit(
        run_id=run_id,
        source_path=source_path,
        categories=categories,
        skill_map=SKILL_MAP,
        domain_label="CWE categories",
        prior_context=context,
        skill_tools=SKILL_TOOLS,
        instructions=enhanced_instructions,
        model=os.environ.get("VULTURE_LLM_MODEL"),
        use_llm=effective_use_llm,
        validate_use_llm=validate_use_llm,
    )
