"""CWE Weakness Auditor agent definition.

Implements a two-phase audit pipeline:
  Phase 1 (Skills): 22 concurrent skills including catalog-driven detector
  Phase 2 (LLM): Self-learning analysis with catalog context injection

LLM phase policy (feature 0057/0059 — uniform opt-in, model-gated,
generate-then-verify):

  * Uniform with every other scan agent (feature 0059): the CWE agent respects
    the global ``VULTURE_USE_LLM`` flag (default ``false``) — the LLM phase is
    OPT-IN, NOT on-by-default. ``_resolve_cwe_llm`` decides the effective
    toggle in order: ``VULTURE_CWE_DISABLE_LLM`` escape hatch (always
    skills-only) > explicit per-request ``use_llm`` bool > the
    ``VULTURE_USE_LLM`` environment default (default ``false`` ⇒ skills-only).
    Enable the LLM phase with ``VULTURE_USE_LLM=true`` or a per-request
    ``use_llm=true``.
  * "Model-gated": when the LLM phase is wanted it is gated on a provider
    health probe (``_probe_llm_health``). If no usable model is reachable the
    audit degrades GRACEFULLY to skills-only with a notice and still exits
    cleanly (R5) — no key / no model is not an error for the Mode-E user.
  * "Generate-then-verify": when the LLM phase is on, the L5 LLM judge
    (``validate_use_llm``) defaults ON for CWE, so model-generated findings
    are independently verified before they are reported (R4). A per-request
    ``validate.llm`` bool overrides this.
  * The LLM sweep is bounded (feature 0057 P1d): it stops at
    ``VULTURE_LLM_MAX_FILES`` files (default 10000) or when estimated spend
    crosses ``VULTURE_LLM_BUDGET_USD`` (unset / <= 0 ⇒ no USD cap), emitting
    partial results rather than running unbounded.

Snippet handling (feature 0057 P0/P2a): the shared runner back-fills a code
window onto every finding and, for secret-bearing CWEs (CWE-798/319/312/256/
259/321/522), masks the secret VALUE in that window. Redaction is applied at
EVERY snippet egress point — the per-finding ``finding`` SSE event (live
frontend view), the ``result`` snapshot event, and the persisted DB
``code_snippet`` column — so the raw secret never leaves the agent.
"""

import asyncio
import os
from collections.abc import Generator
from typing import Any

from shared.llm import health as _health
from shared.audit_runner import run_combined_audit
from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context
from shared.env import env_truthy

from cwe_agent.catalog import build_catalog_context, get_static_detectable
from cwe_agent.config import ALL_CATEGORIES
from cwe_agent.skills import SKILL_MAP, SKILL_TOOLS

# Collect CWE IDs covered by catalog for LLM context
_CATALOG_CWE_IDS = [e["id"] for e in get_static_detectable(min_score=0.3)][:80]

INSTRUCTIONS = """You are a CWE (Common Weakness Enumeration) Security Auditor using CWE v4.19.1.

## Catalog Coverage (honest, multi-tier)
The CWE v4.19.1 catalog has 846 entries — that figure is CONTEXT/metadata
(names, consequences, rollup parents), NOT a detection-coverage claim. What the
deterministic skill phase actually DETECTS:
- 21 dedicated regex skills emitting ~73 distinct CWE-ID `category` literals,
  plus 7 corpus-trusted signature CWE-IDs.
- Of those, N=10 CWE types are CORPUS-VERIFIED (recall 1.0 / fp 0.0 on the
  labeled corpus) — see tests/corpus/VERIFIED_CWES.md; N is computed by the
  gate, not asserted.
- 1 catalog-driven generic detector keyword-matches against the 846-entry
  catalog, but that path fires ~0 findings on real code (metadata/context only).

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
- Catalog generic: keyword-matches against the 846-entry catalog + rollup for Class/Pillar parents — metadata/context path that fires ~0 findings on real code (not a coverage claim)

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


def _probe_llm_health() -> Any:
    """Run the async provider health probe from this sync generator.

    This probe is only reached AFTER ``_resolve_cwe_llm`` has decided the LLM
    phase is wanted (via ``VULTURE_USE_LLM=true`` or a per-request
    ``use_llm=true``). At that point the probe must key on *provider/model
    availability*, NOT re-read the global ``VULTURE_USE_LLM`` flag.
    ``check_llm_health`` short-circuits to ``provider=disabled /
    reachable=False`` whenever ``VULTURE_USE_LLM != "true"`` (health.py); if a
    per-request ``use_llm=true`` enabled the phase while the env flag is unset,
    that short-circuit would falsely report "no model" even with a usable model
    configured.

    We therefore force ``VULTURE_USE_LLM=true`` for the duration of the probe
    only, so it proceeds to the real provider-reachability checks, then restore
    the original value. The effective LLM-phase toggle is still owned by
    ``_resolve_cwe_llm`` / the per-request override — this temporary override
    does not flip the global default for any other agent.

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
    """Feature 0057/0059: resolve the CWE agent's effective LLM toggle.

    Uniform with every other scan agent (feature 0059): the CWE agent respects
    ``VULTURE_USE_LLM`` (default ``false``) — the LLM phase is OPT-IN, not
    on-by-default. Resolution order:
      1. ``VULTURE_CWE_DISABLE_LLM`` escape hatch → always skills-only.
      2. Explicit per-request ``use_llm`` bool wins over the global default.
      3. Otherwise (unset) → the ``VULTURE_USE_LLM`` environment default,
         read at RUNTIME (mirrors ``audit_runner``'s ``USE_LLM`` expression) so
         it is monkeypatch-testable; default ``false`` ⇒ skills-only.
      4. If LLM is wanted, gate on provider availability: an unreachable
         model degrades gracefully to skills-only + a notice (R5, exit 0).

    Returns ``(effective_use_llm, notice_or_None)``.
    """
    if env_truthy("VULTURE_CWE_DISABLE_LLM"):
        return False, None

    requested = config.get("use_llm")
    if isinstance(requested, bool):
        want_llm = requested
    else:
        # Mirror audit_runner's USE_LLM expression, read at runtime so the
        # default tracks VULTURE_USE_LLM uniformly with the rest of the fleet.
        want_llm = os.environ.get("VULTURE_USE_LLM", "false").lower() == "true"
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
    """Execute the CWE weakness audit and yield SSE events.

    Runs the skill phase (full coverage) and then, when enabled, the LLM phase
    under the uniform opt-in, model-gated, generate-then-verify policy
    described in the module docstring: ``_resolve_cwe_llm`` resolves the
    effective LLM toggle (``VULTURE_CWE_DISABLE_LLM`` escape hatch >
    per-request ``use_llm`` > the ``VULTURE_USE_LLM`` environment default,
    which is ``false``) and gates it on provider health, degrading to
    skills-only with a notice when the LLM is wanted but no model is reachable;
    when the LLM phase is on, the L5 judge (``validate_use_llm``) defaults ON
    so model findings are verified before being reported.
    """
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
        # 0059: per-audit Tier-3 LLM toggle (config > VULTURE_LLM_TIER3 env > OFF).
        llm_tier3=config.get("llm_tier3"),
    )
