"""The per-audit arguments every scan agent computes identically.

Feature 0079 E10. Seven agents open ``run_audit`` with the same 6-11 lines --
byte-identical but for one label string -- and every cross-cutting change has
had to be applied six or seven times. Feature 0059 (tier3) did; feature 0046
(per-audit validate override) did; the copy-pasted ``# 0059:`` comment in six
agent files is the fingerprint.

This is deliberately a small helper returning a dict to splat, not a framework.
An elaborate ``AgentSpec`` + shared-runner design was built and adversarially
reviewed for this feature and LOST on the project's own metrics: its
``_resolve_llm`` measured cyclomatic C(15) against a baseline of A(5)-B(8), it
could silently disable the LLM phase fleet-wide by omitting ``skill_tools``
from a plan/spec split, and it hollowed out an unmodifiable conformance guard
that greps for the literal ``skill_map=SKILL_MAP`` at the call site.

The DRY property that mattered is kept: a future cross-cutting kwarg is added
HERE, once, and reaches every agent through ``**``. What stays at each call
site is exactly what the 0070 fleet guard needs to see -- ``skill_map``,
``skill_tools``, ``domain_label`` and ``instructions``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from shared.llm.provider import get_max_findings
from shared.tools.memory_client import build_prior_context


def shared_audit_kwargs(
    config: Mapping[str, Any],
    source_path: str,
    prior_findings: Sequence[dict[str, Any]] | None,
    memory_key: str,
    prior_context: str | None = None,
) -> dict[str, Any]:
    """Return the ``run_combined_audit`` kwargs every scan agent shares.

    ``memory_key`` is the agent's memory label ("cwe", "soc2", ...), the one
    value that legitimately differs between call sites.

    ``prior_context`` overrides the memory fetch for an agent that wraps it. The
    asvs agent is the real case: it routes through its own
    ``_safe_build_prior_context`` so a memory-service failure degrades the audit
    instead of killing it. Sharing the three toggles with the fleet while keeping
    that wrapper is strictly better than exempting the agent entirely -- an
    exemption is how the outlier drifts.

    Two simplifications are folded in, each proven rather than assumed:

    * ``prior_findings`` is passed straight through. All seven agents wrote
      ``preloaded = prior_findings if prior_findings else None`` first, which is
      a no-op: ``build_prior_context`` already branches on ``if preloaded:`` and
      ``use_edges = not bool(preloaded)``, so ``None``, ``[]`` and a non-empty
      list behave identically.
    * ``model`` is NOT returned. Four of seven agents passed
      ``model=os.environ.get("VULTURE_LLM_MODEL")`` and three passed nothing,
      and they behaved identically: every consumer resolves
      ``model or os.environ.get("VULTURE_LLM_MODEL", DEFAULT_MODEL)``. An agent
      that computes a real model override still passes it explicitly.
    """
    validate = config.get("validate")
    validate_llm = validate.get("llm") if isinstance(validate, dict) else None
    use_llm = config.get("use_llm")
    context = (
        prior_context
        if prior_context is not None
        else build_prior_context(
            source_path,
            memory_key,
            preloaded=prior_findings,
            max_findings=get_max_findings(),
        )
    )
    return {
        "prior_context": context,
        # Both toggles are three-valued: True / False / unset. isinstance keeps
        # a stray string or number from reading as True and silently forcing a
        # phase on, which is why the guard is here rather than at seven sites.
        "use_llm": use_llm if isinstance(use_llm, bool) else None,
        "validate_use_llm": validate_llm if isinstance(validate_llm, bool) else None,
        # Feature 0059: per-audit Tier-3 toggle (config > VULTURE_LLM_TIER3 > off).
        # Passed through raw because run_combined_audit applies no isinstance
        # guard to it today, and changing that is not this refactor's job.
        "llm_tier3": config.get("llm_tier3"),
    }
