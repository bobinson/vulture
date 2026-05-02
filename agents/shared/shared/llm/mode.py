"""Skills/LLM dual-mode resolution for agents.

Single source of truth for what mode an audit should run in. Reads
``VULTURE_USE_LLM`` and ``VULTURE_REQUIRE_LLM`` (feature 0039) and
returns a mode tag agents branch on.

This is the synchronous v1.0 of feature 0043. The async
``resolve_audit_mode()`` (which probes LLM health) is reserved for v1.1
when agents need to distinguish "operator opted in but LLM unreachable"
from "operator opted in and LLM reachable" — the prove + discover
agents only need the synchronous "skills_only or not" check today.

Contract: every audit-producing agent MUST call
``is_skills_only()`` as the first meaningful step of its run function
and skip every LLM call when the result is True. See
``docs/features/0043_universal_skills_llm_contract/`` for the spec.
"""

from __future__ import annotations

import os


def is_skills_only() -> bool:
    """True when the operator has opted out of LLM use.

    Returns True for any value of ``VULTURE_USE_LLM`` other than
    case-insensitive ``"true"`` — so unset, empty, ``"false"``, ``"0"``,
    or any garbage string all mean skills-only.

    Why this default direction: prior to 0043, agents were built with
    LLM-as-the-default assumption. Operators who don't have keys (the
    ``dev skills`` workflow, the no-API-key open-source path) get a
    silent skills-only mode without having to set anything. Operators
    who need LLM set ``VULTURE_USE_LLM=true`` explicitly.
    """
    return os.getenv("VULTURE_USE_LLM", "").lower() != "true"


def is_llm_required() -> bool:
    """True when the operator wants a hard failure if LLM is unreachable.

    Set via ``VULTURE_REQUIRE_LLM=true`` (feature 0039). Used by the
    prove agent to distinguish "operator chose skills-only" (which is
    fine) from "operator wanted LLM but it's unconfigured" (which
    should fail loudly rather than silently degrade).
    """
    return os.getenv("VULTURE_REQUIRE_LLM", "").lower() == "true"
