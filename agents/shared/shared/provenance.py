"""The LLM-family provenance rule — ONE rule, shared with the Go backend.

A finding is LLM-authored when its ``provenance``, trimmed (Go's whitespace
set, ``shared.gospace``) and lower-cased,
starts with ``llm``: ``llm``, the L5 survival re-tag ``llm_l5_verified``, and
any case or whitespace variant of either. This is exactly the backend's
``isLLMProvenance`` (``backend/internal/handler/stream_handler.go``); the two are
pinned against one fixture so a spelling can never be "LLM" to the backend's
dedup guard and "deterministic" (demotion-immune) to the L5 judge (0074, D1b).
"""

from __future__ import annotations

from typing import Any

from shared.gospace import trim_go_space

_LLM_FAMILY_PREFIX = "llm"


def is_llm_provenance(provenance: Any) -> bool:
    """True when *provenance* names the LLM tier (prefix rule, not substring)."""
    return isinstance(provenance, str) and trim_go_space(provenance).lower().startswith(_LLM_FAMILY_PREFIX)
