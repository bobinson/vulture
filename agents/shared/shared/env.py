"""Environment-variable helpers shared across agents.

Single source of truth for the ``VULTURE_*`` truthy-flag convention used by
the kill switches (``VULTURE_CWE_DISABLE_LLM``, ``VULTURE_CWE_DISABLE_SIGNATURES``,
``VULTURE_CWE_DISABLE_DANGEROUS_FN`` …). Previously duplicated as a private
``_env_truthy`` in ``agent.py`` / ``catalog_detector.py`` / skills (audit #5).
"""

from __future__ import annotations

import os

__all__ = ["env_truthy"]

_TRUTHY = frozenset({"true", "1", "yes"})


def env_truthy(name: str) -> bool:
    """True iff env var ``name`` is set to a truthy token (true / 1 / yes)."""
    return os.environ.get(name, "").strip().lower() in _TRUTHY
