"""Environment-variable helpers shared across agents.

Single source of truth for the ``VULTURE_*`` truthy-flag convention used by
the kill switches (``VULTURE_CWE_DISABLE_LLM``, ``VULTURE_CWE_DISABLE_SIGNATURES``,
``VULTURE_CWE_DISABLE_DANGEROUS_FN`` …). Previously duplicated as a private
``_env_truthy`` in ``agent.py`` / ``catalog_detector.py`` / skills (audit #5).
"""

from __future__ import annotations

import os

__all__ = ["env_flag", "env_truthy"]

_TRUTHY = frozenset({"true", "1", "yes"})
_FALSEY = frozenset({"false", "0", "no", "off"})


def env_truthy(name: str) -> bool:
    """True iff env var ``name`` is set to a truthy token (true / 1 / yes)."""
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def env_flag(name: str, default: bool) -> bool:
    """A ``VULTURE_*`` boolean with an explicit default, read at CALL time.

    ``env_truthy`` covers the default-FALSE kill switches. The default-TRUE
    rollback switches were each hand-rolled instead, and the token sets drifted:
    some tested ``!= "false"`` and some tested ``not in ("0","false","no","off")``,
    so within ONE feature ``VULTURE_LLM_JSON_SCAN=off`` left the scan enabled
    while ``VULTURE_LLM_LINE_NUMBERS=off`` disabled numbering. An operator cannot
    be expected to know which switch takes which spelling.

    One token set for both directions: ``true/1/yes/on`` and ``false/0/no/off``.
    An unset or unrecognised value takes ``default`` — an operator typo must not
    silently flip a rollback switch.
    """
    raw = os.environ.get(name, "").strip().lower()
    if raw in _TRUTHY or raw == "on":
        return True
    if raw in _FALSEY:
        return False
    return default
