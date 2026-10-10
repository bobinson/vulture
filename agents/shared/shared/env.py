"""Environment-variable helpers shared across agents.

Single source of truth for the ``VULTURE_*`` truthy-flag convention used by
the kill switches (``VULTURE_CWE_DISABLE_LLM``, ``VULTURE_CWE_DISABLE_SIGNATURES``,
``VULTURE_CWE_DISABLE_DANGEROUS_FN`` …). Previously duplicated as a private
``_env_truthy`` in ``agent.py`` / ``catalog_detector.py`` / skills (audit #5).
"""

from __future__ import annotations

import functools
import logging
import os

from shared.gospace import trim_go_space

__all__ = ["env_flag", "env_mode", "env_truthy"]

logger = logging.getLogger(__name__)

# ONE on-list for env_truthy and env_flag, equal to Go's config.ParseFlag
# (feature 0074 contract T2): "on" enables everywhere.
_TRUTHY = frozenset({"true", "1", "yes", "on"})
_FLAG_TRUE = _TRUTHY
_FALSEY = frozenset({"false", "0", "no", "off"})
_MODE_OFF = "off"
_SHOWN_CHARS = 40


@functools.lru_cache(maxsize=256)
def _warn_unrecognised(name: str, raw: str, using: str) -> None:
    """One warning per (variable, value): an operator typo in a rollback switch
    must be visible, but not once per call on a hot path."""
    logger.warning("env_value_unrecognised name=%s value=%r using=%s",
                   name, raw[:_SHOWN_CHARS], using)


def env_truthy(name: str) -> bool:
    """True iff env var ``name`` is set to a truthy token (true / 1 / yes / on)."""
    return trim_go_space(os.environ.get(name, "")).lower() in _TRUTHY


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
    silently flip a rollback switch — and an unrecognised NON-BLANK value is
    logged once (feature 0074 review item 16), so the typo is not silent either.
    """
    raw = trim_go_space(os.environ.get(name, "")).lower()
    if raw in _FLAG_TRUE:
        return True
    if raw in _FALSEY:
        return False
    if raw:
        _warn_unrecognised(name, raw, str(default).lower())
    return default


def env_mode(name: str, modes: frozenset[str], default: str) -> str:
    """A ``VULTURE_*`` mode string normalised to one of ``modes`` (feature 0074
    contract C16), read at CALL time.

    Blank or unset takes ``default``; a false token (``false/0/no/off``, any
    case) is ``off``; a member of ``modes`` is itself, case-insensitively; any
    other non-blank value takes ``default`` and is logged once, naming the
    variable. Go's ``config`` reader applies the same rule to the same names.
    """
    raw = trim_go_space(os.environ.get(name, "")).lower()
    if not raw:
        return default
    if raw in _FALSEY:
        return _MODE_OFF
    if raw in modes:
        return raw
    _warn_unrecognised(name, raw, default)
    return default
