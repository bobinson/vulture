"""Stable per-detector identity for xss findings. Feature 0079 C1.

The xss agent set ``check_id`` at ZERO sites while cwe set it at 149. That gap
has four measured consequences, none of them about the field itself:

1. ``stream_handler.go`` awards +1 detail score for a non-empty CheckID, so at a
   cross-agent collision an xss row systematically LOST the tie to a cwe row
   that carried one.
2. ``audit_runner._dedup_key`` falls back to the normalised TITLE without one --
   the mechanism behind the measured helpers.ts:138 attribution flip, where two
   xss rows scoring 53-53 traded places 4-2 across six runs of the same image.
3. ``validate/calibration.py`` keys a rule as ``check_id or category``, so every
   xss row calibrated under "CWE-79", indistinguishable from cwe-agent rows; a
   per-rule demotion could not separate them.
4. ``backend/internal/cwe/layer.go``'s pluginRule and pluginPrefix resolution
   steps were dead code for xss.

This is ADDITIVE. ``category`` is untouched: the xss agent's published finding
contract (skills/SKILLS.md, the /info description) specifies CWE ids, a passing
0078 conformance test codifies that shape, and 11 of its 16 sites feed the OWASP
Top 10 manifest through ``parse_cwe_id`` on the category field. Renaming the
category would silently drop them.

NOT inert, and the plan says so: giving xss rows a check_id makes them satisfy
``_is_deterministic``, which excludes their demotions from ``honoured_idx`` and
lowers RC6's ``demote_frac``. That can leave an LLM demotion standing that RC6
used to neutralise. ``VULTURE_XSS_CHECK_IDS=false`` reverses exactly this.
"""

from __future__ import annotations

from shared.env import env_flag


def check_ids_enabled() -> bool:
    """Read at call time, never cached, so the switch stays flippable."""
    return env_flag("VULTURE_XSS_CHECK_IDS", True)


def cid(check_id: str) -> dict[str, str]:
    """Return the ``check_id`` fragment to splat into a finding dict.

    Returns an empty dict when disabled, so ``**cid(...)`` contributes nothing
    and the finding is byte-identical to the pre-0079 form.
    """
    if not check_ids_enabled():
        return {}
    return {"check_id": check_id}
