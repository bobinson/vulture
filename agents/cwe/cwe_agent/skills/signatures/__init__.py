"""Deterministic SIGNATURE tier (feature 0057 Phase 4).

Sink/source/sanitizer signatures for high-value CWEs the 21 regex skills miss,
routed THROUGH ``check_catalog_generic`` (R11) — never a parallel skill
category. Signatures land as ``candidate`` until the Phase-5 corpus gate
promotes them to ``trusted``.
"""

from cwe_agent.skills.signatures.detector import match_signatures
from cwe_agent.skills.signatures.registry import SIGNATURES, covered_cwe_ids
from cwe_agent.skills.signatures.schema import CweSignature

__all__ = ["CweSignature", "SIGNATURES", "covered_cwe_ids", "match_signatures"]
