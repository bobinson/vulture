"""P4c — the signature registry.

Aggregates the per-family ``SIGNATURES`` tuples into one introspectable
``SIGNATURES`` tuple and exposes ``covered_cwe_ids()`` so the Phase-5 corpus
gate can enumerate exactly which CWEs the signature tier claims (R10/P4c).

Tranche 1 ships 7 net-new, signature-tractable CWEs the 21 regex skills miss:
CWE-1333 (ReDoS), 90 (LDAP), 91 (XPath), 917 (EL/SpEL), 943 (NoSQL),
117 (log injection), 548 (directory listing).

CWE-489 (active debug code) was DROPPED from tranche 1: it collides with the
existing ``configuration`` skill (CWE-1188 ``DEBUG=True`` / CWE-1295
``debug=True``), both already in ``_BASE_DEDICATED_CWES``. Per plan §4 it is
kept only if the Phase-5 corpus shows it net-new — deferred to that gate.
"""

from __future__ import annotations

from cwe_agent.skills.signatures.families import (
    dir_listing,
    el_injection,
    injection_ldap_xpath,
    log_injection,
    nosql,
    redos,
)
from cwe_agent.skills.signatures.schema import CweSignature

# Aggregate per-family tuples. Order is stable for deterministic output.
SIGNATURES: tuple[CweSignature, ...] = (
    redos.SIGNATURES
    + injection_ldap_xpath.SIGNATURES
    + el_injection.SIGNATURES
    + nosql.SIGNATURES
    + log_injection.SIGNATURES
    + dir_listing.SIGNATURES
)


def covered_cwe_ids() -> frozenset[str]:
    """Return the set of CWE ids the signature tier covers — introspectable
    for the Phase-5 corpus gate (P4c)."""
    return frozenset(sig.cwe_id for sig in SIGNATURES)


__all__ = ["SIGNATURES", "covered_cwe_ids"]
