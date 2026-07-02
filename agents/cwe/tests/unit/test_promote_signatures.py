"""Feature 0057 Phase 5 — T21: data-driven candidate->trusted promotion (P5c/R15).

Pins the contract of ``scripts/promote_signatures.py``: signature status is
driven SOLELY by the corpus gate result. For each signature CWE in
``covered_cwe_ids()``:

    status = "trusted"   iff that CWE is VERIFIED by the gate
    status = "candidate" otherwise (a CWE that regresses below gate AUTO-DEMOTES)

Skill CWEs (78/89/798) carry no ``status`` field — promotion only touches
signature family modules; the gate merely reports them VERIFIED-or-not.

RED until ``scripts/promote_signatures.py`` exists with:
    promote_signatures.decide_statuses(verified: set[str]) -> dict[cwe -> status]
        pure mapping over covered_cwe_ids(); "trusted" iff cwe in verified.
    promote_signatures.rewrite_status(module_source: str, new_status: str) -> str
        rewrites the `status="..."` literal(s) in a family module's source text,
        idempotently, without touching anything else.

The pure-function design keeps the test from mutating the real family files: we
feed source text in and assert the transformed text out.
"""

from __future__ import annotations

import importlib

from cwe_agent.skills.signatures.registry import covered_cwe_ids

promote = importlib.import_module("promote_signatures")


# --------------------------------------------------------------------------
# T21 — promotion is data-driven: trusted iff gated.
# --------------------------------------------------------------------------
def test_T21_decide_statuses_trusted_iff_verified():
    """A verified signature CWE is decided trusted; an unverified one stays
    candidate. Driven entirely by the gate's verified set — no hand-coding."""
    covered = covered_cwe_ids()
    # Use real covered CWEs so the mapping is meaningful. Verify one, not another.
    assert "1333" in covered
    assert "548" in covered

    decisions = promote.decide_statuses(verified={"1333"})

    assert decisions["1333"] == "trusted"      # gated → promoted
    assert decisions["548"] == "candidate"      # not gated → stays candidate
    # every covered CWE gets a decision, nothing invented beyond the registry.
    assert set(decisions) == set(covered)


def test_T21_unverified_signature_auto_demotes_to_candidate():
    """Risk #9: a CWE that drops out of the verified set is demoted back to
    candidate even if it was previously trusted (idempotent, gate-driven)."""
    covered = covered_cwe_ids()
    decisions = promote.decide_statuses(verified=set())  # nothing passes the gate
    assert all(status == "candidate" for status in decisions.values())
    assert set(decisions) == set(covered)


def test_T21_rewrite_status_flips_candidate_to_trusted():
    """rewrite_status flips the status literal in family source text to trusted,
    touching only the status field."""
    src = (
        "    CweSignature(\n"
        '        cwe_id="1333",\n'
        '        sig_id="cwe.sig.redos",\n'
        '        status="candidate",\n'
        "    ),\n"
    )
    out = promote.rewrite_status(src, "trusted")
    assert 'status="trusted"' in out
    assert 'status="candidate"' not in out
    # nothing else changed.
    assert 'cwe_id="1333"' in out
    assert 'sig_id="cwe.sig.redos"' in out


def test_T21_rewrite_status_is_idempotent():
    """Re-applying the same status is a no-op (safe to re-run promotion)."""
    src = '        status="trusted",\n'
    assert promote.rewrite_status(src, "trusted") == src


def test_T21_rewrite_status_demotes_trusted_to_candidate():
    """The reverse direction also works — trusted reverts to candidate when the
    gate no longer verifies the CWE."""
    src = '        status="trusted",\n'
    out = promote.rewrite_status(src, "candidate")
    assert 'status="candidate"' in out
    assert 'status="trusted"' not in out
