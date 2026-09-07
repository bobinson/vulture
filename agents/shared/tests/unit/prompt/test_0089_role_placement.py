"""A fragment's declared role must agree with the turn its spec puts it in.

Feature 0089 Phase 1, and the generic form of the defect that motivated it.

`render()` decides placement from WHICH TUPLE a manifest lists a fragment in
(`spec.fragments` -> system, `spec.user_fragments` -> user). It never consults
the fragment's declared `role`. So a fragment saying `role: USER` that is listed
in `spec.fragments` lands in the system turn, silently, and every byte-exactness
test still passes because the fragment's own bytes are perfect.

That is precisely how `prove/retry_guidance` came to sit in the PROVE system
turn while the live call site appends it to the user prompt. Rather than write a
parity test per site and hope the next one is remembered, this asserts the
invariant over EVERY spec in the registry at once: the two sources of placement
information have to agree.

This is an addition beyond the LLD's twelve lint checks. It is here rather than
in `lint.py` because it is a property of a MANIFEST's composition, not of a
prompt's text — the linter reads fragments and their declarations, while this
needs the spec that binds them into turns.
"""

from __future__ import annotations

from shared.prompt import registry
from shared.prompt.fragment import Role
from shared.prompt.manifests import MANIFESTS

# Roles admissible in each turn. EITHER and SYSTEM_USER_MIRROR are legitimately
# placeable in both; TOOL_DESC belongs to a tool schema, never a chat turn.
_SYSTEM_OK = {Role.SYSTEM, Role.EITHER, Role.SYSTEM_USER_MIRROR}
_USER_OK = {Role.USER, Role.EITHER, Role.SYSTEM_USER_MIRROR}


def _roles(ids):
    for fid in ids:
        frag = registry.get(fid)
        assert frag is not None, f"spec names unknown fragment {fid!r}"
        yield fid, frag.role


def test_every_spec_places_fragments_in_a_turn_their_role_admits():
    violations = []
    for spec_id, spec in MANIFESTS.items():
        for fid, role in _roles(spec.fragments):
            if role not in _SYSTEM_OK:
                violations.append(f"{spec_id}: {fid} declares {role.name} but is in the SYSTEM turn")
        for fid, role in _roles(spec.user_fragments):
            if role not in _USER_OK:
                violations.append(f"{spec_id}: {fid} declares {role.name} but is in the USER turn")
    assert not violations, "role/turn disagreement:\n  " + "\n  ".join(violations)


def test_the_registry_is_not_empty_and_every_spec_names_fragments():
    """Guards the vacuous pass: an empty registry would satisfy the test above.

    Two of this session's earlier mistakes were assertions over empty
    collections, so the subject is counted before it is judged.
    """
    assert len(MANIFESTS) >= 7, f"only {len(MANIFESTS)} specs registered"
    placed = sum(len(s.fragments) + len(s.user_fragments) for s in MANIFESTS.values())
    assert placed >= 20, f"only {placed} fragment placements to check"


def test_tool_desc_fragments_are_never_placed_in_a_chat_turn():
    """A tool description belongs in a tool schema, not in a message."""
    for spec_id, spec in MANIFESTS.items():
        for fid, role in _roles(tuple(spec.fragments) + tuple(spec.user_fragments)):
            assert role is not Role.TOOL_DESC, f"{spec_id}: {fid} is TOOL_DESC"
