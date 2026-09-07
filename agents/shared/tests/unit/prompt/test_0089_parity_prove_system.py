"""Assembled parity for the PROVE system turn and its retry suffix.

Feature 0089 Phase 1. This file exists because of a defect it now prevents:
`PROVE_SYSTEM` listed `prove/retry_guidance` as a second SYSTEM fragment, while
`llm_helper.py:194-197` sends the system message alone and concatenates the
guidance onto the USER prompt. Every fragment involved was byte-exact, so the
byte-exactness test passed; the composition was still wrong.

What let it survive was `render(PROVE_SYSTEM, ...)` being called for its side
effect with the result discarded. So the assertions here are about the ASSEMBLED
turns and the wire payload, never a fragment in isolation.
"""

from __future__ import annotations

import pytest

from prove_agent.llm_helper import _RETRY_GUIDANCE, _SYSTEM_MSG
from shared.prompt.manifests.prove_system import PROVE_RETRY, PROVE_SYSTEM
from shared.prompt.profile import profile_for
from shared.prompt.render import Mode, render


def _r(spec):
    """ADAPT, following the call site (item 4.5 flipped it).

    It was TRANSCRIBE until item 4.8, which is when the distinction started to
    matter: `_SYSTEM_MSG` and `_RETRY_GUIDANCE` are ADAPT renders, and
    `core/language` — listed in `PROVE_SYSTEM`, dropped by rule 9 for `gpt-4o`
    — is 476 bytes that TRANSCRIBE keeps and production never sends. Comparing
    the live payload against the mode it is not rendered in would fail for a
    reason that says nothing about the payload.
    """
    return render(spec, profile_for("gpt-4o"), mode=Mode.ADAPT)


def test_prove_system_turn_is_the_system_message_alone():
    """The live payload is exactly one system message and no user turn."""
    rp = _r(PROVE_SYSTEM)
    assert rp.instructions == _SYSTEM_MSG
    assert rp.messages == [{"role": "system", "content": _SYSTEM_MSG}]
    # The regression this file was written for: guidance must NOT be here.
    assert rp.user == ""
    assert _RETRY_GUIDANCE[1] not in rp.instructions
    assert _RETRY_GUIDANCE[2] not in rp.instructions
    # The SPEC's list, which item 4.8 grew; the rendered bytes above are where
    # the clause's absence on this profile is asserted.
    assert rp.fragments == ("prove/system", "core/language")


@pytest.mark.parametrize("attempt", (1, 2))
def test_prove_retry_guidance_is_a_user_suffix(attempt: int):
    """`prompt + guidance` — concatenation, so the leading newlines are its own.

    A blank-line join would emit four newlines where live emits two, which is
    why the fragment is `verbatim`. Asserted as bytes against the live list at
    the same index, so an index swap fails.
    """
    rp = _r(PROVE_RETRY[attempt])
    assert rp.user == _RETRY_GUIDANCE[attempt]
    assert rp.instructions == ""
    assert rp.messages == [{"role": "user", "content": _RETRY_GUIDANCE[attempt]}]
    assert rp.user.startswith("\n\n"), "the separator belongs to the guidance"


def test_attempt_zero_has_no_spec():
    """Live sends `""` on the first attempt.

    Absent rather than present-and-empty: a spec rendering to nothing cannot be
    told apart from a spec that failed to render.
    """
    assert _RETRY_GUIDANCE[0] == ""
    assert 0 not in PROVE_RETRY
    assert set(PROVE_RETRY) == {1, 2}
    assert len(_RETRY_GUIDANCE) == 3
