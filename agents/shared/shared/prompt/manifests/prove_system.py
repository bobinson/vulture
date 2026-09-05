"""PROVE system manifest — feature 0089 Phase 0.c (transcribe).

The JSON-API system message, and the retry guidance the prove agent appends when
a response fails to parse. `prove/system` declares FORBIDS_PROSE; the reflect
prompts declare an `analysis` field, so that stance is an honest record of a real
contradiction, not a wish.

**Phase 1 correction.** `prove/retry_guidance` was listed here as a second
SYSTEM fragment. `llm_helper.py:194-197` does not do that: the system turn is
`_SYSTEM_MSG` alone, and the guidance is concatenated onto the **user** prompt,
selected by attempt, empty on attempt 0. Two differences follow and both matter
for a faithful transcription:

* it is a USER suffix, not a system section, so it must not be blank-line joined
  into the system text;
* it is appended by `prompt + guidance`, which is why each variant carries its
  own leading `\n\n` and is marked `verbatim` — a blank-line join would emit
  four newlines where live emits two.

Nothing asserted the assembled turn before Phase 1: the manifest test called
`render(PROVE_SYSTEM, ...)` for its side effect and discarded the result, so a
byte-perfect fragment sat in the wrong turn undetected.
"""

from __future__ import annotations

from ..spec import PromptSpec

PROVE_SYSTEM = PromptSpec(
    id="prove_system",
    tier="prove",
    fragments=("prove/system",),
)

# Keyed by attempt index, mirroring `_RETRY_GUIDANCE`. Attempt 0 is absent
# rather than empty: live sends `""`, and a spec rendering to nothing would be
# indistinguishable from a spec that failed to render.
PROVE_RETRY: dict[int, PromptSpec] = {
    n: PromptSpec(
        id=f"prove_retry_{n}",
        tier="prove",
        fragments=(),
        user_fragments=(f"prove/retry_guidance_{n}",),
    )
    for n in (1, 2)
}

# Bind each spec to a module-level name so the auto-discovering MANIFESTS
# loader (which scans top-level PromptSpec values, not dict members) finds it —
# the same binding `prove_plan`, `prove_reflect` and `prove_analyze` each do.
#
# Phase 2.2 is why it is no longer optional. While `_RETRY_GUIDANCE` was an
# inline literal in `llm_helper.py`, `test_prove_fragments_are_byte_exact`
# compared the fragment against it and any edit to `retry_guidance_{1,2}.md`
# failed there. The call site now RENDERS those fragments, so both sides of that
# comparison move together and the pin is gone: measured, a one-character edit
# to `retry_guidance_2.md` changed the live prove payload and failed no test in
# either suite. Registering the specs restores the pin as a committed golden,
# which is the guard that does not move with the fragment.
for _n, _spec in PROVE_RETRY.items():
    globals()[f"PROVE_RETRY_{_n}"] = _spec
