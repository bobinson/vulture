"""PROVE system manifest — feature 0089 Phase 0.c (transcribe).

The JSON-API system message, and the retry guidance the prove agent appends when
a response fails to parse. `prove/system` declares FORBIDS_PROSE as an
ENVELOPE-scoped stance — the reply is a single JSON object with no prose
around it — exactly as `validate/output_contract` carries it beside its own
free-text `reasoning` field. Item 4.5 reworded the text so it no longer names
the reflect schema's `analysis` field in its forbid list; the earlier text
did, which was the real contradiction.

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

**Item 4.7 deliberately gives this tier NO `SYSTEM+USER_MIRROR` fragment**, and
records the reason here rather than leaving the absence to be read as an
oversight. Rule 2 exists to keep the output contract alive when a gateway drops
the system turn; PROVE already survives that, because every user fragment of
the tier states the contract itself — `prove/plan` ("Reply with ONLY a JSON
object (no markdown, no explanation)"), `prove/reflect` and `prove/analyze`
("Reply with JSON only"), and both retry guidances. That is the same argument
item 4.4 made for `generate/quote_obligation`: single placement in the turn no
gateway drops buys what the mirror buys by duplication, for none of the cost.

The second reason is a wire-shape one, particular to this tier. `PROVE_SYSTEM`
has no user fragments, and `llm_helper._SYSTEM_TURN` is
`render(PROVE_SYSTEM, ...).messages` — so a mirror here would not prepend a
prelude to the prompt, it would emit a second user MESSAGE, which
`llm_json_call` then puts ahead of the real one. Two user turns on the wire,
the first restating a contract the second states again.

The exemption is enforced, not just written down:
`tests/unit/prompt/test_0089_4_7_mirror.py::NO_MIRROR` fails if this tier ever
carries a mirrored fragment while this reason still stands.
"""

from __future__ import annotations

from ..spec import PromptSpec

# `core/language` is listed HERE, and that is what makes the pin reach the wire:
# `llm_helper._SYSTEM_TURN` is `render(PROVE_SYSTEM, ...).messages` and every
# plan / reflect / analyze call sends it, while the user turns are rendered from
# a spec built per call (`render_prove_prompt`) that lists no system fragment at
# all. The three per-strategy manifest families list it too — their
# `fragments=("prove/system", "core/language")` is the same system turn — so the
# transcription and production cannot disagree about what this tier sends.
PROVE_SYSTEM = PromptSpec(
    id="prove_system",
    tier="prove",
    # 2: item 4.5 reworded `prove/system` to constrain shape only.
    # 3: item 4.8 appended `core/language`.
    version=3,
    fragments=("prove/system", "core/language"),
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
