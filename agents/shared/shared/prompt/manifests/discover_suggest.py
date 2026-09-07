"""DISCOVER tier — endpoint suggestion. Feature 0089 Phase 0.c, adapted in 4.6.

Phase 0.c transcribed `discover_agent/plugins/llm_suggest.py:_LLM_DISCOVER_PROMPT`
byte for byte into one user fragment, because the call site built
`messages=[{"role": "user", ...}]` and set no system message at all. Phase 4.6
is the item that was allowed to change those bytes, and it made four changes:

* THE SYSTEM ROLE. The standing half of the prompt — persona, focus list,
  output contract, rules — is identical on every call; only the discovered
  evidence varies. It moved to `discover/system`, and `discover/suggest` is now
  the evidence and the ask. The call site renders in `Mode.ADAPT`, so a family
  whose chat template has no system turn (gemma) still receives the whole
  thing, folded into the front of its single user turn.
* THE EXEMPLAR (below).
* AN ABSTENTION CLAUSE. Ten numbered categories and "Limit to 20" told the
  model to fill a list; nothing told it an empty list was an answer. The clause
  says so and `discover/system` declares `BLESSES_ABSTENTION`, so a future
  tool-permitting fragment in this spec is a `check_03_stance_conflict`
  failure rather than a silent contradiction.
* A WIDER PATH RULE. The rule admitted eight roots while the plugin's own
  filter admits any non-static path (`ep.startswith("/") and not
  is_static_path(ep)`), so the prompt was the narrower of the two authorities
  and instructed away a real `/oauth/token` or `/.well-known/*` before the
  filter ever saw it.

THE EXEMPLAR, which is what 4.6 was mainly for. The one worked example was
`{"endpoints": ["/api/path1", "/api/path2", ...], "reasoning": "..."}`, whose
bare `...` is not JSON. Phase 2.1 had already replaced the plugin's hard
`json.loads` with `shared.prompt.extract.extract_object`, which rescues a
fence, a `<think>` preamble and surrounding prose — but it cannot rescue a
syntax error, so a model copying the shape it was shown still lost the entire
suggestion round, silently, to `discover()`'s blanket `except`. The example is
now two real-looking paths and parses. That retired two allow entries at once:
`exemplar_validity` and `placeholder_echo`, which `check_09` raised on the same
`...`.

Item 4.8 closed the last annotated finding here. `reasoning` is free text that
egresses, and until `core/language` existed no fragment in the library bound an
output language at all, so `check_12_language_pin` fired on this spec and on
seventeen others. This manifest now lists the clause and carries NO allow entry.

A finding that promptlint CANNOT see is still open too: `{technologies}`,
`{forms}` and `{headers}` are filled from the scanned site's own response
headers and HTML and are spliced in with no delimiter and no MARKS_UNTRUSTED
fragment. 4.6 narrows the blast radius — the instructions now sit in a
different turn from the target's bytes — but that is not a fix: no nonce, no
slot, no marker. `check_05_slot_marking` only fires for a spec that declares
`slots`, and this one still declares none, so the gap stays pinned by
`test_discover_interpolates_target_bytes_with_no_untrusted_marker`.

**Item 4.7 could not reach this manifest, and this is the record of why.** It
is the one spec in the library that rule 2 leaves unprotected, and the reason
is granularity, not oversight: the mirror's unit is the FRAGMENT, and DISCOVER
has no dedicated output-contract fragment. Its two contract lines ("Return ONLY
a JSON object:" and the exemplar, 109 bytes) sit inside `discover/system`
between the ten-category focus list and the rules block, so the only role flip
available duplicates 1634 bytes to protect those 109 — ~410 tokens against rule
2's own ~40-token justification. Splitting the contract out is a change to
`discover/system`'s TEXT, which is 4.6's split rather than 4.7's role flip, and
it would invalidate three assertions 4.6 committed (`DISCOVER_SUGGEST.fragments
== ("discover/system",)`). Item 4.8 has since appended `core/language` to that
tuple, so those assertions read `("discover/system", "core/language")` now — a
second SYSTEM fragment, but not a mirrored one, so the exposure below is
unchanged.

The exposure is real and worth stating precisely, because this tier's user turn
is the one place in the library that refers deictically to the system turn:
`discover/suggest` ends "…as the JSON object described above". If a gateway
drops the system role here, the model is asked to suggest endpoints "as the
JSON object described above" with no such object anywhere in what it received —
prose back, and `discover()`'s blanket `except` turns the whole suggestion
round into silence. Tracked in `test_0089_4_7_mirror.py::NO_MIRROR`.
"""

from __future__ import annotations

from ..spec import PromptSpec

DISCOVER_SUGGEST = PromptSpec(
    id="discover_suggest",
    tier="discover",
    # version 2: Phase 4.6 rewrote both fragments and split the turn.
    # version 3: item 4.8 appended `core/language`. Pinned by
    # `test_0089_version_bump.py`.
    version=3,
    # `core/language` last, not before `discover/system`: `_seam_join` lstrips
    # only the FIRST part, so a fragment moved into first position silently
    # loses any leading newline it carries, and this tier's identity sentence
    # is the one the model should read first either way.
    fragments=("discover/system", "core/language"),
    user_fragments=("discover/suggest",),
    schema_fields=("endpoints", "reasoning"),
)
