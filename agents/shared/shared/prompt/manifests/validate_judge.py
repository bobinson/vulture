"""VALIDATE tier — the L5 judge. Feature 0089 Phase 0.c, flipped in Phase 2.

A byte-verbatim transcription of `shared/validate/prompts/validate_judge.txt`
(split at its own section boundaries) plus the tool contract that
`judge_tools.tool_discipline_prompt()` used to append at call time.

Phase 2 made this the SOURCE rather than a copy: `llm_judge` renders these
specs and no longer reads either file. Both `.txt` files and
`_TOOL_DISCIPLINE_TEMPLATE` stay on disk, unread by production, as the
transcription's oracle — `tests/unit/prompt/test_0089_manifest_validate.py`
compares every fragment's text against them and
`test_0089_parity_validate_assembly.py` compares the assembled turns against
their composition, which is the only comparison in that suite with a
non-library side.

The fragments are listed in the order the source file states them, and
`validate/tool_discipline` last because that is where `llm_judge` concatenated
it (`system_prompt + "\\n\\n" + tool_discipline_prompt(...)`). The seam is
reproduced by declaration, not by text: `validate/output_contract` keeps its
terminating newline (the prompt file's own, which the no-tools turn sends) and
`validate/tool_discipline` declares `seam: tight`, so the file terminator, the
join and the fragment's leading blank line supply one newline each — the three
the concatenation produced.

`schema_fields` comes from `schema.VERDICT_SCHEMA` rather than a local copy of
the field names, in declaration order: `check_01_orphan_field` compares a
fragment's `declares_fields` against this tuple, so a second copy here is a
second place the L5 field list can drift from `llm_judge._coerce_verdict`.
(`validate/` itself has no schema constant to import — only
`_VERDICT_SCHEMA_VERSION` (`l5_cache.py:130`), which is a cache-key string.)

`slots` is empty and `channels` is not, and item 4.3 is why. The user template
interpolates `{audit_id}`, `{n}` and `{findings_block}` as raw text, and the
finding block is where the untrusted code and description bytes enter — but
that block is composed per FINDING inside `_render_user_message`, and the tool
results enter later still, mid-loop, from an executor. None of the three can be
a `Slot` VALUE in a module-level spec, so `slots` stays empty and the channels
are declared instead. `_render_user_message` and `_call_llm_with_tools` do use
`Slot` + `slots.wrap()` at the point the bytes actually exist, which is what
puts the per-request token on every marker; `channels` is how the linter gets
to see that from here.
"""

from __future__ import annotations

from ..backlog import OWNER
from ..lint import LintAllow
from ..schema import VERDICT_SCHEMA
from ..spec import PromptSpec

# ── the ONE exemption both judge specs still carry ────────────────────────
#
# A shared CONSTANT rather than a builder taking the spec id, as of item 4.8:
# the entry that remains keys on a FRAGMENT, so nothing in it varies by spec.
# The two entries that did vary are both retired, and their history is the
# reason this block is longer than the tuple it introduces.
#

# Item 4.2 retired the third. `validate/evidence_citation` used to declare
# `references: [numbered_snippet]`, and `check_07_dangling_reference` fired
# because no variable and no slot of that name exists in the render — the
# "numbered snippet" was a coordinate space that lived in one sentence and
# nowhere else. 4.2 states one space (the file's own numbering), so the
# fragment references nothing and the annotation goes with it rather than
# being re-worded.
#
# Item 4.3 retired the fourth, on both specs, without addressing it directly.
# `validate/untrusted_warning` tripped `placeholder_echo` on the bare `...`
# inside its marker documentation (`<<<CODE ... CODE>>>`), annotated as
# syntax illustration rather than an echoable value. 4.3 replaced that
# fragment with `core/untrusted`, whose marker documentation is
# `<<<CHANNEL:TOKEN` — a shape that names the token instead of eliding the
# content, so there is no ellipsis left to annotate. The exemption went with
# the fragment rather than being re-pointed at the new one.
#
# Item 4.8 retired the second — the `language_pin` entry, on both specs, and
# with it the sixteen on the other tiers. `core/language` is listed below and
# carries `BINDS_LANGUAGE`, which is the stance `check_12` looks for and which
# no fragment in the library carried until that item. That is also what turned
# the builder into this constant: `language_pin` reports the SPEC id, so it
# needed one entry per spec; nothing left here does.
_JUDGE_ALLOW: tuple[LintAllow, ...] = (
    LintAllow(
        "exemplar_validity", "validate/output_contract", owner=OWNER,
        reason="Phase 4.2 — the verdict exemplar uses angle-bracket type "
               "placeholders (`\"exploitable\":<float 0..1>`), so the block "
               "the model is shown is not parseable JSON.",
    ),
)


VALIDATE_JUDGE = PromptSpec(
    id="validate_judge",
    tier="validate",
    # 2: feature 0089 item 4.2 — `validate/evidence_citation` rewritten to one
    # coordinate space, `evidence_file` added to `validate/output_contract`'s
    # declared fields and exemplar, and the tool contract's competing
    # definition of `evidence_line` removed. `_VERDICT_SCHEMA_VERSION` moved in
    # the same change, so no verdict cached under the old prompt is served.
    #
    # 3: item 4.3 — `validate/untrusted_warning` replaced by `core/untrusted`,
    # and `channels` declared below. `_VERDICT_SCHEMA_VERSION` moved again for
    # the same reason.
    #
    # 4: item 4.7 — `core/untrusted` and `validate/output_contract` declare
    # `SYSTEM+USER_MIRROR`, and `validate/user_template` declares
    # `keep_trailing` so the mirror cannot eat its terminator. NO
    # `_VERDICT_SCHEMA_VERSION` BUMP, deliberately, and this is the one place
    # in Phase 4 where a VALIDATE item does not move it: this call site still
    # renders `Mode.TRANSCRIBE` (item 4.1 owns that flip, and
    # `test_mode_matches_phase` pins it), TRANSCRIBE mirrors nothing, and the
    # verbatim fast path makes `keep_trailing` inert there — so not one byte of
    # the shipped judge prompt moves and every cached verdict was produced
    # under the prompt still being sent. Measured against the committed
    # goldens, which ARE the pre-item render and which
    # `test_golden_bytes_default_profile` re-derives: the TRANSCRIBE
    # fingerprint is `b5f69cd26e0f05eb` here and `f41c56c0ced8ef83` for the
    # plain spec, unchanged across the item. What DOES move is the ADAPT
    # render nothing sends yet — `facaf0a7d7d42cc2` / `a2bf3e4ab0b59ece`, user
    # turn 79 -> 2063 bytes. Evicting the cache for a prompt that did not
    # change would cost a full re-judge for nothing. The bump belongs to 4.1,
    # in the commit that flips the mode.
    #
    # 5: item 4.8 — `core/language` inserted below, and the retained oracle
    # `prompts/validate_judge.txt` gains the same section in the same position
    # so it still composes to the turn production sends.
    # `_VERDICT_SCHEMA_VERSION` MOVES FOR THIS ONE, and the reason is the mode:
    # this site still renders TRANSCRIBE (item 4.1 owns the flip), TRANSCRIBE
    # applies no rule, so unlike every other tier the judge sends the clause to
    # EVERY family rather than to the four whose profile pins the output
    # language. That is a real byte change to the shipped prompt — measured on
    # the TRANSCRIBE render both specs send: +476 bytes on the system turn, and
    # fingerprint `b5f69cd26e0f05eb` -> `bc8f171cbb5ddfa0` (plain
    # `f41c56c0ced8ef83` -> `6a1dc6ce88af944c`). The sizes are 6667 -> 7143 as
    # the goldens capture them (`{n}` unfilled) and 6666 -> 7142 as
    # `_judge_system_prompt(10)` sends them at the default batch size; the
    # delta is the same 476 either way. The "before" fingerprints are exactly
    # what item 4.7 recorded as its "after", so nothing moved between the two
    # items. Every cached verdict was therefore produced under a different
    # prompt. When 4.1 flips this site the clause narrows to the four
    # language-pinning families by itself, with no edit here.
    #
    # 6: item 4.1 — the mode flip itself. Not one fragment moved for this one;
    # what moved is `llm_judge._judge_prompt`, from `Mode.TRANSCRIBE` to
    # `Mode.ADAPT`, and the version tracks the prompt this manifest SENDS
    # rather than the bytes it holds. Three rules arrive at once, measured on
    # the default profile with `{n}` unfilled: rule 2 mirrors `core/untrusted`
    # and `validate/output_contract` into the head of the user turn (79 ->
    # 2063 bytes — this is item 4.7's declaration finally shipping), rule 9
    # narrows `core/language` to the four language-pinning families (system
    # 7143 -> 6667 for the other six, which is the narrowing item 4.8 said
    # 4.1 would perform "by itself, with no edit here"), and rule 1 folds the
    # whole system turn into the user turn for `gemma`. Fingerprints:
    # `bc8f171cbb5ddfa0` -> `facaf0a7d7d42cc2` (openai/o-series/claude/gemini/
    # generic), `39dc50c8b86d4d5a` (glm/qwen/kimi/seed, which keep the clause)
    # and `c1ca290f81f71243` (gemma, one turn). The plain spec moves the same
    # way: `6a1dc6ce88af944c` -> `a2bf3e4ab0b59ece` / `f55bd54f11ab9c5d` /
    # `4a14146d7fc7d17e`. `_VERDICT_SCHEMA_VERSION` MOVES WITH IT — every
    # cached verdict was produced under the pre-flip prompt.
    version=6,
    fragments=(
        "validate/role",
        "core/untrusted",
        "validate/language_idioms",
        "validate/calibration",
        "validate/closure",
        "validate/evidence_citation",
        # Between the citation rules and the output contract, not at the end:
        # `validate/tool_discipline` must stay LAST so `VALIDATE_JUDGE_PLAIN`
        # can keep slicing it off, and the clause belongs with the contract
        # whose free-text `reasoning` it constrains. The seam is the ordinary
        # blank line — `validate/output_contract`'s `keep_trailing` terminator
        # and `validate/tool_discipline`'s `seam: tight` still meet each other
        # exactly as before, so the three-newline live seam is untouched.
        "core/language",
        "validate/output_contract",
        "validate/tool_discipline",
    ),
    user_fragments=("validate/user_template",),
    tools=("read_file", "search_pattern", "parse_ast"),
    # The three untrusted channels this turn actually feeds. DESC and CODE are
    # per-finding blocks `_render_user_message` builds; TOOL is whatever the
    # three tools above return, mid-loop, from files the MODEL chose — the
    # largest attacker-influenced surface in the tier and the one the pre-4.3
    # policy never mentioned, because a policy keyed on marker pairs can only
    # describe channels that already have markers and this one had none.
    channels=("DESC", "CODE", "TOOL"),
    schema_fields=tuple(f.name for f in VERDICT_SCHEMA.fields),
    allow=_JUDGE_ALLOW,
)

# The SECOND system turn the judge actually sends. `_judge_batch` prefers the
# tool-equipped path, but a provider that rejects `tools=` degrades to plain
# judging (`_call_with_strict_retry` -> `_call_llm`), and a run with no source
# root never gets a tool executor at all — both send `prompts/validate_judge.txt`
# with NO tool contract appended. That is a different prompt, so it is a
# different spec with its own golden, rather than a substring of this one taken
# on trust: without it the flip would have had to keep reading the file for the
# no-tools path and only half the call site would have moved.
#
# `fragments` is sliced off VALIDATE_JUDGE instead of being restated so the two
# cannot drift in the seven sections they share; only the tool contract differs.
# The user turn is identical (`_judge_batch` renders `user_msg` once, before it
# knows which path it will take), so it is shared by reference too.
VALIDATE_JUDGE_PLAIN = PromptSpec(
    id="validate_judge_plain",
    tier="validate",
    version=6,                                  # item 4.1, with VALIDATE_JUDGE
    fragments=VALIDATE_JUDGE.fragments[:-1],
    user_fragments=VALIDATE_JUDGE.user_fragments,
    tools=(),
    # Two channels, not three. Dropping `validate/tool_discipline` drops the
    # tools with it, so this turn feeds no TOOL bytes and must not claim to:
    # `check_05_slot_marking` would be satisfied either way (`core/untrusted`
    # names all six), so an over-declaration here would be a claim nothing
    # falsifies — which is the property that let the pre-4.3 policy stand.
    channels=("DESC", "CODE"),
    schema_fields=VALIDATE_JUDGE.schema_fields,
    # Same three as VALIDATE_JUDGE: dropping `validate/tool_discipline` removes
    # the tier's only PERMITS_TOOL_USE fragment, but `tools=()` drops the
    # attachment with it, so `check_11` stays silent rather than newly firing.
    allow=_JUDGE_ALLOW,
)
