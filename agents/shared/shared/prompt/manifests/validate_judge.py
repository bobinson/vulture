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
the five names, in declaration order: `check_01_orphan_field` compares a
fragment's `declares_fields` against this tuple, so a second copy here is a
second place the L5 field list can drift from `llm_judge._coerce_verdict`.
(`validate/` itself has no schema constant to import — only
`_VERDICT_SCHEMA_VERSION` (`l5_cache.py:130`), which is a cache-key string.)

`slots` is empty on purpose. The user template still interpolates
`{audit_id}`, `{n}` and `{findings_block}` as raw text, and the finding block
is where the untrusted code and description bytes actually enter; converting
that to Slot() is Phase 2, and doing it here would change what the judge sends.
"""

from __future__ import annotations

from ..backlog import LANGUAGE_PIN, OWNER
from ..lint import LintAllow
from ..schema import VERDICT_SCHEMA
from ..spec import PromptSpec


def _judge_allow(spec_id: str) -> tuple[LintAllow, ...]:
    """The four exemptions both judge specs carry (they share seven sections)."""
    return (
        LintAllow("language_pin", spec_id, owner=OWNER, reason=LANGUAGE_PIN),
        LintAllow(
            "dangling_reference", "validate/evidence_citation", owner=OWNER,
            reason="Phase 4.2 — the fragment references `numbered_snippet`, "
                   "which this render neither declares as a variable nor "
                   "supplies as a slot, so the citation instruction points at "
                   "nothing the model can see. Resolving it needs the finding "
                   "block to become a real Slot, which is Phase 2.",
        ),
        LintAllow(
            "exemplar_validity", "validate/output_contract", owner=OWNER,
            reason="Phase 4.2 — the verdict exemplar uses angle-bracket type "
                   "placeholders (`\"exploitable\":<float 0..1>`), so the block "
                   "the model is shown is not parseable JSON.",
        ),
        LintAllow(
            "placeholder_echo", "validate/untrusted_warning", owner=OWNER,
            reason="Phase 4.2 — the `...` is marker-syntax documentation "
                   "(`<<<CODE ... CODE>>>`) telling the model where slot "
                   "content sits; it is not an exemplar value and nothing "
                   "echoes it. Reported because `_PLACEHOLDERS` carries a bare "
                   "`...`.",
        ),
    )


VALIDATE_JUDGE = PromptSpec(
    id="validate_judge",
    tier="validate",
    fragments=(
        "validate/role",
        "validate/untrusted_warning",
        "validate/language_idioms",
        "validate/calibration",
        "validate/closure",
        "validate/evidence_citation",
        "validate/output_contract",
        "validate/tool_discipline",
    ),
    user_fragments=("validate/user_template",),
    tools=("read_file", "search_pattern", "parse_ast"),
    schema_fields=tuple(f.name for f in VERDICT_SCHEMA.fields),
    allow=_judge_allow("validate_judge"),
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
    fragments=VALIDATE_JUDGE.fragments[:-1],
    user_fragments=VALIDATE_JUDGE.user_fragments,
    tools=(),
    schema_fields=VALIDATE_JUDGE.schema_fields,
    # Same four as VALIDATE_JUDGE: dropping `validate/tool_discipline` removes
    # the tier's only PERMITS_TOOL_USE fragment, but `tools=()` drops the
    # attachment with it, so `check_11` stays silent rather than newly firing.
    allow=_judge_allow("validate_judge_plain"),
)
