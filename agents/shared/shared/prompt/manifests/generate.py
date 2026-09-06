"""GENERATE tier — the scan agents' LLM detection call. Feature 0089 Phase 0.c.

One spec per agent that HAS an LLM generate path. There are seven: `owasp` is
absent because it is a categorizer over the CWE agent's findings with no LLM
path and no instructions to transcribe (feature 0063).

ITEM 4.4 IS WHERE THIS TIER STOPPED BEING A TRANSCRIPTION. Phases 0-3 held the
bytes still; 4.4 flips both of the tier's call sites to `Mode.ADAPT` and adds
four sentences the prompt never had. Assembly is now:

  SYSTEM  domains/<agent>              the agent's identity (Phase 2.5:
                                       rendered at the agent's own call site)
          core/untrusted               the by-channel distrust policy (4.3)
          generate/source_presentation the `--- path ---` / `NN: ` contract
          generate/evidence_discipline what the shown bytes may support
          generate/tool_trigger        when to call a tool, and the budget
          generate/vocab_category      the agent's per-run category enum
          generate/vocab_severity      the closed severity set
          core/language                output language (4.8, BINDS_LANGUAGE)
          generate/json_fenced         the wire shape (REQUIRES_FENCE)
  USER    generate/task
          generate/field_contract      the eight field names — ONE author now
          generate/quote_obligation    the 0076 obligation, stated once
          generate/source_inline       the packed source listing

Three branches of the live builder are deliberately NOT in these specs, and
each is a renderer decision rather than a call-site one:

* `generate/source_in_system` — the anthropic-only path that moves the source
  body into the system message for prompt caching. Whether source belongs in
  the system turn is `ModelProfile`, not agent identity.
* `generate/source_in_system_ref` — the user-turn pointer that path substitutes
  for the source body.
* `generate/tools_only` — reached only when the source context is EMPTY. Until
  4.4 it was the sole sentence in the whole tier that permitted tool use, while
  three file tools were attached on EVERY call, so `check_11_tool_announcement`
  fired on all seven specs. `generate/tool_trigger` is the fix: it is on every
  branch, so the permission is stated wherever the tools are attached.

WHAT 4.4 RESOLVED, AND WHAT IT DID NOT. The eight-field contract had two
authors — `generate/field_contract` in the user turn and `generate/json_fenced`
in the system turn, which `audit_runner._quote_contract_suffix`'s docstring
called "one policy written twice, in two places that are edited independently".
`generate/json_fenced` now states the WIRE SHAPE only and declares no fields,
so five of the seven renders declare the list exactly once. cwe and asvs still
declare it twice because their `domains/` fragment carries a "## Reporting
Format" block of its own; that half belongs to the agent identity, not to this
tier, and is annotated (`_own_field_list_allow`).

The quote obligation had the same shape and a worse symptom: `_field_contract()`
emitted it in the user turn and `_quote_contract_suffix()` again in the system
turn, but only on the unstructured branch — so a structured-output model saw it
once and an LM Studio / Gemini model twice, a count that turned on a capability
with nothing to do with evidence. It is now stated once, in the user turn, for
every profile, and `_quote_contract_suffix()` is gone from `audit_runner`.

`generate/json_fenced` IS listed even though the live builder appended it only
when `supports_structured_output` is false: it carries `REQUIRES_FENCE`, and
`render`'s ADAPT rule 4+5 drops it for a profile whose API can enforce the
shape. Which is the whole reason the stance exists — and why the call site
renders against a profile whose `structured` reflects THIS endpoint, not just
the model family (see `audit_runner._generate_rendered`).
"""

from __future__ import annotations

from ..backlog import OWNER
from ..lint import LintAllow
from ..profile import profile_for
from ..render import Mode, render
from ..spec import PromptSpec

# `_MODEL_VISIBLE_FIELDS` + the 0076 quote field: the projection of
# `AuditFinding` the model is actually shown. `linked_cwe` is NOT here, which
# is why `domains/asvs` DECLARING it is an orphan_field finding. Phase 2.5
# removed the line that asked the model for it; the declaration is retained on
# purpose so the check keeps reporting the unschema'd name (see `_ASVS_ALLOW`).
_SCHEMA_FIELDS: tuple[str, ...] = (
    "severity", "category", "title", "description",
    "file_path", "line_start", "line_end", "recommendation",
    "evidence_quote",
)

# `severity` has a closed vocabulary (`_SEVERITY_WEIGHTS` / `_SEVERITY_ALIASES`
# in audit_runner) and every out-of-set value is coerced to `info` after the
# fact by `normalize_severity`. Phase 0.c declared it here with NO binding
# fragment on purpose, so `check_04_vocab_closure` would report that the prompt
# never stated the set; item 4.4 adds `generate/vocab_severity`, which binds it
# in the front matter, so the check now passes and that annotation is retired.
# `category` is deliberately absent: `generate/vocab_category` states it per
# run, from the agent's declared enum.
_VOCABULARY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("severity", ("critical", "high", "medium", "low", "info")),
)

# Attached on EVERY generate call, confined to the audit source root.
_TOOLS: tuple[str, ...] = ("read_file", "list_files", "search_pattern")

# The system turn, in the order the model reads it: the distrust policy governs
# everything after it; the presentation contract says how to read the listing;
# evidence discipline says what may be reported from it; the tool trigger says
# when to look past it; the two vocabularies close the enum fields; `core/
# language` closes the free-text ones (item 4.8); the wire shape comes last and
# is dropped for a profile whose API can enforce it.
#
# `core/language` sits with the vocabularies and not at the end because it is
# the third field-level constraint, not part of the wire shape: `vocab_category`
# and `vocab_severity` close the two enum fields, and it closes `title`,
# `description` and `recommendation`. It is also the one section of this turn
# whose presence depends on the model rather than on the run — rule 9 drops it
# for the six families that do not drift — so putting it before
# `generate/json_fenced`, which rule 4+5 already drops per profile, keeps both
# conditional sections adjacent instead of straddling the contract.
#
# `generate/quote_obligation` is NOT here as of item 4.4. Until then it was
# listed in BOTH turns, because the live builder emitted it twice per call —
# once in the user turn via `_field_contract()` and again in the system turn via
# `_quote_contract_suffix()`, the second only on the unstructured branch, so a
# structured-output model saw the sentence once and an LM Studio / Gemini model
# twice. It is now stated exactly once, in the USER turn: that is the turn no
# gateway drops, so single placement buys the protection `SYSTEM+USER_MIRROR`
# existed to buy by duplication. A mirror listing could not have served — ADAPT
# prepends a mirrored fragment to the user turn WITHOUT removing it from the
# system turn, so a fragment listed in both turns AND mirrored renders three
# times.
_SYSTEM_SUFFIX: tuple[str, ...] = (
    "core/untrusted",
    "generate/source_presentation",
    "generate/evidence_discipline",
    "generate/tool_trigger",
    "generate/vocab_category",
    "generate/vocab_severity",
    "core/language",
    "generate/json_fenced",
)

# The channels this tier feeds. SOURCE is the packed `--- rel ---` file blocks
# `generate/source_inline` (or `generate/source_in_system`) carries; TOOL is
# whatever the three file tools above return. Item 4.3 added both, and the
# marking they get is the by-channel DISTRUST statement, not a nonce delimiter:
# the source blocks are still delimited by `--- rel ---`, which is
# attacker-influenced (it is built from a filename) and is simultaneously a
# production parser boundary (`_FILE_BLOCK_HEADER_RE`). Item 4.4 added
# `generate/source_presentation`, which DESCRIBES that delimiter to the model
# so a claimed `file_path` and `line_start` can be read off it — it does not
# convert the source to a nonce-wrapped `Slot`. That conversion stays open: a
# Slot moves the source body inside `<<<SOURCE:TOKEN` markers minted per
# render, and this tier renders its two turns from two SEPARATE renders, so it
# needs a shared nonce before it can have a shared marker. What 4.3 fixes is
# that the tier had no untrusted
# fragment AT ALL: raw repository source was inlined with zero marking
# (`audit_runner.py:3038`, 0089 LLD §9.2) and nothing told the model that the
# bytes between the dashes were data.
_CHANNELS: tuple[str, ...] = ("SOURCE", "TOOL")

_USER_TURN: tuple[str, ...] = (
    "generate/task", "generate/field_contract", "generate/quote_obligation",
    "generate/source_inline",
)


# ── promptlint exemptions (Phase 3 gate) ──────────────────────────────────
#
# ITEM 4.8 EMPTIED THE TIER-WIDE BUILDER, so the builder is gone with it. Every
# GENERATE spec carried exactly one exemption in common — `language_pin`,
# because no fragment in the library declared `BINDS_LANGUAGE` at all — and
# `core/language` in `_SYSTEM_SUFFIX` above retires all seven of those at once.
# Five agents therefore carry NO annotation now (`allow=()` is written out at
# each of them rather than left to a helper that returns an empty tuple: an
# empty exemption list is a fact about that spec, and a call returning `()`
# reads as a list somebody forgot to fill).
#
# cwe and asvs keep only what their own `domains/` fragment causes.
#
# Item 4.4 retired five more before 4.8, and each was retired by the prompt
# change the entry named rather than by deleting the entry:
#
#   * `tool_announcement` — `generate/tool_trigger` is on every branch now, so
#     the three file tools attached to every call are positively permitted by a
#     sentence the model is actually shown.
#   * `vocab_closure` — `generate/vocab_severity` binds the closed set, which
#     needed `parse_fragment` to start reading a `binds_vocabulary:` key at all
#     (it hardcoded `()` before, so no fragment on disk could close one).
#   * `duplicate_contract` on `generate/json_fenced` — that fragment states the
#     wire shape and no longer enumerates the eight field names.
#   * `duplicate_contract` on `generate/field_contract` — retired for the five
#     agents whose domain fragment ships no field list of its own.
#   * `placeholder_echo` on `generate/json_fenced` — the fence-syntax
#     illustration lost the ellipsis `check_09` reported.


# cwe and asvs ship their own "## Reporting Format" block inside the agent
# identity, so those two renders still state the field list twice and
# `check_02` still reports BOTH declaring fragments. The remaining half cannot
# be fixed from this tier: the block is the agent's own INSTRUCTIONS text, which
# `tests/unit/prompt/test_0089_no_second_source_of_truth.py` pins byte-for-byte
# against the constant those agents' own unit tests assert on.
def _own_field_list_allow(spec_id: str) -> LintAllow:
    return LintAllow(
        "duplicate_contract", "generate/field_contract", owner=OWNER,
        reason=f"Phase 4.4 — {spec_id} keeps one half of the field-list "
               "duplication: its `domains/` fragment carries a '## Reporting "
               "Format' block of its own, so `generate/field_contract` is the "
               "second declaring fragment in this render. The tier's own half "
               "(`generate/json_fenced`) was resolved; this one belongs to the "
               "agent identity and is annotated rather than fixed here.",
    )


# `domains/asvs` is a THIRD fragment declaring the field list, and the only one
# declaring a field no schema has.
_ASVS_ALLOW: tuple[LintAllow, ...] = (
    _own_field_list_allow("generate/asvs"),
    LintAllow(
        "duplicate_contract", "domains/asvs", owner=OWNER,
        reason="Phase 4.4 — `domains/asvs` ships its own '## Reporting "
               "Format' block, so it is the SECOND fragment declaring the "
               "field list in this render (it was the third until 4.4 stopped "
               "`generate/json_fenced` declaring one).",
    ),
    LintAllow(
        "orphan_field", "domains/asvs", owner=OWNER,
        reason="Phase 4.4 — the PROMPT half is fixed: Phase 2.5 removed the "
               "'- linked_cwe (optional)' line from `domains/asvs` (and from "
               "the agent's byte oracle in the same change), so the model is "
               "no longer asked for a field that `_SCHEMA_FIELDS` / "
               "`_MODEL_VISIBLE_FIELDS` drop on parse. The finding still "
               "fires because `declares_fields` retains the name, and that "
               "declaration is deliberately kept: `check_01_orphan_field` "
               "reads metadata, not prose, and it is the only signal that "
               "`linked_cwe` remains unschema'd. 4.4 reconciles the "
               "declaration with the text it now describes.",
    ),
)

_CWE_ALLOW: tuple[LintAllow, ...] = (
    _own_field_list_allow("generate/cwe"),
    LintAllow(
        "duplicate_contract", "domains/cwe", owner=OWNER,
        reason="Phase 4.4 — `domains/cwe` also ships a '## Reporting Format' "
               "block, so this render still states the field contract twice "
               "(three times until 4.4 resolved the tier's own half).",
    ),
    LintAllow(
        "placeholder_echo", "domains/cwe", owner=OWNER,
        reason="Phase 4.4 — the `...` is prose, not an exemplar: an ellipsis "
               "inside 'random.random/Math.random flowing into "
               "token|key|nonce...'. Nothing here is echoable to an executor; "
               "reported because `_PLACEHOLDERS` carries a bare `...`.",
    ),
)


CHAOS = PromptSpec(
    id="generate/chaos", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/chaos", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=(),
)

SOC2 = PromptSpec(
    id="generate/soc2", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/soc2", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=(),
)

SSDF = PromptSpec(
    id="generate/ssdf", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/ssdf", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=(),
)

DO178C = PromptSpec(
    id="generate/do178c", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/do178c", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=(),
)

# `domains/asvs` carries its own "## Reporting Format" field list AND declares
# `linked_cwe`, which no schema has: a THIRD declaring fragment on top of the
# tier-wide pair below, plus orphan_field.
ASVS = PromptSpec(
    id="generate/asvs", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/asvs", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=_ASVS_ALLOW,
)

# `domains/cwe` also carries a "## Reporting Format" field list, so this render
# states the contract three times. Not merged — the duplication is the finding.
CWE = PromptSpec(
    id="generate/cwe", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/cwe", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=_CWE_ALLOW,
)

XSS = PromptSpec(
    id="generate/xss", tier="generate",
    version=5,                       # item 4.8: core/language (4.7 -> 4)
    fragments=("domains/xss", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    channels=_CHANNELS,
    allow=(),
)


GENERATE_SPECS: dict[str, PromptSpec] = {
    "chaos": CHAOS,
    "soc2": SOC2,
    "ssdf": SSDF,
    "do178c": DO178C,
    "asvs": ASVS,
    "cwe": CWE,
    "xss": XSS,
}


# ── the live call site's spec (feature 0089 Phase 2.3, 2.5) ───────────────
#
# `shared.audit_runner` renders THIS, not one of the seven specs above, and the
# reason is `instructions`. The agent's system prompt still reaches the runner
# as a plain string parameter — `run_combined_audit(instructions=...)`, which
# `shared/audit_kwargs.py` records as a standing call-site contract — so
# `domains/<agent>`, the ONLY fragment the seven differ by, is not an id the
# runner resolves. What Phase 2.5 changed is where that string comes FROM: the
# agent renders it with `domain_instructions()` below instead of handing over
# its own `INSTRUCTIONS` constant. This spec deliberately still lists no domain
# fragment, which is what makes the identity's single channel structural rather
# than a convention — see `_generate_system_prompt`'s docstring.
#
# What is left after the identity is exactly this tier's shared halves, which is
# why they are named once, here, and shared by both: the seven specs and
# `live_spec()` read the same `_SYSTEM_SUFFIX` / `_USER_TURN` tuples, so a
# fragment added to the transcription cannot go missing from production.
#
# Every parameter below is a branch the live builder already took, and each is
# the call site's to decide rather than the renderer's under TRANSCRIBE:
#
#   source=      "inline" -> generate/source_inline        (the ordinary path)
#                "system" -> generate/source_in_system + _ref  (anthropic
#                            prompt caching: the body moves to the system turn
#                            and the user turn gets a pointer to it)
#                "none"   -> generate/tools_only           (empty source
#                            context; `generate/tool_trigger` is on every
#                            branch, so this is a task sentence now, not the
#                            tier's only tool permission)
#   vocabulary=  the agent passed a non-empty `category_enum`; mirrors
#                `_category_vocabulary_suffix()` returning "" for a falsy one.
#   fenced=      `not supports_structured_output(model)` — the API cannot
#                enforce the shape, so the prose contract must.
#   quote=       `VULTURE_LLM_QUOTE_REQUIRED`, read at call time (0076 D14).
#   prior=       the memory bank returned context for this codebase.
#
# THE ASYMMETRY IS GONE (item 4.4). `quote` now gates exactly one listing, in
# the user turn. It used to gate two — `fenced and quote` on the system side
# against a bare `quote` on the user side — which is how the number of times a
# model was told to quote its evidence came to depend on whether its endpoint
# could enforce a JSON schema.

_SOURCE_SYSTEM: dict[str, tuple[str, ...]] = {
    "system": ("generate/source_in_system",),
    "inline": (),
    "none": (),
}
_SOURCE_USER: dict[str, str] = {
    "system": "generate/source_in_system_ref",
    "inline": "generate/source_inline",
    "none": "generate/tools_only",
}


def _keep(ids: tuple[str, ...], drop: frozenset[str]) -> tuple[str, ...]:
    return tuple(i for i in ids if i not in drop)


def _when(flag: bool, *ids: str) -> tuple[str, ...]:
    """`ids` when `flag`, otherwise nothing.

    A named conditional so `live_spec` below reads as the branch table it is.
    The five booleans it takes are per-run facts, and spelling each one as an
    inline `(...) if flag else ()` put six ternaries in one function — the
    branches were the noise, not the information.
    """
    return ids if flag else ()


def _unless(flag: bool, *ids: str) -> list[str]:
    """The fragment ids to DROP when `flag` is false. The inverse of `_when`.

    Separate from `_when` because the two feed opposite sides: `_when` builds a
    fragment list, `_unless` builds the drop set `_keep` filters against, and
    collapsing them into one helper with a polarity argument would put the
    branch back.
    """
    return [] if flag else list(ids)


def live_spec(
    *,
    source: str,
    vocabulary: bool,
    fenced: bool,
    quote: bool,
    prior: bool,
    variables: dict | None = None,
) -> PromptSpec:
    """The spec one live generate call renders, minus `domains/<agent>`.

    Built per call rather than shipped as a module-level constant: the five
    booleans are per-run facts (the model's capabilities, the operator's
    switches, whether memory had anything to say), and TRANSCRIBE renders every
    fragment a spec lists — so the branch has to be in the fragment LIST, which
    is where the live builder's `if`s already put it.

    Not a member of `MANIFESTS`, deliberately. The registry collects
    module-level `PromptSpec` literals, and a spec whose fragment list depends
    on five arguments has no single golden render to commit and no single lint
    verdict to annotate; the seven specs above are the committed transcription
    of this tier and they carry both.
    """
    drop = frozenset(
        _unless(vocabulary, "generate/vocab_category")
        + _unless(fenced, "generate/json_fenced"),
    )
    user = _keep(_USER_TURN, frozenset(
        _unless(quote, "generate/quote_obligation")
        + ["generate/source_inline"],
    ))
    return PromptSpec(
        id="generate/live", tier="generate",
        fragments=(*_SOURCE_SYSTEM[source], *_keep(_SYSTEM_SUFFIX, drop)),
        user_fragments=(
            *user,
            *_when(prior, "generate/prior_context"),
            _SOURCE_USER[source],
        ),
        schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
        # Per BRANCH, not the tier constant: `source="none"` inlines no
        # repository bytes at all, and PRIOR only arrives when the memory bank
        # had something to say. The seven committed specs transcribe the
        # ordinary path and carry `_CHANNELS`; this is the one place the set
        # actually varies, and declaring it accurately here is what keeps
        # `check_05` a statement about the render rather than about the tier.
        channels=(*_when(source != "none", "SOURCE"), "TOOL",
                  *_when(prior, "PRIOR")),
        variables=variables or {},
    )


# ── the agent identity, from the library (feature 0089 Phase 2.5) ─────────
#
# The last call-site flip. Until now `domains/<agent>` was transcribed and
# proven byte-exact but UNREAD by production: every agent handed its own
# `INSTRUCTIONS` constant to `run_combined_audit(instructions=...)` and
# `_generate_system_prompt` joined that string to the library's suffix. This is
# the function that reverses the authority — each agent now names its fragment
# id at its own call site and the library produces the bytes.
#
# WHY THE CALL SITE AND NOT THE RUNNER. `run_combined_audit` could have taken a
# fragment-id list and resolved it internally, and that was considered. Three
# things decided against it. (1) It is the shape the three flips before this one
# already use: `discover/llm_suggest` renders `DISCOVER_SUGGEST` in the plugin,
# `validate/llm_judge` renders `VALIDATE_JUDGE` in the judge, and
# `prove/strategies/*` render `prove/plan` with their own domain slots — the
# owning module renders and passes a string on. (2) `instructions` is BOTH the
# prompt head and the flag that arms the LLM phase (`if effective_use_llm and
# skill_tools and instructions`), so a design that empties it to make room for a
# fragment list silently disarms the phase for the five agents with nothing else
# to say. (3) asvs and cwe append a per-run catalog block to their identity; as
# a string concatenation at the call site that is byte-neutral and needs no new
# channel, whereas a runner that owned the whole system turn would need one.
#
# The consequence is that the identity is rendered exactly ONCE, structurally:
# there is one channel into the system turn, so the double-render hazard of a
# fragment list ALONGSIDE a still-populated `instructions=` cannot arise.
#
# Not a member of `MANIFESTS`, for `live_spec`'s reason: the fragment list is an
# argument, so there is no single golden render to commit and no single lint
# verdict to annotate. The seven specs above are this tier's committed
# transcription and they carry both.


def domain_instructions(*fragments: str, model: str | None = None) -> str:
    """Render the SYSTEM-turn identity half of one generate call.

    `fragments` is the call site's EXPLICIT list, one id per line, resolved in
    the order given — no tier inheritance and no computed list, per 0089 §3.3.
    Every agent passes exactly one id today; the signature is plural because a
    list is what a call site declares, not because anything splits it.

    Byte-neutral by construction and measured as such: for all seven agents the
    render equals that agent's `INSTRUCTIONS` oracle exactly (asvs 1715B, chaos
    268B, cwe 3437B, do178c 470B, soc2 327B, ssdf 378B, xss 1641B). The two
    trailing-newline cases (asvs, xss) survive because their fragments declare
    `keep_trailing`; `render`'s join would otherwise strip the byte their live
    prompts carry.

    ITEM 4.4 FLIPPED THE MODE TO ADAPT, and this render is still byte-neutral
    across all ten families — `test_0089_4_4_generate_adapt.py` asserts it per
    agent, per family. It flips with `_generate_rendered` because the two
    compose the two halves of ONE system message and rendering them under two
    rule sets would be incoherent, not because a rule bites here: a `domains/`
    fragment carries neither `REQUIRES_FENCE` (rule 4+5) nor `BINDS_LANGUAGE`
    (rule 9), so the only rule that can reach it is the no-system-role fold —
    and this function returns ONE string for ONE channel, which the caller
    hands to `run_combined_audit(instructions=...)` either way. `.instructions
    or .user` is that fold's inverse: a relocation with nowhere to relocate to.

    The identity of a no-system-role family (gemma) is therefore still sent as
    a system message the chat template may drop. That is unchanged by 4.4 and
    not fixable here — `instructions` is a runner parameter, so folding it into
    the user turn is a `run_combined_audit` signature question, not a render.

    `model` resolves the profile, defaulting to the ambient one. It is resolved
    to a model STRING before `profile_for` sees it: that function is
    `lru_cache`d on its argument, so `profile_for()` caches whatever the first
    caller's environment resolved to under the key `None` for the life of the
    process. Harmless while the mode was TRANSCRIBE (the profile reached
    nothing but a discarded budget hint); under ADAPT the profile decides
    placement, and a stale one decides it wrongly.
    """
    if not fragments:
        raise ValueError("domain_instructions() needs at least one fragment id")
    from shared.llm.provider import get_model

    spec = PromptSpec(
        id="generate/domain", tier="generate", fragments=fragments,
        schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    )
    rp = render(spec, profile_for(get_model(model)), mode=Mode.ADAPT)
    return rp.instructions or rp.user
