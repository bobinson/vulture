"""GENERATE tier — the scan agents' LLM detection call. Feature 0089 Phase 0.c.

One spec per agent that HAS an LLM generate path. There are seven: `owasp` is
absent because it is a categorizer over the CWE agent's findings with no LLM
path and no instructions to transcribe (feature 0063).

Assembly order is `_collect_llm_findings_async`'s, not a tidier one:

  SYSTEM  domains/<agent>          the agent's identity (Phase 2.5: rendered
                                   from this fragment at the agent's own call
                                   site; before it, the agent's INSTRUCTIONS)
          generate/vocab_category  += _category_vocabulary_suffix(...)
          generate/json_fenced     += the unstructured fence block
  USER    generate/field_contract  _build_llm_prompt: *_field_contract()
          generate/quote_obligation                   ... + the 0076 obligation
          generate/source_inline                      ... + the source tail

Three branches of the live builder are deliberately NOT in these specs, and
each is a Phase 2 renderer decision rather than a call-site one:

* `generate/source_in_system` — the anthropic-only path that moves the source
  body into the system message for prompt caching. Whether source belongs in
  the system turn is `ModelProfile`, not agent identity.
* `generate/source_in_system_ref` — the user-turn pointer that path substitutes
  for the source body.
* `generate/tools_only` — reached only when the source context is EMPTY, and
  the sole sentence in the whole tier that permits tool use. Three file tools
  are attached on every call regardless, so `check_11_tool_announcement` fires
  on all seven specs. That finding is the point; it is not fixed by listing an
  unreachable fragment here.

`generate/field_contract` and `generate/json_fenced` BOTH declare the eight
field names, so `check_02_duplicate_contract` fires on all seven specs, not
just on the two agents that ship their own "## Reporting Format" block. That is
not an artefact of the fragment boundary: the two are separate sentences in
separate roles, appended by separate branches, and
`audit_runner._quote_contract_suffix`'s own docstring calls them "one policy
written twice, in two places that are edited independently". Contrast
`generate/quote_obligation`, which names `evidence_quote` and deliberately does
NOT declare it — it and `generate/field_contract` are two halves of the single
list `_field_contract()` returns, so declaring both would manufacture a
duplication that does not exist in the prompt.

One live placement is still untranscribed: `_quote_contract_suffix()` appends
the SAME obligation sentence to the SYSTEM turn in the unstructured branch, so
that sentence really occupies both roles. These specs carry only the user-turn
copy, which means the tier's transcription under-reports the quote sentence's
duplication even now that the field list's is visible. `Role.SYSTEM_USER_MIRROR`
is the mechanism for it; wiring it is a Phase 2 renderer decision.

`generate/json_fenced` IS listed even though the live builder appends it only
when `supports_structured_output` is false: it carries `REQUIRES_FENCE`, and
`render`'s ADAPT rule 4+5 drops it for a profile whose API can enforce the
shape. Which is the whole reason the stance exists.
"""

from __future__ import annotations

from ..backlog import LANGUAGE_PIN, OWNER
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
# in audit_runner) that NO fragment in this tier states — every out-of-set
# value is silently coerced to `info` after the fact. Declared here so
# `check_04_vocab_closure` reports the gap rather than the gap staying
# invisible. `category` is deliberately absent: `generate/vocab_category`
# does state it, per run, from the agent's declared enum.
_VOCABULARY: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("severity", ("critical", "high", "medium", "low", "info")),
)

# Attached on EVERY generate call, confined to the audit source root.
_TOOLS: tuple[str, ...] = ("read_file", "list_files", "search_pattern")

# `generate/quote_obligation` is listed in BOTH turns because the live builder
# emits it twice per call: once in the user turn via `_field_contract()` and
# again in the system turn via `_quote_contract_suffix()`. Note the system copy
# exists ONLY on the unstructured branch, so a structured-output model sees the
# sentence once and an LM Studio / Gemini model sees it twice. That asymmetry is
# a Phase 4 question; Phase 1 reproduces it.
_SYSTEM_SUFFIX: tuple[str, ...] = (
    "generate/vocab_category", "generate/json_fenced", "generate/quote_obligation",
)
_USER_TURN: tuple[str, ...] = (
    "generate/task", "generate/field_contract", "generate/quote_obligation",
    "generate/source_inline",
)


# ── promptlint exemptions (Phase 3 gate) ──────────────────────────────────
#
# Everything the tier trips is a transcription of what the live builder emits
# today, so all of it is annotated rather than fixed here: Phase 1 recorded the
# "before" and changing a fragment now would erase it. Each entry names the
# Phase 4 item that owns the fix.
#
# `language_pin` and `tool_announcement` key on the SPEC id (their findings
# report `spec.id`, not a fragment), so they cannot live in a flat shared tuple
# — hence the builder.

def _tier_allow(spec_id: str) -> tuple[LintAllow, ...]:
    """The six exemptions every GENERATE spec carries."""
    return (
        LintAllow("language_pin", spec_id, owner=OWNER, reason=LANGUAGE_PIN),
        LintAllow(
            "tool_announcement", spec_id, owner=OWNER,
            reason="Phase 4.4 — `generate/tools_only` is the tier's only "
                   "PERMITS_TOOL_USE fragment and the live builder appends it "
                   "ONLY when the source context is empty, yet three file "
                   "tools are attached on every call. Listing it here would "
                   "assert a permission the prompt does not give; 4.4 adds "
                   "`generate/tool_trigger` on every branch with the real "
                   "budget.",
        ),
        LintAllow(
            "vocab_closure", "-", owner=OWNER,
            reason="Phase 4.4 — DELIBERATE. `_VOCABULARY` above declares "
                   "`severity`'s closed set precisely so this check reports "
                   "that no fragment states it; every out-of-set value is "
                   "silently coerced to `info` after the fact. Dropping the "
                   "declaration would hide the gap, not close it.",
        ),
        LintAllow(
            "duplicate_contract", "generate/field_contract", owner=OWNER,
            reason="Phase 4.4 — `generate/field_contract` (user turn) and "
                   "`generate/json_fenced` (system turn) declare the SAME "
                   "eight field names, so the contract is stated twice per "
                   "render. Recorded alongside it: `_quote_contract_suffix()` "
                   "emits the quote obligation a second time in the system "
                   "turn on the unstructured branch only, so a "
                   "structured-output model sees that sentence once and an LM "
                   "Studio / Gemini model twice.",
        ),
        LintAllow(
            "duplicate_contract", "generate/json_fenced", owner=OWNER,
            reason="Phase 4.4 — the second half of the field-list duplication "
                   "described on the `generate/field_contract` entry. Note the "
                   "check reads `spec.fragments`, so it reports this fragment "
                   "even for a profile whose ADAPT render drops it under rule "
                   "4+5 (REQUIRES_FENCE).",
        ),
        LintAllow(
            "placeholder_echo", "generate/json_fenced", owner=OWNER,
            reason="Phase 4.4 — the `...` here is fence-syntax illustration "
                   "('Wrap the array in ```json ... ``` fences'), not an "
                   "exemplar value an executor could send. It is reported "
                   "because `_PLACEHOLDERS` carries a bare `...`; 4.4 reviews "
                   "that entry with the tier's other prompt work.",
        ),
    )


# `domains/asvs` is a THIRD fragment declaring the field list, and the only one
# declaring a field no schema has.
_ASVS_ALLOW: tuple[LintAllow, ...] = (
    LintAllow(
        "duplicate_contract", "domains/asvs", owner=OWNER,
        reason="Phase 4.4 — `domains/asvs` ships its own '## Reporting "
               "Format' block, making it a THIRD fragment declaring the field "
               "list in this render.",
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
    LintAllow(
        "duplicate_contract", "domains/cwe", owner=OWNER,
        reason="Phase 4.4 — `domains/cwe` also ships a '## Reporting Format' "
               "block, so this render states the field contract three times.",
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
    fragments=("domains/chaos", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/chaos"),
)

SOC2 = PromptSpec(
    id="generate/soc2", tier="generate",
    fragments=("domains/soc2", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/soc2"),
)

SSDF = PromptSpec(
    id="generate/ssdf", tier="generate",
    fragments=("domains/ssdf", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/ssdf"),
)

DO178C = PromptSpec(
    id="generate/do178c", tier="generate",
    fragments=("domains/do178c", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/do178c"),
)

# `domains/asvs` carries its own "## Reporting Format" field list AND declares
# `linked_cwe`, which no schema has: a THIRD declaring fragment on top of the
# tier-wide pair below, plus orphan_field.
ASVS = PromptSpec(
    id="generate/asvs", tier="generate",
    fragments=("domains/asvs", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/asvs") + _ASVS_ALLOW,
)

# `domains/cwe` also carries a "## Reporting Format" field list, so this render
# states the contract three times. Not merged — the duplication is the finding.
CWE = PromptSpec(
    id="generate/cwe", tier="generate",
    fragments=("domains/cwe", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/cwe") + _CWE_ALLOW,
)

XSS = PromptSpec(
    id="generate/xss", tier="generate",
    fragments=("domains/xss", *_SYSTEM_SUFFIX),
    user_fragments=_USER_TURN,
    schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    allow=_tier_allow("generate/xss"),
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
#                            context — the tier's only sentence that permits
#                            tool use)
#   vocabulary=  the agent passed a non-empty `category_enum`; mirrors
#                `_category_vocabulary_suffix()` returning "" for a falsy one.
#   fenced=      `not supports_structured_output(model)` — the API cannot
#                enforce the shape, so the prose contract must.
#   quote=       `VULTURE_LLM_QUOTE_REQUIRED`, read at call time (0076 D14).
#   prior=       the memory bank returned context for this codebase.
#
# KNOWN ASYMMETRY, reproduced deliberately (Phase 4.4 owns the fix): the quote
# obligation is emitted twice per call — user turn via `_field_contract()`,
# system turn via `_quote_contract_suffix()` — and the SYSTEM copy exists only
# on the unstructured branch. Hence `fenced and quote` below, against a bare
# `quote` in the user turn. A structured-output model sees the sentence once
# and an LM Studio / Gemini model sees it twice.

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
        ([] if vocabulary else ["generate/vocab_category"])
        + ([] if fenced else ["generate/json_fenced"])
        + ([] if fenced and quote else ["generate/quote_obligation"]),
    )
    user = _keep(_USER_TURN, frozenset(
        ([] if quote else ["generate/quote_obligation"])
        + ["generate/source_inline"],
    ))
    return PromptSpec(
        id="generate/live", tier="generate",
        fragments=(*_SOURCE_SYSTEM[source], *_keep(_SYSTEM_SUFFIX, drop)),
        user_fragments=(
            *user,
            *(("generate/prior_context",) if prior else ()),
            _SOURCE_USER[source],
        ),
        schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
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


def domain_instructions(*fragments: str) -> str:
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

    Mode is TRANSCRIBE, so `profile_for()` reaches nothing but
    `output_budget_hint` — which this discards — and the ambient model therefore
    cannot move a prompt byte. It is resolved rather than faked because a future
    ADAPT render needs the real one.
    """
    if not fragments:
        raise ValueError("domain_instructions() needs at least one fragment id")
    spec = PromptSpec(
        id="generate/domain", tier="generate", fragments=fragments,
        schema_fields=_SCHEMA_FIELDS, vocabulary=_VOCABULARY, tools=_TOOLS,
    )
    return render(spec, profile_for(), mode=Mode.TRANSCRIBE).instructions
