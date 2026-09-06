"""Item 4.4 — the GENERATE tier renders in ADAPT, and says four new things.

Feature 0089 Phase 4. The tier's two call sites (`audit_runner._generate_
rendered` and `manifests.generate.domain_instructions`) flip to `Mode.ADAPT`
together, because they compose the two halves of ONE system message and
rendering them under two rule sets would be incoherent.

WHAT THE ITEM CHANGES, AND WHAT EACH TEST HERE DEFENDS.

1. `generate/tool_trigger` — three file tools are attached on EVERY generate
   call and, before this item, not one sentence in the tier permitted using
   them: `generate/tools_only` is reachable only when the source context is
   empty. So `check_11_tool_announcement` fired on all seven specs and was
   annotated seven times. The new fragment states the trigger AND the budget,
   and the budget is read from `shared.llm.loop_detector` — the module whose
   `LoopDetector.record` actually returns KILL — rather than retyped, because
   a prompt that states a bound the runtime does not enforce is worse than one
   that states none.

2. `generate/vocab_severity` — `severity` has a closed set
   (`audit_runner._SEVERITY_WEIGHTS`) and `normalize_severity` silently maps
   everything else to `info`. No fragment stated it. The manifest declared the
   vocabulary with no binding fragment ON PURPOSE so `check_04_vocab_closure`
   would report the gap; this closes it, and that annotation retires.

3. `generate/evidence_discipline` — locate the claim accurately, look for the
   guard that would refute it, and open the file when the answer is off-screen.
   It carries NO abstention stance, and that is two findings at once. A draft
   closed with "if it is still undecidable after you have looked, say nothing
   about it", which 0076's AC20 lock caught as a suppression instruction — a
   prompt-level deletion mechanism sitting outside every switch. And a
   `BLESSES_ABSTENTION` declaration would have collided with item (1)'s
   `PERMITS_TOOL_USE` in `fragment.CONFLICTING`: a prompt that both hands a
   model tools and blesses not looking is the measured defect this library was
   built for.

4. `generate/source_presentation` — the `--- path ---` / `NN: ` contract. The
   model is asked for `file_path`, `line_start` and `line_end` against a
   listing whose shape nothing in the prompt described.

5. THE DUPLICATE CONTRACT, both halves.
   * The FIELD LIST was declared by `generate/field_contract` (user turn) and
     again by `generate/json_fenced` (system turn) — `_quote_contract_suffix`'s
     own docstring calls that "one policy written twice, in two places that are
     edited independently". `generate/json_fenced` now states the WIRE SHAPE
     only and declares no fields.
   * The QUOTE OBLIGATION was emitted twice per call — user turn via
     `_field_contract()`, system turn via `_quote_contract_suffix()` — and the
     system copy existed ONLY on the unstructured branch, so a structured-output
     model saw the sentence once and an LM Studio / Gemini model twice. It is
     now emitted exactly once, in the USER turn, for every profile. The user
     turn is the right survivor: it is the turn no gateway drops, so the
     `SYSTEM+USER_MIRROR` protection is preserved by placement rather than by
     duplication.

6. THE PROFILE MUST TELL THE TRUTH ABOUT THIS ENDPOINT. Under ADAPT, rule 4+5
   drops `REQUIRES_FENCE` fragments when `profile.structured is not NONE`. The
   call site's own `fenced=` is computed from `supports_structured_output()`,
   which is ALSO False for a custom endpoint (LM Studio, a gateway) — a
   transport fact the family profile does not carry. Left alone, an
   openai-family model behind a gateway would lose its prose JSON contract AND
   not be sent `output_type`: no contract at all. `_generate_rendered` therefore
   renders against a profile whose `structured` is `NONE` exactly when the call
   site says the endpoint cannot enforce the shape.

7. NOTHING MAY BE LOST WHEN THE SYSTEM TURN IS FOLDED. ADAPT moves every system
   fragment into the user turn for a family whose chat template has no system
   role (gemma). The tier renders its two turns from two SEPARATE renders, so
   the fold is only lossless if BOTH renders are given the same facts — hence
   `_build_llm_prompt` now takes `vocabulary=` / `fenced=` too. Without that the
   entire tier policy would vanish for that family: `.instructions` empty and
   the user render's spec never listing the fragments that were folded.

HERMETIC: no network, no model call, no agent-package import.
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from shared.prompt import Mode, lint, profile_for, render
from shared.prompt.fragment import CONFLICTING, Role, Stance
from shared.prompt.manifests.generate import (
    GENERATE_SPECS,
    domain_instructions,
    live_spec,
)
from shared.prompt.profile import MODEL_PROFILES, Structured
from shared.prompt.registry import get

AGENTS = tuple(sorted(GENERATE_SPECS))

# The eight names the field contract has always carried. A literal here on
# purpose: the assertion below is that ONE fragment states them, and a list
# read from the fragment under test could not fail.
EIGHT_FIELDS = (
    "severity", "category", "title", "description",
    "file_path", "line_start", "line_end", "recommendation",
)

# One model per capability family, resolved the way `lint.family_models` does,
# so a family added to `MODEL_PROFILES` is swept here too.
def _family_models() -> dict[str, str]:
    from shared.prompt.lint import family_models

    return family_models()


@pytest.fixture(autouse=True)
def _pin_prompt_knobs(monkeypatch):
    """Pin the knobs that move these bytes, so ambient env cannot fake a pass."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_REQUIRED", "true")
    monkeypatch.setenv("VULTURE_LLM_QUOTE_MAX_LINES", "3")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("VULTURE_LLM_ENDPOINT_KIND", raising=False)


def _runner():
    from shared import audit_runner

    return audit_runner


def _lint(agent: str, model: str = "gpt-4o") -> list:
    spec = GENERATE_SPECS[agent]
    return lint(spec, render(spec, profile_for(model), mode=Mode.ADAPT))


def _checks(agent: str, model: str = "gpt-4o") -> set[str]:
    return {f.check for f in _lint(agent, model)}


# ── 1. the tool trigger, with the budget the runtime really enforces ──────

def test_the_loop_guard_really_kills_at_the_two_budgets_the_prompt_states():
    """The numbers are read from the enforcing module — prove it enforces them.

    Drives the real `LoopDetector`, not the constants: a prompt that promises a
    bound nothing enforces teaches the model a rule it can break for free, and
    a constant renamed out from under the fragment would otherwise go unnoticed.
    """
    from shared.llm.loop_detector import (
        GLOBAL_CALL_LIMIT,
        KILL_THRESHOLD,
        LoopAction,
        LoopDetector,
    )

    total = LoopDetector()
    actions = [total.record(f"tool_{i}", None, f"result_{i}")
               for i in range(GLOBAL_CALL_LIMIT)]
    assert actions[-1] is LoopAction.KILL, "the global budget is not enforced"
    assert LoopAction.KILL not in actions[:-1], "it killed EARLIER than stated"

    repeat = LoopDetector()
    repeats = [repeat.record("read_file", None, "same") for _ in range(KILL_THRESHOLD)]
    assert repeats[-1] is LoopAction.KILL, "the repeat budget is not enforced"
    assert LoopAction.KILL not in repeats[:-1]


def test_tool_trigger_retypes_no_number_and_the_render_fills_the_real_ones():
    """The fragment carries placeholders; the call site supplies the constants."""
    from shared.llm.loop_detector import GLOBAL_CALL_LIMIT, KILL_THRESHOLD

    frag = get("generate/tool_trigger")
    assert not re.search(r"\d", frag.text), (
        f"generate/tool_trigger retypes a number: {frag.text!r}"
    )
    assert "{tool_call_budget}" in frag.text
    assert "{tool_repeat_budget}" in frag.text

    turn = _runner()._generate_system_prompt(
        "IDENTITY", "--- a.py ---\n1: x\n", None,
        source_in_system=False, fenced=True, model="gpt-4o",
    )
    assert str(GLOBAL_CALL_LIMIT) in turn
    assert str(KILL_THRESHOLD) in turn
    assert "{tool_call_budget}" not in turn


def test_tool_trigger_permits_tool_use_on_every_branch():
    """`check_11` fired on all seven specs; three tools are attached always."""
    assert Stance.PERMITS_TOOL_USE in get("generate/tool_trigger").stance
    for agent in AGENTS:
        assert "tool_announcement" not in _checks(agent), agent

    for source in ("inline", "system", "none"):
        spec = live_spec(source=source, vocabulary=True, fenced=True,
                         quote=True, prior=True)
        ids = tuple(spec.fragments) + tuple(spec.user_fragments)
        assert "generate/tool_trigger" in ids, source


def test_no_stance_conflict_is_created_by_permitting_tool_use():
    """The measured defect: tools attached while a clause blesses not looking.

    `generate/evidence_discipline` declares NO abstention stance at all, and
    that is the same finding twice over. A draft of it closed with "if it is
    still undecidable after you have looked, say nothing about it", which
    `test_0076_obligation.py::test_prompt_never_instructs_suppression_of_
    unquotable_findings` caught as a suppression instruction (AC20) — so the
    clause came out, and with it the only thing there was to declare.
    """
    assert frozenset({Stance.PERMITS_TOOL_USE, Stance.BLESSES_ABSTENTION}) in CONFLICTING
    for fid in ("generate/evidence_discipline", "generate/tool_trigger",
                "generate/source_presentation", "generate/vocab_severity"):
        assert Stance.BLESSES_ABSTENTION not in get(fid).stance, fid
    for agent in AGENTS:
        assert "stance_conflict" not in _checks(agent), agent


# ── 2. the severity vocabulary ────────────────────────────────────────────

def test_vocab_severity_binds_exactly_the_set_the_normaliser_accepts():
    """The fragment, the manifest and `normalize_severity` must be one set."""
    from shared.prompt.manifests.generate import _VOCABULARY

    ar = _runner()
    accepted = tuple(ar._SEVERITY_WEIGHTS)
    frag = get("generate/vocab_severity")
    assert frag.binds_vocabulary == (("severity", accepted),), frag.binds_vocabulary
    assert _VOCABULARY == (("severity", accepted),)
    for value in accepted:
        assert value in frag.text, value
        assert ar.normalize_severity(value) == value


def test_the_fragment_states_the_consequence_the_normaliser_actually_applies():
    """Out-of-set does not error — it downgrades. The prompt must say which."""
    ar = _runner()
    assert ar.normalize_severity("catastrophic") == "info"
    assert "info" in get("generate/vocab_severity").text


@pytest.mark.parametrize(
    ("front_matter", "expected"),
    [
        ("binds_vocabulary: severity=[critical, low]",
         (("severity", ("critical", "low")),)),
        ("binds_vocabulary: a=[x]; b=[y, z]",
         (("a", ("x",)), ("b", ("y", "z")))),
        ("", ()),
    ],
    ids=["one-binding", "two-bindings", "absent"],
)
def test_the_parser_reads_the_binds_vocabulary_front_matter(
    tmp_path, front_matter, expected,
):
    """The key `parse_fragment` never read.

    It set `binds_vocabulary = ()` unconditionally, so `check_04_vocab_closure`
    could only ever REPORT a gap — there was no way to write a fragment that
    closed one. Every case here goes through the real parser on a real file.
    """
    from shared.prompt.fragment import parse_fragment

    path = tmp_path / "probe.md"
    path.write_text(f"---\nid: probe\n{front_matter}\n---\nbody", encoding="utf-8")
    assert parse_fragment(path).binds_vocabulary == expected


@pytest.mark.parametrize("bad", ["critical, low", "severity", "severity=[]", "=[a]"])
def test_a_binds_vocabulary_that_binds_nothing_is_a_parse_error(tmp_path, bad):
    """The silent-nothing case is the one this parser must never produce.

    A value that looks like a binding but yields none would leave `check_04`
    still reporting the gap while its author believed it closed — so it raises
    at registry-load time, the way a bad `seam:` already does, rather than
    falling back to an empty tuple.
    """
    from shared.prompt.fragment import parse_fragment

    path = tmp_path / "probe.md"
    path.write_text(f"---\nid: probe\nbinds_vocabulary: {bad}\n---\nbody",
                    encoding="utf-8")
    with pytest.raises(ValueError, match="binds_vocabulary"):
        parse_fragment(path)


def test_vocab_closure_is_closed_on_every_generate_spec():
    """The annotation the manifest kept deliberately open now has nothing to say."""
    for agent in AGENTS:
        assert "vocab_closure" not in _checks(agent), agent


# ── 3/4. evidence discipline and source presentation ──────────────────────

def test_source_presentation_states_the_shapes_production_emits():
    """Header and line prefix, checked against the code that writes them."""
    from shared.tools.line_format import number_lines, read_line_number

    ar = _runner()
    rel = "app/handlers.py"
    assert ar._block_header(rel, []) == f"--- {rel} ---"
    windowed = ar._block_header(rel, [(1, 9), (31, 89)])
    assert windowed == f"--- {rel} (lines 1-9, 31-89 omitted) ---"
    assert number_lines(["x = 1", "y = 2"]) == "1: x = 1\n2: y = 2"

    text = get("generate/source_presentation").text
    assert "--- " in text and " ---" in text, "the header delimiters are unstated"
    assert "omitted" in text, "the windowed header is unstated"
    # The numbering example in the fragment must parse with the SAME reader
    # production uses to strip a prefix back off.
    examples = [line for line in text.splitlines() if read_line_number(line) is not None]
    assert examples, f"no `NN: ` example the live reader recognises: {text!r}"


def test_source_presentation_carries_no_literal_ellipsis():
    """The elision marker is described, never echoed — `check_09` reads for it.

    `_extract_file_snippet` joins two kept windows with a line of three dots,
    and `lint._PLACEHOLDERS` carries a bare one, so writing the marker verbatim
    would trade a fixed `placeholder_echo` for a new one.
    """
    text = get("generate/source_presentation").text
    assert "..." not in text
    assert "three dots" in text or "ellipsis" in text


def test_evidence_discipline_routes_the_undecided_case_to_a_tool():
    """The alternative to a guessed finding is a look, and it must be named."""
    text = get("generate/evidence_discipline").text
    assert "read_file" in text and "tool" in text


# ── 5. the duplicate contract, both halves ────────────────────────────────

def test_exactly_one_tier_fragment_declares_the_field_list():
    """`generate/json_fenced` states the WIRE SHAPE now, not the fields."""
    fenced = get("generate/json_fenced")
    assert fenced.declares_fields == (), fenced.declares_fields
    for name in EIGHT_FIELDS:
        assert name not in fenced.text, f"json_fenced still names {name!r}"

    contract = get("generate/field_contract")
    assert contract.declares_fields == EIGHT_FIELDS
    for name in EIGHT_FIELDS:
        assert name in contract.text, name


def test_duplicate_contract_survives_only_where_a_domain_ships_its_own():
    """Five agents are clean; cwe and asvs ship a "## Reporting Format" block.

    Those two remain annotated — the item's stated fallback ("resolve both or
    annotate what remains") — because the block is the agent's own INSTRUCTIONS
    text, which `test_0089_no_second_source_of_truth.py` pins byte-for-byte
    against the constant its own unit tests assert on.
    """
    own_block = {"cwe", "asvs"}
    for agent in AGENTS:
        declaring = {f.fragment for f in _lint(agent) if f.check == "duplicate_contract"}
        if agent in own_block:
            assert declaring == {"generate/field_contract", f"domains/{agent}"}, agent
        else:
            assert declaring == set(), agent


def test_placeholder_echo_is_gone_from_json_fenced():
    """The `...` was fence-syntax illustration; the sentence no longer needs it."""
    assert "..." not in get("generate/json_fenced").text
    for agent in AGENTS:
        echoes = {f.fragment for f in _lint(agent) if f.check == "placeholder_echo"}
        assert "generate/json_fenced" not in echoes, agent


# The five booleans `live_spec` branches on, as (fenced, quote) — the pair the
# quote asymmetry depended on.
@pytest.mark.parametrize("fenced", [True, False])
@pytest.mark.parametrize("source", ["inline", "system", "none"])
@pytest.mark.parametrize("model", ["gpt-4o", "gemini-2.5-flash", "gemma-3-27b"])
def test_the_quote_obligation_is_emitted_exactly_once(fenced, source, model):
    """BEFORE: once for a structured model, twice for LM Studio / Gemini.

    The system copy came from `_quote_contract_suffix()`, which the live builder
    appended only on the unstructured branch. The count therefore depended on a
    capability that has nothing to do with evidence.
    """
    spec = live_spec(source=source, vocabulary=True, fenced=fenced,
                     quote=True, prior=False,
                     variables={"quote_max_lines": "3", "source_context": "S",
                                "source_path": "/s", "domain_label": "d",
                                "categories": "c", "category_vocabulary": "V",
                                "tool_call_budget": "100", "tool_repeat_budget": "20"})
    rp = render(spec, profile_for(model), mode=Mode.ADAPT)
    sentence = "A finding without a quote will be reported as unverified."
    assert (rp.instructions + "\n" + rp.user).count(sentence) == 1


def test_the_quote_obligation_is_listed_in_one_turn_only():
    """One listing, so ADAPT's mirror rule cannot make a third copy."""
    frag = get("generate/quote_obligation")
    assert frag.role is Role.USER, (
        "SYSTEM+USER_MIRROR here would put it in the system turn AND at the "
        "front of the user turn, on top of the user listing — three copies"
    )
    for spec in GENERATE_SPECS.values():
        assert spec.fragments.count("generate/quote_obligation") == 0, spec.id
        assert spec.user_fragments.count("generate/quote_obligation") == 1, spec.id


def test_the_dead_system_copy_is_gone_from_the_builder():
    """`_quote_contract_suffix` was the second authority; it no longer exists.

    Its docstring named itself the duplicate ("one policy written twice, in two
    places that are edited independently"). Removing the placement without
    removing the function would leave the second place behind, ready to be
    re-appended by the next edit.
    """
    assert not hasattr(_runner(), "_quote_contract_suffix")


# ── 6. the profile must tell the truth about THIS endpoint ────────────────

@pytest.mark.parametrize("model", ["gpt-4o", "claude-sonnet-4", "qwen3:8b"])
def test_a_gateway_that_cannot_enforce_the_shape_still_gets_the_prose_contract(
    monkeypatch, model,
):
    """The regression ADAPT would otherwise introduce, for every family.

    `supports_structured_output()` is False behind ANY custom endpoint, so the
    call site sends no `output_type`. If the render then also dropped
    `generate/json_fenced` under rule 4+5 the model would be given no contract
    at all — not the prose one, not the API one.
    """
    # The endpoint marker rather than OPENAI_BASE_URL: `provider` caches the
    # URL in a module constant at import time, and `uses_custom_endpoint`
    # reads this one at CALL time precisely so a run can be configured after
    # import (0073 P2 — in broker mode the agent never sees the URL at all).
    monkeypatch.setenv("VULTURE_LLM_ENDPOINT_KIND", "openai-compatible")
    from shared.llm.provider import supports_structured_output, uses_custom_endpoint

    assert uses_custom_endpoint()

    assert not supports_structured_output(model)
    turn = _runner()._generate_system_prompt(
        "IDENTITY", "--- a.py ---\n1: x\n", None,
        source_in_system=False, fenced=True, model=model,
    )
    assert get("generate/json_fenced").text in turn


def test_a_native_structured_model_is_not_shown_the_prose_contract():
    """The other half of rule 4+5, so the test above is not vacuous."""
    assert profile_for("gpt-4o").structured is Structured.NATIVE
    turn = _runner()._generate_system_prompt(
        "IDENTITY", "--- a.py ---\n1: x\n", None,
        source_in_system=False, fenced=False, model="gpt-4o",
    )
    assert "```json" not in turn


# ── 7. the fold must not lose the tier policy ─────────────────────────────

_NO_SYSTEM_ROLE = "gemma-3-27b"
# A family whose profile pins the output language (item 4.8, rule 9). It has a
# system role, which every pinning family does — so this is the pin's presence
# case, not a second fold case.
_PINS_LANGUAGE = "glm-4.6"
_SOURCE = "--- a.py ---\n1: import os\n2: os.system(cmd)\n"


def test_the_family_without_a_system_role_is_still_a_real_case():
    """Guards the vacuous pass: this test is worthless if gemma grew one."""
    assert profile_for(_NO_SYSTEM_ROLE).system_role is False
    assert any(caps["system_role"] for caps in MODEL_PROFILES.values())


def _assembled(model: str) -> tuple[str, str]:
    """(system turn, both turns concatenated) for one live GENERATE call."""
    ar = _runner()
    vocab = frozenset({"CWE-79"})
    system = ar._generate_system_prompt(
        "IDENTITY", _SOURCE, vocab,
        source_in_system=False, fenced=True, model=model,
    )
    user = ar._build_llm_prompt(
        "/src", ["injection"], "checks", _SOURCE, "",
        vocabulary=vocab, fenced=True, model=model,
    )
    return system, system + "\n" + user


def test_nothing_in_the_system_suffix_is_lost_when_the_turn_is_folded():
    """Every system fragment reaches the model, in one turn or the other.

    "EVERY" MEANS EVERY FRAGMENT THE RULES ADMIT, as of item 4.8. The loop was
    over all of `_SYSTEM_SUFFIX`, which was the same thing while the only rule
    that could remove a fragment (4+5, `REQUIRES_FENCE`) was disarmed by the
    `fenced=True` call above. `core/language` is admitted only for a family
    whose profile pins the output language, and the no-system-role family this
    test folds is not one — so it is absent here BY RULE, and requiring it
    would require rule 9 to fail whenever rule 1 applies.

    Absent-by-rule and lost-in-the-fold are exactly what a bare `in` check
    cannot tell apart, so the same fragment is asserted PRESENT on a family
    that does pin — same builders, same call — and the "vanished" claim keeps
    its meaning.
    """
    from shared.prompt.manifests.generate import _SYSTEM_SUFFIX

    system, whole = _assembled(_NO_SYSTEM_ROLE)
    _, pinning = _assembled(_PINS_LANGUAGE)
    for fid in _SYSTEM_SUFFIX:
        frag = get(fid)
        needle = frag.text.split("{")[0].rstrip()
        assert needle
        if Stance.BINDS_LANGUAGE in frag.stance:
            assert needle not in whole, f"{fid} reached a family rule 9 excludes"
            assert needle in pinning, f"{fid} vanished for a family that pins it"
            continue
        assert needle in whole, f"{fid} vanished in the fold"
        assert needle in pinning, f"{fid} vanished on the pinning family"
    assert system.strip() == "IDENTITY", (
        "the folded turn must leave the identity alone in the system message"
    )


def test_the_fold_duplicates_nothing():
    """Both turns come from two renders; a shared fragment could land twice."""
    ar = _runner()
    vocab = frozenset({"CWE-79"})
    system = ar._generate_system_prompt(
        "IDENTITY", _SOURCE, vocab,
        source_in_system=False, fenced=True, model=_NO_SYSTEM_ROLE,
    )
    user = ar._build_llm_prompt(
        "/src", ["injection"], "checks", _SOURCE, "",
        vocabulary=vocab, fenced=True, model=_NO_SYSTEM_ROLE,
    )
    whole = system + "\n" + user
    for fid in ("core/untrusted", "generate/json_fenced", "generate/tool_trigger",
                "generate/vocab_severity", "generate/field_contract"):
        needle = get(fid).text.split("{")[0].rstrip()
        assert whole.count(needle) == 1, f"{fid} appears twice"
    assert whole.count(_SOURCE) == 1, "the source body was emitted twice"


# ── the second call site: the agent identity ──────────────────────────────

@pytest.mark.parametrize("agent", AGENTS)
def test_domain_instructions_is_byte_neutral_under_adapt_for_every_family(agent):
    """Flipping this site may not move an agent's identity by one byte.

    `domains/<agent>` carries no `REQUIRES_FENCE` and no `BINDS_LANGUAGE`, so
    the only ADAPT rule that can reach it is the no-system-role fold — and this
    function returns ONE string for ONE channel, which the caller hands to
    `run_combined_audit(instructions=...)` either way. The fold is therefore a
    relocation with nowhere to relocate to, and the bytes must be identical.
    """
    from shared.prompt.spec import PromptSpec

    fid = f"domains/{agent}"
    reference = render(PromptSpec(id="ref", tier="generate", fragments=(fid,)),
                       profile_for("gpt-4o"), mode=Mode.TRANSCRIBE).instructions
    assert reference == get(fid).text.rstrip("\n") or reference == get(fid).text
    for model in _family_models().values():
        assert domain_instructions(fid, model=model) == reference, model


# ── the assembled prompt, once, end to end ────────────────────────────────

def test_the_assembled_system_turn_orders_its_sections_as_specified():
    """Order is a prompt decision, so it is asserted, not left to the tuple.

    Named `..._the_seven_sections_...` until item 4.8 made it eight:
    `core/language` sits between the vocabularies it belongs with and the wire
    shape, both of which are already profile-conditional. The literal is the
    point of this test, so it grows by one line and the name stops claiming a
    count it no longer has.
    """
    from shared.prompt.manifests.generate import _SYSTEM_SUFFIX

    assert _SYSTEM_SUFFIX == (
        "core/untrusted",
        "generate/source_presentation",
        "generate/evidence_discipline",
        "generate/tool_trigger",
        "generate/vocab_category",
        "generate/vocab_severity",
        "core/language",
        "generate/json_fenced",
    )
    spec = dataclasses.replace(
        GENERATE_SPECS["cwe"],
        variables={"category_vocabulary": "CWE-79", "source_context": "S",
                   "tool_call_budget": "100", "tool_repeat_budget": "20"},
    )
    # `_PINS_LANGUAGE` rather than `gemini-2.5-flash` as of item 4.8: this
    # assertion needs a profile that admits EVERY section, and gemini does not
    # pin its output language, so rule 9 would drop `core/language` and the
    # order of the remaining seven would be all this could see. Both profiles
    # are `Structured.NONE`, so rule 4+5 still keeps `generate/json_fenced` and
    # nothing else about the render changes.
    turn = render(spec, profile_for(_PINS_LANGUAGE), mode=Mode.ADAPT).instructions
    positions = [turn.index(get(fid).text.split("{")[0].rstrip())
                 for fid in _SYSTEM_SUFFIX]
    assert positions == sorted(positions), positions
    assert len(positions) == len(set(positions)) == len(_SYSTEM_SUFFIX)
