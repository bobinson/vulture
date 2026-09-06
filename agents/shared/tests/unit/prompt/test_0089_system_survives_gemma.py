"""`test_system_survives_gemma` — the 0.e blocker no lint check can see.

The blocker is "contract system-only", and its two coordinates are
`audit_runner.py`'s `_generate_system_prompt` (the tier suffix, system turn)
and `shared/validate/prompts/validate_judge_user.txt` (four lines: an audit id,
a count, and the findings block). Read together they state the hazard: BOTH
tiers put the whole output contract in the system turn, and neither user turn
says anything about the shape of the answer. A family whose chat template has
no system role — `gemma`, `system_role=False` — therefore risks being asked for
a field list it was never shown, or for JSON it was never told to emit. The
response still parses as *something*, which is why nothing else catches it.

No linter can: `lint.py`'s twelve checks read a spec's fragments and their
declarations, and the contract fragment is present and correct in every one of
them. What is wrong in the failure case is not the prompt, it is the TURN, and
the turn is decided by `render` at call time from a capability profile.

WHAT IS ASSERTED, AND WHY IT IS THE UNION OF THE TURNS. `test_system_survives_gemma`
asserts that for a `system_role=False` profile the output contract is in the
text the model receives — *in whichever turn it ends up in*, not in a
particular one. Two reasons the union is the right predicate rather than "the
user turn":

  * the two tiers are at different points in Phase 4. GENERATE renders ADAPT
    (item 4.4), where rule 1 folds the whole system turn into the user turn, so
    for gemma the contract is in the user half and `_generate_system_prompt`
    returns the agent identity and nothing else. VALIDATE still renders
    TRANSCRIBE (item 4.1 owns that flip), where the contract stays in the
    system turn. A predicate naming one turn would either fail on VALIDATE
    today or stop testing GENERATE after 4.1 lands.
  * the failure this covers is LOSS. The renderer's no-system-role branch is
    two statements — `usr_frags = sys_frags + usr_frags` then `sys_frags = []` —
    and the second without the first drops every system fragment on the floor.
    That is what the union sees, in both modes, for every manifest at once.

THE MODE-SPECIFIC HALF IS ASSERTED SEPARATELY, in
`test_gemma_receives_one_turn_and_the_contract_is_in_it`: under ADAPT, gemma's
render has NO system message, so "somewhere in the delivered text" and "in the
turn gemma actually reads" are the same statement. That is the assertion that
fails on the dropped-fold mutation.

WHAT COUNTS AS "THE OUTPUT CONTRACT" is derived, never retyped: a fragment that
`declares_fields`. That is the library's own machine-readable marker for "this
block tells the model what to emit" — the same property `check_01_orphan_field`
and `check_02_duplicate_contract` key on. Deriving it means a tier that grows a
new contract fragment is covered here without an edit, and a tier that loses
one fails `test_every_manifest_states_a_contract_or_records_why_it_does_not`.

WHAT IS DELIBERATELY NOT ASSERTED: that every name in `spec.schema_fields`
reaches the prompt. It does not, legitimately — `prove_plan_*` share one
`ProofPlan` schema covering three protocols, so `protocol`, `rpc_method` and
`rpc_params` are in the schema of a plan spec whose exemplar is HTTP and are
correctly absent from its text. The direction that IS an error (a fragment
demanding a field no schema has) is `check_01_orphan_field`'s, and it already
runs in `promptlint`. This file checks the fields each contract fragment
declares of ITSELF, which is the half that must survive relocation.
"""

from __future__ import annotations

import dataclasses

import pytest

from shared.prompt import Mode, profile_for, registry, render
from shared.prompt.manifests import MANIFESTS

# The family the whole file is about. A model string, not a family name, so it
# goes through `family_for` exactly as production does.
GEMMA = "google/gemma-4-31b"
# A control with a system role, same `Structured.NONE` capability otherwise —
# without it the sweep could pass against a renderer that emits one fixed turn.
CONTROL = "qwen/qwen3.6-35b-a3b"

MODES = (Mode.TRANSCRIBE, Mode.ADAPT)

# The manifests with no contract fragment, and why that is correct rather than
# an omission. A recorded reason, in the shape item 4.7's `NO_MIRROR` uses: a
# spec silently absent from the sweep is a spec nobody looked at.
NO_CONTRACT: dict[str, str] = {
    "prove_system": (
        "the PROVE system turn is a persona and a safety boundary; it states "
        "no field list, because each of the tier's user turns carries its own "
        "(`prove/plan*`, `prove/reflect*`, `prove/analyze*` all declare "
        "fields). Nothing here can be lost to a dropped system role."
    ),
    "prove_retry_1": (
        "a retry NUDGE appended to an existing user turn, not a call of its "
        "own: it re-states the failure, and the contract it is nudging "
        "towards was delivered by the plan/analyze turn it follows."
    ),
    "prove_retry_2": (
        "the second retry nudge, for the same reason as the first."
    ),
}


# ── the derivation ────────────────────────────────────────────────────────


def contract_fragments(spec) -> tuple[str, ...]:
    """Fragment ids in `spec` that state an output contract.

    Both turns are searched. A tier may put its contract in either — GENERATE's
    field list is a USER fragment and VALIDATE's is a SYSTEM one — and the
    question this file asks is about the union anyway.
    """
    return tuple(
        fid for fid in tuple(spec.fragments) + tuple(spec.user_fragments)
        if registry.get(fid).declares_fields
    )


def undelivered_by_design(spec, frag) -> frozenset[str]:
    """Names `frag` declares that this spec is ALLOWED not to put in its prose.

    Derived from the spec's own `allow=` list, never listed here. A name is
    exempt only when BOTH hold:

      * the manifest carries an owned, explained `orphan_field` allow row for
        this fragment — which is `check_01_orphan_field`'s finding, and the
        place the reason for the divergence is already written down; and
      * the name is genuinely absent from `spec.schema_fields`, which is the
        condition that made check 01 fire in the first place.

    Deriving rather than listing is what keeps this honest in both directions.
    Today it resolves to exactly one row, library-wide — `generate/asvs` ::
    `domains/asvs` :: `linked_cwe`, whose allow reason records that Phase 2.5
    deliberately removed the `- linked_cwe (optional)` line from the prose
    while keeping the declaration as the standing signal that the name is
    unschema'd. The moment that backlog row is retired, this exemption
    disappears with it and the sweep starts demanding the field like any
    other; and a NEW undeliverable declaration cannot be smuggled in, because
    it has no allow row and fails the sweep. `test_the_carve_out_is_derived_
    narrow_and_load_bearing` pins both directions.
    """
    if not any(a.check == "orphan_field" and a.fragment == frag.id
               for a in spec.allow):
        return frozenset()
    return frozenset(n for n in frag.declares_fields if n not in spec.schema_fields)


def contract_gaps(spec, delivered: str) -> list[str]:
    """What `spec` promised the model and `delivered` does not contain.

    Whole fragment text, compared with `in` — never a phrase from it. The
    failure this covers includes "a summary of the contract survived", and a
    keyword search cannot tell a summary from the thing.

    The per-field pass below is not redundant with the text comparison: a name
    in `declares_fields` need not appear in the fragment's own body, and when
    it does not, this is the only check that sees it. That is the branch
    `domains/asvs` sits in.
    """
    gaps = []
    for fid in contract_fragments(spec):
        frag = registry.get(fid)
        if frag.text.strip("\n") not in delivered:
            gaps.append(f"{fid}: fragment text absent")
            continue
        exempt = undelivered_by_design(spec, frag)
        for name in frag.declares_fields:
            if name not in delivered and name not in exempt:
                gaps.append(f"{fid}: declares {name!r}, which is not delivered")
    return gaps


def delivered_text(rp) -> str:
    """Everything the model receives, in whichever turn it ended up in."""
    return "\n".join(m["content"] for m in rp.messages)


# ══════════════════════════════════════════════════════════════════════════
# THE COVER
# ══════════════════════════════════════════════════════════════════════════


def test_system_survives_gemma():
    """Every manifest's output contract reaches a no-system-role model.

    One assertion over the whole library in both renderer modes, because the
    blocker is not a property of one spec: any manifest whose contract lives in
    the system turn is exposed to the same relocation, and Phase 4 moves the
    call sites one at a time.
    """
    profile = profile_for(GEMMA)
    assert profile.system_role is False, (
        f"{GEMMA} no longer resolves to a no-system-role profile; this whole "
        "file is testing nothing"
    )
    violations = []
    for mode in MODES:
        for spec_id, spec in sorted(MANIFESTS.items()):
            rp = render(spec, profile, mode=mode)
            for gap in contract_gaps(spec, delivered_text(rp)):
                violations.append(f"{mode.value}/{spec_id}: {gap}")
    assert violations == [], (
        "a no-system-role model would be asked for output it was never told "
        "how to shape:\n  " + "\n  ".join(violations)
    )


@pytest.mark.parametrize("mode", MODES, ids=lambda m: m.value)
def test_the_control_family_also_receives_every_contract(mode):
    """The sweep must not be a statement about renderers in general.

    If it passed for gemma and failed for a system-role family, the contract
    would be surviving by accident. Both must hold; only gemma's is the
    blocker.
    """
    profile = profile_for(CONTROL)
    assert profile.system_role is True, "fixture assumption"
    violations = [
        f"{spec_id}: {gap}"
        for spec_id, spec in sorted(MANIFESTS.items())
        for gap in contract_gaps(spec, delivered_text(render(spec, profile, mode=mode)))
    ]
    assert violations == [], violations


def test_gemma_receives_one_turn_and_the_contract_is_in_it():
    """ADAPT's rule 1, stated as the thing that makes the union sufficient.

    Under ADAPT a no-system-role profile gets exactly one message. So there is
    no turn for a contract to hide in: it is in the message gemma reads, or it
    is gone. This is the assertion that fails if the fold is ever reduced to
    `sys_frags = []`.
    """
    profile = profile_for(GEMMA)
    for spec_id, spec in sorted(MANIFESTS.items()):
        rp = render(spec, profile, mode=Mode.ADAPT)
        assert rp.instructions == "", f"{spec_id}: gemma got a system turn"
        assert [m["role"] for m in rp.messages] == ["user"], (
            f"{spec_id}: roles {[m['role'] for m in rp.messages]}")
        assert contract_gaps(spec, rp.user) == [], spec_id


def test_no_system_fragment_at_all_is_lost_to_the_fold():
    """Wider than the contract: the fold must lose NOTHING.

    The contract is what the blocker names because it is the loss whose output
    still parses. But a fold that dropped, say, the marker rule would be the
    same bug with a worse consequence, so the whole system turn is compared —
    fragment by fragment, so the failure names which one went missing.

    Scoped to the fragments the ADAPT rules ADMIT: rule 9 drops
    `BINDS_LANGUAGE` fragments for a profile that does not pin its output
    language, and gemma's does not. Asserting those survive would be asserting
    that rule 9 stops working when rule 1 also applies (item 4.7 records the
    same carve-out for the same reason).
    """
    from shared.prompt.fragment import Stance

    profile = profile_for(GEMMA)
    assert profile.output_language_pin is False, "fixture assumption"
    assert profile.structured.value == "none", "fixture assumption"
    missing = []
    for spec_id, spec in sorted(MANIFESTS.items()):
        rp = render(spec, profile, mode=Mode.ADAPT)
        for fid in spec.fragments:
            frag = registry.get(fid)
            if Stance.BINDS_LANGUAGE in frag.stance:
                continue
            body = frag.text.strip("\n")
            if body and body not in rp.user:
                missing.append(f"{spec_id}: {fid}")
    assert missing == [], (
        "system fragment(s) lost when the turn was folded into the user "
        f"message: {missing}")


# ══════════════════════════════════════════════════════════════════════════
# The two call sites the blocker table names, driven for real
# ══════════════════════════════════════════════════════════════════════════


def test_the_generate_tier_delivers_its_contract_to_gemma(monkeypatch):
    """`audit_runner.py` — the first coordinate in the blocker table.

    Driven through `_generate_system_prompt` and `_build_llm_prompt`, the two
    functions that produce the bytes an audit actually sends, rather than
    through a manifest render: the hazard here is a SPLIT one. The tier builds
    its two turns from two SEPARATE renders and keeps a different half of each,
    so a library-level assertion cannot see that the half being kept is the
    half that folded.

    Measured, and this is the blocker in one line: for gemma the tier suffix is
    EMPTY — `_generate_system_prompt` returns the agent identity alone — and
    every rule, vocabulary and contract survives only because
    `_build_llm_prompt` was given the same `vocabulary` / `fenced` facts and
    folded the identical set into the turn that is used.

    THE IDENTITY IS RENDERED, NOT TYPED. `instructions` reaches this function
    from `domain_instructions(...)` — the same production call every scan agent
    makes at its own `run_combined_audit` site since Phase 2.5 (see
    `_generate_system_prompt`'s own docstring, which is the line range the
    blocker table cites). A stub string here would make the `domains/cwe` half
    of the contract trivially absent and the assertion below untestable.
    """
    monkeypatch.setenv("VULTURE_LLM_MODEL", GEMMA)
    from shared import audit_runner as ar
    from shared.prompt.manifests import MANIFESTS as M
    from shared.prompt.manifests.generate import domain_instructions

    identity = domain_instructions("domains/cwe", model=GEMMA)
    system = ar._generate_system_prompt(
        identity, "print(1)", frozenset({"CWE-89"}),
        source_in_system=False, fenced=True, model=GEMMA,
    )
    user = ar._build_llm_prompt(
        "/src", ["injection"], "categories", "print(1)", "",
        vocabulary=frozenset({"CWE-89"}), fenced=True, model=GEMMA,
    )
    assert system == identity, (
        "fixture assumption: for a no-system-role family the tier suffix folds "
        f"away entirely, leaving only the identity. Got {system[len(identity):]!r}"
    )
    delivered = system + "\n" + user
    assert contract_gaps(M["generate/cwe"], delivered) == []
    # The wire-shape half of the contract is a separate fragment from the field
    # list, and only one of the two is a user fragment to begin with. Both have
    # to arrive or the model is asked for eight fields with no instruction to
    # emit JSON.
    assert registry.get("generate/field_contract").text.strip("\n") in user
    assert registry.get("generate/json_fenced").text.strip("\n") in user

    # ── the sharper statement, and the reason the union is not enough here ──
    #
    # For GENERATE the two turns are not equally safe. `_generate_system_prompt`
    # returns a string the caller hands to `run_combined_audit(instructions=)`,
    # which is a system message — and `domain_instructions`' docstring records
    # the consequence in as many words: "The identity of a no-system-role family
    # (gemma) is therefore still sent as a system message the chat template may
    # drop." Folding it is a runner-signature question, out of scope here.
    #
    # So the property that actually protects gemma is not "the contract is
    # somewhere in the union", it is "no field is reachable ONLY through the
    # droppable channel". `domains/cwe` carries a '## Reporting Format' block of
    # its own and it lands exclusively in `system`; every name it declares must
    # therefore be restated by a USER fragment. It is — by
    # `generate/field_contract`, which declares the identical eight — and that
    # redundancy is the thing under test, not a coincidence to leave unasserted.
    system_only = registry.get("domains/cwe")
    assert system_only.text.strip("\n") in system
    assert system_only.text.strip("\n") not in user, (
        "fixture assumption: the identity is the system-only half")
    stranded = [
        name
        for fid in contract_fragments(M["generate/cwe"])
        for name in registry.get(fid).declares_fields
        if name not in user
        and name not in undelivered_by_design(M["generate/cwe"], registry.get(fid))
    ]
    assert stranded == [], (
        "a no-system-role model would reach these field names only through the "
        f"system turn its chat template may drop: {stranded}")


def test_the_validate_tier_delivers_its_contract_to_gemma(monkeypatch):
    """`validate_judge_user.txt` — the second coordinate.

    The four-line user template states an audit id, a count and the findings;
    the entire verdict contract is in the system turn. Driven through
    `_judge_system_prompt` and `_render_user_message`, the pair `_judge_batch`
    puts on the wire.

    This site still renders TRANSCRIBE, so today the contract is delivered in
    the system message and the union is what makes the assertion true. When
    item 4.1 flips the mode the contract moves into the user turn and this test
    keeps passing unchanged — which is the property the union was chosen for.
    """
    monkeypatch.setenv("VULTURE_LLM_MODEL", GEMMA)
    profile_for.cache_clear()
    from shared.prompt.manifests import MANIFESTS as M
    from shared.validate.llm_judge import _judge_system_prompt, _render_user_message

    finding = {"id": "f1", "check_id": "CWE-89", "severity": "high",
               "file_path": "a.py", "line_start": 3, "line_end": 3,
               "description": "d", "code_snippet": "x = 1"}
    system = _judge_system_prompt(3)
    user = _render_user_message("a1", [(0, finding, "python")], "deadbeef")
    delivered = system + "\n" + user
    assert contract_gaps(M["validate_judge"], delivered) == []
    assert contract_gaps(M["validate_judge_plain"], delivered) == []
    # The no-tools turn is a different prompt and is sent on its own whenever
    # the provider rejects `tools=`; it must carry the contract too.
    from shared.validate.llm_judge import _judge_system_prompt_plain
    assert contract_gaps(M["validate_judge_plain"],
                         _judge_system_prompt_plain() + "\n" + user) == []


# ══════════════════════════════════════════════════════════════════════════
# The detector must detect, and the sweep must not be vacuous
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("spec_id", ["generate/cwe", "validate_judge", "discover_suggest"])
def test_removing_the_contract_from_the_delivered_text_is_detected(spec_id):
    """The red team the plan asks for, on the detector itself.

    `contract_gaps` is what every assertion above is built on. Handed the real
    render with the contract fragment cut out of it, it must report the loss —
    otherwise the sweep is a statement about nothing. Both loss shapes are
    exercised: the fragment removed whole, and the fragment replaced by a
    plausible SUMMARY of itself.
    """
    spec = MANIFESTS[spec_id]
    fids = contract_fragments(spec)
    assert fids, f"{spec_id} has no contract fragment to remove"
    rp = render(spec, profile_for(GEMMA), mode=Mode.ADAPT)
    whole = delivered_text(rp)
    assert contract_gaps(spec, whole) == [], "fixture assumption: it survives"

    for fid in fids:
        body = registry.get(fid).text.strip("\n")
        assert body in whole
        excised = whole.replace(body, "")
        assert any(g.startswith(f"{fid}:") for g in contract_gaps(spec, excised)), (
            f"{spec_id}: removing {fid} entirely went unnoticed")
        summarised = whole.replace(body, "Reply with JSON.")
        assert any(g.startswith(f"{fid}:") for g in contract_gaps(spec, summarised)), (
            f"{spec_id}: replacing {fid} with a summary went unnoticed")


def test_the_field_branch_fires_on_a_declaration_the_prose_does_not_back():
    """The per-field half of `contract_gaps`, on the real instance of it.

    This branch is NOT reachable by mutating a field name out of the delivered
    text: every other declared name lives inside its own fragment's body, so
    removing it trips the whole-text comparison first and `contract_gaps`
    returns "fragment text absent" without ever reaching the name. The branch
    exists for the one shape that comparison cannot see — a `declares_fields`
    entry with no prose behind it — and the library holds exactly one:
    `domains/asvs` declares `linked_cwe`, which Phase 2.5 removed from the
    '## Reporting Format' block while deliberately keeping the declaration.

    So the branch is driven where it actually lives, with the fragment body
    INTACT (asserted, so a future text change cannot silently move this back
    onto the text branch and leave the field branch untested).
    """
    spec = MANIFESTS["generate/asvs"]
    frag = registry.get("domains/asvs")
    delivered = delivered_text(render(spec, profile_for(GEMMA), mode=Mode.ADAPT))
    assert frag.text.strip("\n") in delivered, (
        "the body must be present or this exercises the text branch instead")
    assert "linked_cwe" in frag.declares_fields
    assert "linked_cwe" not in delivered

    bare = contract_gaps(dataclasses.replace(spec, allow=()), delivered)
    assert bare == ["domains/asvs: declares 'linked_cwe', which is not delivered"], bare
    assert contract_gaps(spec, delivered) == [], "the allow row must suppress it"


def test_the_carve_out_is_derived_narrow_and_load_bearing():
    """The exemption must come from the manifest, cover one name, and matter.

    Four directions, because a carve-out is the easiest way to make a sweep
    stop testing anything:

      * DERIVED — strip the spec's `allow` list and the exemption is gone. The
        input is the manifest's own annotated backlog, so retiring the row
        retires the exemption with it; nothing here restates `linked_cwe` as
        the thing to skip.
      * NARROW — one (spec, fragment, name) triple in the whole library. A
        second undeliverable declaration appearing anywhere fails here even if
        someone also wrote it an allow row.
      * LOAD-BEARING — the sweep genuinely fails without it, so it is not a
        precaution against a condition that never arises.
      * BOUNDED — the fragment's other eight declared names are NOT exempted.
        An allow row is per-fragment; it must not become a licence for every
        field that fragment names.
    """
    exempt = {
        (sid, fid, name)
        for sid, spec in MANIFESTS.items()
        for fid in contract_fragments(spec)
        for name in undelivered_by_design(spec, registry.get(fid))
    }
    assert exempt == {("generate/asvs", "domains/asvs", "linked_cwe")}, sorted(exempt)

    spec = MANIFESTS["generate/asvs"]
    frag = registry.get("domains/asvs")
    assert undelivered_by_design(dataclasses.replace(spec, allow=()), frag) == frozenset()
    assert set(frag.declares_fields) - {"linked_cwe"} <= set(spec.schema_fields), (
        "every other name this fragment declares is schema'd and stays demanded")

    delivered = delivered_text(render(spec, profile_for(GEMMA), mode=Mode.ADAPT))
    assert contract_gaps(dataclasses.replace(spec, allow=()), delivered) != []
    assert contract_gaps(spec, delivered) == []


def test_the_allow_row_the_carve_out_reads_is_owned_and_explained():
    """The exemption inherits promptlint's own annotation contract.

    `gate()` refuses an allow row with no `owner` or no `reason`; this file
    consumes the same rows to suppress a failure, so it must not accept a
    weaker one than the linter would.
    """
    rows = [a for a in MANIFESTS["generate/asvs"].allow
            if a.check == "orphan_field" and a.fragment == "domains/asvs"]
    assert len(rows) == 1, rows
    assert rows[0].owner == "bobinson", rows[0].owner
    assert "linked_cwe" in rows[0].reason
    assert len(rows[0].reason.strip()) > 40


def test_every_manifest_states_a_contract_or_records_why_it_does_not():
    """No manifest may be silently outside the sweep.

    Both directions, so a `NO_CONTRACT` row whose spec grew a contract fragment
    fails too — a stale exemption is how a spec ends up excused from a check it
    now passes, and then from one it does not.
    """
    unanswered = [sid for sid, spec in sorted(MANIFESTS.items())
                  if not contract_fragments(spec) and sid not in NO_CONTRACT]
    assert unanswered == [], (
        f"{unanswered}: no contract fragment and no NO_CONTRACT reason")
    assert set(NO_CONTRACT) <= set(MANIFESTS), sorted(set(NO_CONTRACT) - set(MANIFESTS))
    contradictory = [sid for sid in sorted(NO_CONTRACT) if contract_fragments(MANIFESTS[sid])]
    assert contradictory == [], f"{contradictory}: exempted while stating a contract"
    for sid, why in sorted(NO_CONTRACT.items()):
        assert len(why.strip()) > 40, f"{sid}: no reason"


def test_the_sweep_is_not_vacuous():
    """A derivation that found no contract would satisfy every assertion."""
    covered = {sid: contract_fragments(spec) for sid, spec in MANIFESTS.items()}
    with_contract = {sid: f for sid, f in covered.items() if f}
    assert len(MANIFESTS) >= 26, len(MANIFESTS)
    assert len(with_contract) == len(MANIFESTS) - len(NO_CONTRACT)
    assert len(with_contract) >= 20, sorted(with_contract)
    # Every tier is represented — a sweep that only reached one would not cover
    # the blocker, which names two.
    tiers = {sid.split("/")[0].split("_")[0] for sid in with_contract}
    assert {"generate", "validate", "prove", "discover"} <= tiers, tiers
    # And the contracts are real text, not empty fragments that trivially pass.
    for sid, fids in sorted(with_contract.items()):
        for fid in fids:
            assert len(registry.get(fid).text.strip()) > 40, f"{sid}/{fid}"


def test_the_two_families_have_the_capabilities_this_file_assumes():
    """A profile change that flipped either one would make the file vacuous."""
    assert profile_for(GEMMA).system_role is False
    assert profile_for(CONTROL).system_role is True
