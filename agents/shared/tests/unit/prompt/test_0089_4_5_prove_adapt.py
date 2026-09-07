"""Feature 0089 Item 4.5 — PROVE flips to ADAPT + the drift fixes 2.6 deferred.

Test-first (GREEN team). Every assertion here targets the NEW behaviour and
FAILS against the pre-4.5 tree; each is driven against live code
(`render_prove_prompt`, the manifests, `lint`, `render`), never a literal
written in the test.

What 4.5 changes, and the assertion that pins each:

  * `prove/system` constrains the response SHAPE only. Its text no longer
    forbids the `analysis` field the reflect schema demands — the FORBIDS_PROSE
    stance is envelope-scoped, exactly as `validate/output_contract` uses it
    alongside its own free-text `reasoning` field.
  * ssdf's rule-3 build-artifacts exclusion is restored, matching the family.
  * the plan exemplar no longer teaches `/real-path` or `payload if POST` — the
    two literals the executor SENDS verbatim (check_09 placeholder_echo).
  * the evidence block (Code/Hints) reaches soc2/ssdf/chaos, not just cwe/owasp.
  * the plan schema carries the full ProofPlan contract — filename, protocol,
    rpc_method, rpc_params — which retires cwe's `filename` orphan_field.
  * the three analyze prompts place the output contract ABOVE the untrusted
    response block and add an undecidable clause.
  * the call site renders in ADAPT.

Import note: prove lives at `agents/prove`, installed editable as
`vulture-prove-agent`, so `import prove_agent` resolves from this shared test
tree exactly as the sibling `test_0089_parity_prove.py` does.
"""

from __future__ import annotations

import dataclasses
import inspect

from prove_agent import llm_helper
from prove_agent.llm_helper import render_prove_prompt
from shared.prompt import Mode, lint, profile_for, registry, render
from shared.prompt.fragment import Stance
from shared.prompt.manifests.prove_analyze import PROVE_ANALYZE_DOMAIN
from shared.prompt.manifests.prove_plan import PROVE_PLAN_DOMAIN, PROVE_PLANS
from shared.prompt.manifests.prove_reflect import PROVE_REFLECT
from shared.prompt.manifests.prove_system import PROVE_SYSTEM

_STRATEGIES = ("cwe", "owasp", "soc2", "ssdf", "chaos")
_PROTOCOLS = ("http", "ws", "jsonrpc")

# Every strategy now carries the evidence block, so every plan render is driven
# with the code/hints runtime values.
_PLAN_RT = dict(
    title="SQL injection", category="CWE-89", description="user input in query",
    file_path="app/db.py", line_start=42, code_snippet="cur.execute(q)",
    verification_hints="try a quote", staging_url="http://staging",
    iteration=1, site_context="/api/users", prior_context="none",
)

_ANALYZE_RT = {
    "http": dict(title="t", category="c", method="GET", url="http://s/x",
                 status_code=200, response_headers='{"h":"v"}',
                 response_snippet="BODY-BODY-BODY", expected_indicators='["ind"]'),
    "ws": dict(title="t", category="c", url="ws://s/x", messages="MSG-MSG-MSG",
               expected_indicators='["ind"]'),
    "jsonrpc": dict(title="t", category="c", method="rpc_x",
                    response="RESP-RESP-RESP", expected_indicators='["ind"]'),
}
# The stable literal that marks the START of the untrusted response block per
# protocol. It appears nowhere else in the prompt.
_UNTRUSTED_MARKER = {
    "http": "Response (truncated):",
    "ws": "Messages received:",
    "jsonrpc": "RPC method:",
}


def _prof():
    return profile_for("gpt-4o")


# ── 1. system message constrains SHAPE, not the analysis field ────────────────

def test_system_constrains_shape_not_the_analysis_field():
    text = registry.get("prove/system").text
    # It still constrains the ENVELOPE to a single JSON object with no markup.
    assert "JSON object" in text
    assert "markdown" in text.lower()
    # ...but it no longer forbids the reflect schema's `analysis` field by name.
    assert "analysis" not in text.lower(), text
    # The removal matters because reflect really does demand that field.
    assert "analysis" in PROVE_REFLECT["cwe"].schema_fields


def test_system_keeps_forbids_prose_as_an_envelope_stance():
    """FORBIDS_PROSE means the ENVELOPE is strict JSON — the same way
    `validate/output_contract` carries it beside its free-text `reasoning`
    field. The stance stays; only the text that named a schema field is gone."""
    assert Stance.FORBIDS_PROSE in registry.get("prove/system").stance


# ── 2. ssdf's lost exclusion is restored ──────────────────────────────────────

def test_ssdf_regains_the_build_artifacts_exclusion():
    rules = PROVE_PLAN_DOMAIN["ssdf"]["domain_rules"]
    assert "build artifacts (_next/static/*, _buildManifest.js, etc.)" in rules
    assert "These are NOT API endpoints." in rules
    got = render_prove_prompt("prove/plan", PROVE_PLAN_DOMAIN["ssdf"], **_PLAN_RT)
    assert "build artifacts (_next/static/*, _buildManifest.js, etc.)" in got


def test_every_plan_strategy_shares_the_build_artifacts_exclusion():
    for name in _STRATEGIES:
        got = render_prove_prompt("prove/plan", PROVE_PLAN_DOMAIN[name], **_PLAN_RT)
        assert "build artifacts (_next/static/*, _buildManifest.js, etc.)" in got, name


# ── 3. the placeholder exemplar no longer teaches a literal the executor sends ─

def test_plan_exemplar_no_longer_teaches_sent_placeholders():
    for name in _STRATEGIES:
        got = render_prove_prompt("prove/plan", PROVE_PLAN_DOMAIN[name], **_PLAN_RT)
        assert "/real-path" not in got, name
        assert "payload if POST" not in got, name
    # ...and the per-strategy oracle fragments agree.
    for name in _STRATEGIES:
        t = registry.get(f"prove/plan_{name}").text
        assert "/real-path" not in t and "payload if POST" not in t, name


def test_placeholder_echo_no_longer_fires_on_any_plan_spec():
    prof = _prof()
    for name in _STRATEGIES:
        spec = PROVE_PLANS[name]
        rp = render(spec, prof, mode=Mode.TRANSCRIBE)
        echoes = [f for f in lint(spec, rp) if f.check == "placeholder_echo"]
        assert echoes == [], (name, echoes)


# ── 4. the missing evidence block reaches every strategy ──────────────────────

def test_evidence_block_reaches_all_five_strategies():
    for name in _STRATEGIES:
        block = PROVE_PLAN_DOMAIN[name]["evidence_block"]
        assert "Code: {code_snippet}" in block, name
        assert "Hints: {verification_hints}" in block, name
        got = render_prove_prompt("prove/plan", PROVE_PLAN_DOMAIN[name], **_PLAN_RT)
        assert "Code: cur.execute(q)" in got, name
        assert "Hints: try a quote" in got, name


# ── 5. the plan schema carries the full ProofPlan contract ────────────────────

def test_plan_schema_carries_full_proofplan_contract():
    for name in _STRATEGIES:
        sf = PROVE_PLANS[name].schema_fields
        for field in ("filename", "protocol", "rpc_method", "rpc_params"):
            assert field in sf, (name, field)


def test_cwe_filename_is_no_longer_an_orphan_field():
    prof = _prof()
    spec = PROVE_PLANS["cwe"]
    rp = render(spec, prof, mode=Mode.TRANSCRIBE)
    orphans = [f for f in lint(spec, rp) if f.check == "orphan_field"]
    assert orphans == [], orphans


# ── 6. analyze: output contract ABOVE the untrusted block + undecidable clause ─

def test_analyze_output_contract_is_above_the_untrusted_block():
    for proto in _PROTOCOLS:
        got = render_prove_prompt(
            "prove/analyze", PROVE_ANALYZE_DOMAIN[proto], **_ANALYZE_RT[proto],
        )
        contract = got.index("Reply with JSON only:")
        untrusted = got.index(_UNTRUSTED_MARKER[proto])
        assert contract < untrusted, (proto, got)


def test_analyze_gains_an_undecidable_clause():
    for proto in _PROTOCOLS:
        got = render_prove_prompt(
            "prove/analyze", PROVE_ANALYZE_DOMAIN[proto], **_ANALYZE_RT[proto],
        )
        assert 'set "conclusive" to false' in got, (proto, got)


def test_analyze_untrusted_response_is_last():
    """The response body — the only attacker-controlled span — ends the prompt,
    so nothing the target returns can sit after an instruction."""
    for proto in _PROTOCOLS:
        got = render_prove_prompt(
            "prove/analyze", PROVE_ANALYZE_DOMAIN[proto], **_ANALYZE_RT[proto],
        )
        payload = {"http": "BODY-BODY-BODY", "ws": "MSG-MSG-MSG",
                   "jsonrpc": "RESP-RESP-RESP"}[proto]
        assert got.rstrip().endswith(payload), (proto, got)


# ── 7. the call site renders in ADAPT ─────────────────────────────────────────

def test_prove_render_call_site_uses_adapt():
    src = inspect.getsource(llm_helper._render)
    assert "Mode.ADAPT" in src
    assert "Mode.TRANSCRIBE" not in src


def test_the_flip_still_changes_nothing_beyond_the_rules_that_are_armed():
    """Item 4.5's safety property, restated for a tree where a rule now bites.

    IT READ, UNTIL ITEM 4.8:

        def test_flip_is_byte_invariant_on_the_default_openai_profile():
            a = render(PROVE_SYSTEM, prof, mode=Mode.ADAPT)
            t = render(PROVE_SYSTEM, prof, mode=Mode.TRANSCRIBE)
            assert a.instructions == t.instructions
            assert a.messages == t.messages

    — "on the shipped default (openai) profile the system turn renders
    identically in both modes". That was 4.5's evidence that flipping this call
    site to ADAPT moved no shipped byte, and it was true because no rule
    applied to `PROVE_SYSTEM`: rule 4+5 found no `REQUIRES_FENCE` fragment,
    rule 1 found a profile with a system role, and rule 9 found no
    `BINDS_LANGUAGE` fragment anywhere in the library.

    Item 4.8 armed rule 9 by adding one, so the two modes MUST now differ on
    this profile — TRANSCRIBE applies no rule and keeps `core/language`, ADAPT
    drops it because `gpt-4o` does not pin its output language. Asserting the
    old equality would be asserting that rule 9 does not work.

    What survives is the part of the claim that was ever about the flip: ADAPT
    changes the turn by the rules and by NOTHING else. So the comparison is
    against the transcription of the same spec with exactly the fragments rule
    9 drops removed — byte for byte, both turns and the message list.
    """
    prof = _prof()
    assert prof.output_language_pin is False, "fixture assumption"
    a = render(PROVE_SYSTEM, prof, mode=Mode.ADAPT)
    t = render(PROVE_SYSTEM, prof, mode=Mode.TRANSCRIBE)
    assert a.instructions != t.instructions, (
        "rule 9 is armed and this profile does not pin its output language, so "
        "the two modes cannot agree"
    )
    dropped = dataclasses.replace(
        PROVE_SYSTEM,
        fragments=tuple(f for f in PROVE_SYSTEM.fragments
                        if Stance.BINDS_LANGUAGE not in registry.get(f).stance),
    )
    expected = render(dropped, prof, mode=Mode.TRANSCRIBE)
    assert a.instructions == expected.instructions
    assert a.messages == expected.messages


def test_flip_relocates_the_system_turn_for_a_no_system_role_profile():
    """The improvement ADAPT buys prove: a gemma-family model (no system role)
    gets the JSON-API instruction folded into the front of its single user turn
    instead of a system message its chat template would silently drop."""
    prof = profile_for("gemma-2-9b")
    assert prof.system_role is False
    rp = render(PROVE_SYSTEM, prof, mode=Mode.ADAPT)
    assert rp.instructions == ""
    assert rp.messages and rp.messages[0]["role"] == "user"
    assert "JSON object" in rp.messages[0]["content"]
