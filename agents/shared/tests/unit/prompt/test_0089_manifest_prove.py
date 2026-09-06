"""Feature 0089 Phase 0.c — PROVE tier transcription (frag-prove set).

Phase 1 parity: every prove prompt must be reproducible byte-for-byte from the
library. These tests import the ORIGINAL constants and assert the transcribed
fragments equal them, then that the four manifests render and that promptlint
already sees the two real audit findings this transcription exposes:
a cwe plan field (`filename`) no schema has, and analyze fragments that
interpolate a raw HTTP body with no MARKS_UNTRUSTED marker.
"""

from __future__ import annotations

from _format_pin import as_fragment_text

from prove_agent.llm_helper import _RETRY_GUIDANCE, _SYSTEM_MSG
from prove_agent.protocols.jsonrpc_executor import _ANALYZE_PROMPT as RPC_ANALYZE
from prove_agent.protocols.ws_executor import _ANALYZE_PROMPT as WS_ANALYZE
from prove_agent.strategies import chaos, cwe, owasp, soc2, ssdf
from prove_agent.strategies.shared import _ANALYZE_PROMPT as HTTP_ANALYZE
from shared.prompt import Mode, Stance, lint, profile_for, registry, render
from shared.prompt.manifests import MANIFESTS
from shared.prompt.manifests.prove_analyze import PROVE_ANALYZE
from shared.prompt.manifests.prove_plan import PROVE_PLANS
from shared.prompt.manifests.prove_reflect import PROVE_REFLECT
from shared.prompt.manifests.prove_system import PROVE_SYSTEM

_STRATEGY_MODS = {
    "cwe": cwe, "owasp": owasp, "soc2": soc2, "ssdf": ssdf, "chaos": chaos,
}


def _frag(fid: str):
    return registry.get(fid)


def _frags_of(spec):
    ids = tuple(spec.fragments) + tuple(spec.user_fragments)
    return [registry.get(i) for i in ids]


def test_prove_fragments_are_byte_exact():
    assert _frag("prove/system").text == _SYSTEM_MSG
    # Both non-empty variants, each pinned to its own index. The previous form
    # (`_frag("prove/retry_guidance").text in _RETRY_GUIDANCE`) asserted only
    # that ONE fragment matched SOME variant, so variant 2 was never
    # transcribed at all and an index swap would not have been caught.
    assert _frag("prove/retry_guidance_1").text == _RETRY_GUIDANCE[1]
    assert _frag("prove/retry_guidance_2").text == _RETRY_GUIDANCE[2]
    assert _RETRY_GUIDANCE[0] == "", "attempt 0 sends no guidance"
    for name, mod in _STRATEGY_MODS.items():
        assert _frag(f"prove/plan_{name}").text == as_fragment_text(mod._PLAN_PROMPT)
        assert _frag(f"prove/reflect_{name}").text == as_fragment_text(mod._REFLECT_PROMPT)
    assert _frag("prove/analyze_http").text == as_fragment_text(HTTP_ANALYZE)
    assert _frag("prove/analyze_ws").text == as_fragment_text(WS_ANALYZE)
    assert _frag("prove/analyze_jsonrpc").text == as_fragment_text(RPC_ANALYZE)


def test_manifest_prove_renders_all_five_strategies():
    """ADAPT as of item 4.8: `_SYSTEM_MSG` is an ADAPT render, and the two
    modes stopped agreeing when `core/language` joined this tier's system
    turn (rule 9 drops it for `gpt-4o`; TRANSCRIBE keeps it)."""
    prof = profile_for("gpt-4o")
    assert set(PROVE_PLANS) == {"cwe", "owasp", "soc2", "ssdf", "chaos"}
    for name, spec in PROVE_PLANS.items():
        rp = render(spec, prof, mode=Mode.ADAPT)
        # The USER turn, and as bytes: live sends the prompt as the user
        # message beside a separate `_SYSTEM_MSG`. This read `in rp.instructions`
        # before the placement was corrected — wrong turn, and a substring where
        # an equality belongs.
        assert rp.user == as_fragment_text(_STRATEGY_MODS[name]._PLAN_PROMPT)
        assert rp.instructions == _SYSTEM_MSG
    # reflect + analyze render too
    for spec in PROVE_REFLECT.values():
        render(spec, prof, mode=Mode.TRANSCRIBE)
    for spec in PROVE_ANALYZE.values():
        render(spec, prof, mode=Mode.TRANSCRIBE)
    render(PROVE_SYSTEM, prof, mode=Mode.TRANSCRIBE)
    # every prove spec is registered in the shared MANIFESTS table
    for key in ("prove_system", "prove_plan_cwe", "prove_reflect_cwe",
                "prove_analyze_http"):
        assert key in MANIFESTS
        assert MANIFESTS[key].tier == "prove"


def test_lint_surfaces_prove_blockers():
    prof = profile_for("gpt-4o")
    # Item 4.5 widened the plan schema to the full ProofPlan, so cwe's
    # `filename` instruction (rule 8, file upload) is no longer an orphan_field.
    # BEFORE 4.5 this asserted `any("filename" in f.message for f in orphans)` —
    # `filename` declared on the fragment but absent from `_PLAN_SCHEMA`. 4.5
    # added it (with protocol/rpc_method/rpc_params), so the orphan is now GONE.
    cwe_spec = PROVE_PLANS["cwe"]
    rp = render(cwe_spec, prof, mode=Mode.TRANSCRIBE)
    orphans = [f for f in lint(cwe_spec, rp) if f.check == "orphan_field"]
    assert orphans == [], orphans
    assert "filename" in cwe_spec.schema_fields
    # slot_marking is silent ONLY because slots are empty at this phase; the
    # real gap is that no analyze fragment MARKS_UNTRUSTED the raw HTTP body.
    for spec in PROVE_ANALYZE.values():
        rp = render(spec, prof, mode=Mode.TRANSCRIBE)
        assert not any(f.check == "slot_marking" for f in lint(spec, rp))
        assert not any(
            Stance.MARKS_UNTRUSTED in fr.stance for fr in _frags_of(spec)
        )
