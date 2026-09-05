"""Feature 0089 Phase 1 — PROVE assembled-prompt byte parity (GREEN team).

Phase 1 adds NO production code; this file only ADDS a test. It proves the
prompt library reproduces the prove agent's live prompts *as assembled*:
``render(spec, ..., mode=TRANSCRIBE)`` must hand back the exact bytes the live
strategy would send to the model, in the exact role placement, for every prove
plan / reflect / analyze prompt.

Three tests, one per prove prompt family:

  * ``test_prove_plan_assembled_parity``    — cwe is the transcription base.
  * ``test_prove_reflect_assembled_parity`` — cwe is the transcription base.
  * ``test_prove_analyze_assembled_parity`` — http is the transcription base
    (the default protocol executor path).

BYTE parity only. Every parity assertion is a raw ``rendered == live`` (or the
exact ``messages`` list) — no whitespace normalisation, no length compare, no
set compare, no ``in``-as-equality. Each assertion FAILS the instant a fragment
drifts from its live constant.

Phase 2.6 (collapse the five per-strategy copies onto one base + a domain-rules
fragment) has NOT happened, so five full copies of the plan/reflect text still
live in the strategies. These tests assert TODAY's truth: each copy transcribes
to ITS OWN live constant, and the non-base copies DIFFER from the base. They do
not — and must not — assert the copies are equal, because they are not.

Import note: prove lives at ``agents/prove``, not under ``agents/shared``. It is
installed as the editable ``vulture-prove-agent`` package, so ``import
prove_agent`` resolves from this shared test tree exactly as the prove suite's
own tests do; the sibling ``test_0089_manifest_prove.py`` imports it the same
way.
"""

from __future__ import annotations

from _format_pin import as_fragment_text
from prove_agent.llm_helper import _SYSTEM_MSG
from prove_agent.protocols.jsonrpc_executor import _ANALYZE_PROMPT as RPC_ANALYZE
from prove_agent.protocols.ws_executor import _ANALYZE_PROMPT as WS_ANALYZE
from prove_agent.strategies import chaos, cwe, owasp, soc2, ssdf
from prove_agent.strategies.shared import _ANALYZE_PROMPT as HTTP_ANALYZE

from shared.prompt.manifests.prove_analyze import PROVE_ANALYZE
from shared.prompt.manifests.prove_plan import PROVE_PLANS
from shared.prompt.manifests.prove_reflect import PROVE_REFLECT
from shared.prompt.profile import profile_for
from shared.prompt.render import Mode, render

# Live plan/reflect constants keyed by strategy; cwe is the designated base.
_PLAN_LIVE = {
    "cwe": as_fragment_text(cwe._PLAN_PROMPT),
    "owasp": as_fragment_text(owasp._PLAN_PROMPT),
    "soc2": as_fragment_text(soc2._PLAN_PROMPT),
    "ssdf": as_fragment_text(ssdf._PLAN_PROMPT),
    "chaos": as_fragment_text(chaos._PLAN_PROMPT),
}
_REFLECT_LIVE = {
    "cwe": as_fragment_text(cwe._REFLECT_PROMPT),
    "owasp": as_fragment_text(owasp._REFLECT_PROMPT),
    "soc2": as_fragment_text(soc2._REFLECT_PROMPT),
    "ssdf": as_fragment_text(ssdf._REFLECT_PROMPT),
    "chaos": as_fragment_text(chaos._REFLECT_PROMPT),
}
# Live analyze constants keyed by protocol; http is the designated base.
_ANALYZE_LIVE = {
    "http": as_fragment_text(HTTP_ANALYZE),
    "ws": as_fragment_text(WS_ANALYZE),
    "jsonrpc": as_fragment_text(RPC_ANALYZE),
}

# Shared JSON-contract tails — byte-identical across every copy in a family, and
# the scaffold Phase 2.6 will factor into the base. Hardcoded as literals (not
# derived from the base) so the shared-tail check is falsifiable rather than a
# tautology, and so a copy whose contract drifts is caught here too.
# Single braces: these pin the tail of the prompt AS THE MODEL RECEIVES IT.
# They read `{{` while the fragments carried the `str.format` escape, which is
# the same defect stated three times over — the doubled brace is the encoding,
# not the contract.
_PLAN_CONTRACT_TAIL = '","expected_indicators":["indicator"]}'
_REFLECT_CONTRACT_TAIL = (
    'Reply with JSON only:\n'
    '{"analysis":"why inconclusive","suggested_approach":"what to try differently","confidence":50,"learnings":["insight1","insight2"]}'
)
_ANALYZE_CONTRACT_TAIL = (
    'Reply with JSON only:\n'
    '{"conclusive":true,"reproduced":true,"evidence":"explanation"}'
)


def _assert_assembled_equals(spec, live_text: str, frag_id: str) -> str:
    """Assert the TRANSCRIBE render of ``spec`` reproduces ``live_text`` exactly.

    Returns the rendered system text so callers can compare copies to the base.
    Every check here is a raw byte ``==``; nothing is normalised. The profile is
    resolved per call (offline, from the provider table) and, in TRANSCRIBE mode,
    influences only the numeric budget hint — never a byte of the text.
    """
    rp = render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    # The assembled USER text is the live prompt, byte for byte. This asserted
    # `rp.instructions == live_text` and `rp.user == ""` until Phase 1 measured
    # the live call site: `llm_json_call` sends TWO turns and the prompt is the
    # user one. The old form was self-consistent and wrong about production.
    assert rp.user == live_text
    assert rp.instructions == _SYSTEM_MSG
    assert rp.messages == [
        {"role": "system", "content": _SYSTEM_MSG},
        {"role": "user", "content": live_text},
    ]
    # …assembled from exactly the fragments the call site names, in order.
    assert rp.fragments == ("prove/system", frag_id)
    return rp.user


def test_prove_plan_assembled_parity():
    # Anti-vacuous guard: the live base must be the real, populated prompt (its
    # known head and contract tail), so the parity ``==`` below cannot pass by
    # comparing two empty strings.
    assert _PLAN_LIVE["cwe"].startswith(
        "You are a vulnerability researcher. Given this CWE finding,"
    )
    assert _PLAN_LIVE["cwe"][-len(_PLAN_CONTRACT_TAIL):] == _PLAN_CONTRACT_TAIL

    # Headline: render(prove_plan) equals the CWE strategy's live text, exactly.
    base = _assert_assembled_equals(
        PROVE_PLANS["cwe"], _PLAN_LIVE["cwe"], "prove/plan_cwe"
    )
    assert base == as_fragment_text(cwe._PLAN_PROMPT)

    # Every strategy copy transcribes to ITS OWN live constant, byte for byte.
    rendered = {"cwe": base}
    for name in ("owasp", "soc2", "ssdf", "chaos"):
        rendered[name] = _assert_assembled_equals(
            PROVE_PLANS[name], _PLAN_LIVE[name], f"prove/plan_{name}"
        )

    # Phase 2.6 has NOT run: the four copies still DIFFER from the cwe base.
    for name in ("owasp", "soc2", "ssdf", "chaos"):
        assert rendered[name] != base

    # What they share today is the JSON-contract tail (the future base scaffold).
    for text in rendered.values():
        assert text[-len(_PLAN_CONTRACT_TAIL):] == _PLAN_CONTRACT_TAIL


def test_prove_reflect_assembled_parity():
    assert _REFLECT_LIVE["cwe"].startswith(
        "You are a vulnerability researcher reflecting on failed"
    )
    assert (
        _REFLECT_LIVE["cwe"][-len(_REFLECT_CONTRACT_TAIL):]
        == _REFLECT_CONTRACT_TAIL
    )

    # Headline: render(prove_reflect) equals the CWE strategy's live text.
    base = _assert_assembled_equals(
        PROVE_REFLECT["cwe"], _REFLECT_LIVE["cwe"], "prove/reflect_cwe"
    )
    assert base == as_fragment_text(cwe._REFLECT_PROMPT)

    rendered = {"cwe": base}
    for name in ("owasp", "soc2", "ssdf", "chaos"):
        rendered[name] = _assert_assembled_equals(
            PROVE_REFLECT[name], _REFLECT_LIVE[name], f"prove/reflect_{name}"
        )

    for name in ("owasp", "soc2", "ssdf", "chaos"):
        assert rendered[name] != base

    for text in rendered.values():
        assert text[-len(_REFLECT_CONTRACT_TAIL):] == _REFLECT_CONTRACT_TAIL


def test_prove_analyze_assembled_parity():
    assert _ANALYZE_LIVE["http"].startswith(
        "Did this HTTP response confirm the vulnerability?"
    )
    assert (
        _ANALYZE_LIVE["http"][-len(_ANALYZE_CONTRACT_TAIL):]
        == _ANALYZE_CONTRACT_TAIL
    )

    # Headline: render(prove_analyze) equals the HTTP executor's live text.
    base = _assert_assembled_equals(
        PROVE_ANALYZE["http"], _ANALYZE_LIVE["http"], "prove/analyze_http"
    )
    assert base == as_fragment_text(HTTP_ANALYZE)

    rendered = {"http": base}
    for proto in ("ws", "jsonrpc"):
        rendered[proto] = _assert_assembled_equals(
            PROVE_ANALYZE[proto], _ANALYZE_LIVE[proto], f"prove/analyze_{proto}"
        )

    # The per-protocol copies still DIFFER from the http base today.
    for proto in ("ws", "jsonrpc"):
        assert rendered[proto] != base

    for text in rendered.values():
        assert text[-len(_ANALYZE_CONTRACT_TAIL):] == _ANALYZE_CONTRACT_TAIL
