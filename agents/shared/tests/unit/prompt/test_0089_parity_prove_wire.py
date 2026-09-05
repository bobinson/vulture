"""Feature 0089 Phase 1 — PROVE **wire-payload** parity, derived from the live builder.

REPAIR FILE. It exists because ``test_0089_parity_prove.py`` claims something it
does not check, and Phase 1 may not edit an existing test. That file's lines
96-97 assert::

    rp.messages == [{"role": "system", "content": live_text}]
    rp.user == ""

and its docstring calls this "the exact bytes the live strategy would send to
the model, in the exact role placement". Both sides of that ``==`` are written
by the test. The live path is a single funnel for all three prove families
(``prove_agent/llm_helper.py`` ``llm_json_call``, reached from
``strategies/{cwe,owasp,soc2,ssdf,chaos}.py``, ``strategies/shared.py`` and
``protocols/{ws,jsonrpc}_executor.py``) and it sends TWO turns::

    [{"role": "system", "content": _SYSTEM_MSG},
     {"role": "user",   "content": prompt + guidance}]

So the plan / reflect / analyze text lives in the **user** turn live, next to a
separate system turn — and no mutation of the live builder (its system text, its
role, or deleting its system turn outright) can make that hardcoded literal
fail. Every assertion below instead compares a library render against the
messages ``llm_json_call`` *actually assembles*, captured by stubbing
``litellm.acompletion``. Independent provenance on each side: the expected bytes
come from ``.md`` fragment files through ``render()``, the actual bytes come from
running the live builder.

Docstring correction owed to the same audit: the sibling file says "no
whitespace normalisation". True of the test, false of the pipeline under test —
``render._join`` normalises fragment EDGES (``p.rstrip("\n")`` per part, then
``lstrip("\n")`` on the join), so a leading or trailing newline added to a
fragment *file* is invisible to any rendered comparison. That drift is caught
here by pinning the RAW fragment text as well (see
``test_prove_fragment_text_is_byte_exact_including_edges``); the two checks are
not redundant, they see different mutations.

Nothing here is normalised, no length stands in for an equality, and no ``in``
is used as an ``==``. Offline: the transport is stubbed, and the live truncator
cannot fire (``_truncate_prompt``'s floor is 1024 tokens = 4096 chars for any
context window; the longest prove prompt is 1340 chars).
"""

from __future__ import annotations

import asyncio

import litellm
import pytest
from _format_pin import as_fragment_text
from prove_agent import llm_helper
from prove_agent.llm_helper import _RETRY_GUIDANCE, _SYSTEM_MSG
from prove_agent.protocols.jsonrpc_executor import _ANALYZE_PROMPT as RPC_ANALYZE
from prove_agent.protocols.ws_executor import _ANALYZE_PROMPT as WS_ANALYZE
from prove_agent.strategies import chaos, cwe, owasp, soc2, ssdf
from prove_agent.strategies.shared import _ANALYZE_PROMPT as HTTP_ANALYZE

from shared.prompt import registry
from shared.prompt.manifests.prove_analyze import PROVE_ANALYZE
from shared.prompt.manifests.prove_plan import PROVE_PLANS
from shared.prompt.manifests.prove_reflect import PROVE_REFLECT
from shared.prompt.profile import profile_for
from shared.prompt.render import Mode, render
from shared.prompt.spec import PromptSpec

_STRATEGIES = ("cwe", "owasp", "soc2", "ssdf", "chaos")
_MODS = {"cwe": cwe, "owasp": owasp, "soc2": soc2, "ssdf": ssdf, "chaos": chaos}

# fragment id -> the live constant it transcribes, and -> the shipped spec.
_LIVE_BY_FRAGMENT: dict[str, str] = {
    **{f"prove/plan_{n}": as_fragment_text(_MODS[n]._PLAN_PROMPT) for n in _STRATEGIES},
    **{f"prove/reflect_{n}": as_fragment_text(_MODS[n]._REFLECT_PROMPT) for n in _STRATEGIES},
    "prove/analyze_http": as_fragment_text(HTTP_ANALYZE),
    "prove/analyze_ws": as_fragment_text(WS_ANALYZE),
    "prove/analyze_jsonrpc": as_fragment_text(RPC_ANALYZE),
}
_SPEC_BY_FRAGMENT: dict[str, PromptSpec] = {
    **{f"prove/plan_{n}": PROVE_PLANS[n] for n in _STRATEGIES},
    **{f"prove/reflect_{n}": PROVE_REFLECT[n] for n in _STRATEGIES},
    **{f"prove/analyze_{p}": PROVE_ANALYZE[p] for p in ("http", "ws", "jsonrpc")},
}

# Hardcoded so an id typo, a dropped family, or a mapping that silently
# evaluates to {} cannot turn the parametrised tests below into zero tests.
_EXPECTED_FRAGMENT_IDS = frozenset({
    "prove/plan_cwe", "prove/plan_owasp", "prove/plan_soc2", "prove/plan_ssdf",
    "prove/plan_chaos",
    "prove/reflect_cwe", "prove/reflect_owasp", "prove/reflect_soc2",
    "prove/reflect_ssdf", "prove/reflect_chaos",
    "prove/analyze_http", "prove/analyze_ws", "prove/analyze_jsonrpc",
})
_FRAGMENT_IDS = sorted(_EXPECTED_FRAGMENT_IDS)


# ── capturing the live builder ────────────────────────────────────────────────

class _StubMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _StubChoice:
    def __init__(self, content: str) -> None:
        self.message = _StubMessage(content)


class _StubResponse:
    """Shaped like a litellm response; `usage=None` so no global counter moves."""

    def __init__(self, content: str) -> None:
        self.choices = [_StubChoice(content)]
        self.usage = None


def _capture_live_messages(monkeypatch, prompt: str, *, reply: str) -> list[list[dict]]:
    """Run the real ``llm_json_call`` and return the messages it assembled.

    One entry per attempt, in order. Only the transport is replaced —
    ``llm_json_call``'s own message assembly, role placement, retry-guidance
    selection and concatenation all execute for real, which is the whole point:
    a hand-written expectation cannot notice when that assembly changes.

    ``llm_json_call`` swallows every exception, so a stub that never ran would
    otherwise look like a clean pass. The captured count is asserted by callers.
    """
    # The stub binds because `llm_json_call` imports `acompletion` at call time.
    # If that import is ever hoisted to module scope the patch stops taking
    # effect and this test would reach for the real provider, so pin it here
    # rather than discover it as a network timeout.
    assert not hasattr(llm_helper, "acompletion"), (
        "llm_helper imports acompletion at module scope now; the transport stub "
        "no longer binds and this test would go to the network"
    )
    captured: list[list[dict]] = []

    async def _stub(**kwargs):
        captured.append(kwargs["messages"])
        return _StubResponse(reply)

    monkeypatch.setattr(litellm, "acompletion", _stub, raising=True)
    asyncio.run(llm_helper.llm_json_call(prompt))
    return captured


def _live_wire(monkeypatch, prompt: str) -> list[dict]:
    """The single-attempt live payload for ``prompt`` (valid JSON reply, no retry)."""
    attempts = _capture_live_messages(monkeypatch, prompt, reply='{"ok": 1}')
    assert len(attempts) == 1, f"live builder made {len(attempts)} calls, expected 1"
    wire = attempts[0]
    # Shape guard, so the byte `==` below can never be two empty lists agreeing.
    assert [m["role"] for m in wire] == ["system", "user"]
    assert wire[1]["content"], "live user turn is empty — nothing to compare"
    return wire


# ── coverage guard ────────────────────────────────────────────────────────────

def test_all_thirteen_prove_prompt_families_are_covered():
    assert set(_LIVE_BY_FRAGMENT) == _EXPECTED_FRAGMENT_IDS
    assert set(_SPEC_BY_FRAGMENT) == _EXPECTED_FRAGMENT_IDS
    assert len(_FRAGMENT_IDS) == 13
    for fid, text in _LIVE_BY_FRAGMENT.items():
        assert text, f"{fid}: live constant is empty"


# ── 1. the live assembly itself (what the old literal contradicted) ───────────

def test_live_prove_call_sends_system_msg_then_the_prompt_as_user(monkeypatch):
    """Role placement, pinned against the builder rather than asserted about it.

    Sentinel content, so the assertion is about WHICH turn each string lands in
    and nothing else. Mutating the live role, dropping the live system turn, or
    reordering the turns each fail here.
    """
    sentinel = "SENTINEL-PROMPT-0089"
    wire = _capture_live_messages(monkeypatch, sentinel, reply='{"ok": 1}')
    assert len(wire) == 1
    assert wire[0] == [
        {"role": "system", "content": _SYSTEM_MSG},
        {"role": "user", "content": sentinel},
    ]


def test_live_prove_retry_appends_guidance_to_the_user_turn(monkeypatch):
    """Three attempts, guidance selected by index and concatenated — not joined."""
    sentinel = "SENTINEL-PROMPT-0089"
    attempts = _capture_live_messages(monkeypatch, sentinel, reply="not json at all")
    assert len(attempts) == 3
    for n, wire in enumerate(attempts):
        assert wire == [
            {"role": "system", "content": _SYSTEM_MSG},
            {"role": "user", "content": sentinel + _RETRY_GUIDANCE[n]},
        ]


# ── 2. raw fragment bytes, including the edges render() normalises away ───────

@pytest.mark.parametrize("fid", _FRAGMENT_IDS)
def test_prove_fragment_text_is_byte_exact_including_edges(fid: str):
    """The fragment FILE body equals the live constant, edge newlines included.

    Not covered by any rendered comparison: ``render._join`` strips a part's
    trailing newlines and the joined body's leading ones, so a fragment file
    that grows a trailing ``\\n`` still renders identically. This is the only
    check in this file that sees that mutation.
    """
    assert registry.get(fid).text == _LIVE_BY_FRAGMENT[fid]


def test_prove_system_fragment_text_is_byte_exact():
    assert registry.get("prove/system").text == _SYSTEM_MSG


# ── 3. HEADLINE: the library reproduces the live wire payload, byte for byte ──

@pytest.mark.parametrize("fid", _FRAGMENT_IDS)
def test_library_reproduces_the_live_wire_payload(monkeypatch, fid: str):
    """``render()`` == the messages ``llm_json_call`` assembled. Both turns.

    The composition is the one the live call makes: ``prove/system`` in the
    system turn, the prompt fragment in the USER turn. It is spelled out here
    rather than taken from a manifest because no shipped prove manifest states
    it yet — that gap is what
    ``test_shipped_prove_manifests_place_the_prompt_in_the_wrong_turn`` records.

    Left side reads ``.md`` files through the renderer; right side is produced
    by executing the prove agent's own builder. Neither is derived from the
    other, and no byte is normalised on either side.
    """
    live_text = _LIVE_BY_FRAGMENT[fid]
    spec = PromptSpec(
        id=f"parity_{fid.replace('/', '_')}",
        tier="prove",
        fragments=("prove/system",),
        user_fragments=(fid,),
    )
    rp = render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    assert rp.messages == _live_wire(monkeypatch, live_text)


# `test_shipped_prove_manifests_place_the_prompt_in_the_wrong_turn` stood here.
# It recorded, executably, that the shipped manifests put the plan / reflect /
# analyze prompt in the SYSTEM turn while `llm_json_call` sends it in the USER
# turn beside a separate `_SYSTEM_MSG`. Its own docstring directed that it be
# deleted by the repair rather than outlive it, and the repair has landed: the
# fragments declare `role: USER`, the manifests list them in `user_fragments`,
# and `prove/system` is back in the system turn. The assertions below now cover
# the corrected placement against the live wire payload.
#
# Worth keeping in the record: had Phase 2 flipped the prove call site while
# trusting the library's placement, every prove prompt would have moved to the
# wrong role AND the `_SYSTEM_MSG` turn would have been dropped. Phase 1 caught
# it with no production byte changed.


# ── 5. the retry seam no spec can express (successor to the 157 vs 159 B gap) ─

@pytest.mark.parametrize("attempt", (1, 2))
def test_retry_guidance_cannot_be_a_second_user_fragment(monkeypatch, attempt: int):
    """``prompt + guidance`` is concatenation; two user fragments are joined.

    ``manifests/prove_system.py``'s ``PROVE_RETRY`` renders the guidance ALONE
    as a single ``verbatim`` user fragment and is byte-exact (asserted next door
    in ``test_0089_parity_prove_system.py``). What no spec can express is the
    live user turn itself, because ``_join`` owns the separator: composing
    ``(plan, guidance)`` emits the renderer's ``"\\n\\n"`` *and* the guidance's
    own leading ``"\\n\\n"``, four newlines where live sends two.

    Both sides are pinned to bytes against their own provenance, so this fails
    if the live concatenation changes, if the guidance fragment's leading
    newlines change, or when Phase 2 teaches the renderer to append a verbatim
    suffix (at which point the two become equal and this record goes away).
    """
    plan = _LIVE_BY_FRAGMENT["prove/plan_cwe"]
    guidance = _RETRY_GUIDANCE[attempt]
    live = _capture_live_messages(monkeypatch, plan, reply="not json at all")
    assert len(live) == 3
    live_user = live[attempt][1]["content"]
    assert live_user == plan + guidance

    spec = PromptSpec(
        id=f"parity_plan_cwe_retry_{attempt}",
        tier="prove",
        fragments=("prove/system",),
        user_fragments=("prove/plan_cwe", f"prove/retry_guidance_{attempt}"),
    )
    rendered_user = render(
        spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE
    ).user
    assert rendered_user == plan + "\n\n" + guidance
    assert guidance.startswith("\n\n"), "the live separator belongs to the guidance"
