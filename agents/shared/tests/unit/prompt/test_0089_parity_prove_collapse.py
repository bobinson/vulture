"""Feature 0089 Phase 2.6 — PROVE families collapsed onto one template each.

Phase 2.6 replaces the runtime's five `_PLAN_PROMPT`, five `_REFLECT_PROMPT` and
three `_ANALYZE_PROMPT` inline copies with ONE library template per family —
`prove/plan`, `prove/reflect`, `prove/analyze` — rendered with a per-strategy /
per-protocol slot table (`PROVE_{PLAN,REFLECT,ANALYZE}_DOMAIN`).

The plan's own acceptance check: render each collapsed template for every
strategy and diff against that strategy's original string; the only thing that
may vary is what goes into a slot. This file is that check, made executable and
BYTE exact.

The collapsed templates are deliberately NOT registered manifest specs — the
per-strategy `prove/plan_{name}` specs remain this family's golden/lint oracle,
and a parallel manifest would only duplicate their backlog annotations under a
new id (see `manifests/prove_plan.py`). So the render here builds the exact spec
the runtime builds (`prove_agent/llm_helper.render_prove_prompt`): one
`user_fragments` entry plus the slot table as `variables`. This file IS the
template's byte pin, in place of a self-referential golden.

Provenance on each side is independent, so the equality cannot pass by comparing
a thing to itself:

  * left  — `render(spec(user_fragments=("prove/plan",), variables=DOMAIN[key]))`,
    the library assembling the collapsed `.md` template with the manifest's slot
    table;
  * right — `as_fragment_text(mod._PLAN_PROMPT)`, the live inline constant the
    strategy shipped, with `str.format`'s `{{`/`}}` escape resolved the one way
    `render._fill` reads a brace (see `_format_pin`).

Import note: prove lives at `agents/prove`, installed editable as
`vulture-prove-agent`, so `import prove_agent` resolves from this shared test
tree exactly as the sibling `test_0089_parity_prove.py` does.
"""

from __future__ import annotations

from _format_pin import as_fragment_text

from prove_agent.llm_helper import render_prove_prompt
from prove_agent.protocols.jsonrpc_executor import _ANALYZE_PROMPT as RPC_ANALYZE
from prove_agent.protocols.ws_executor import _ANALYZE_PROMPT as WS_ANALYZE
from prove_agent.strategies import chaos, cwe, owasp, soc2, ssdf
from prove_agent.strategies.shared import _ANALYZE_PROMPT as HTTP_ANALYZE
from shared.prompt import Mode, profile_for, registry, render
from shared.prompt.manifests.prove_analyze import PROVE_ANALYZE_DOMAIN
from shared.prompt.manifests.prove_plan import PROVE_PLAN_DOMAIN
from shared.prompt.manifests.prove_reflect import PROVE_REFLECT_DOMAIN
from shared.prompt.spec import PromptSpec

_MODS = {"cwe": cwe, "owasp": owasp, "soc2": soc2, "ssdf": ssdf, "chaos": chaos}
_STRATEGIES = ("cwe", "owasp", "soc2", "ssdf", "chaos")
_PROTOCOLS = ("http", "ws", "jsonrpc")

_PLAN_LIVE = {n: as_fragment_text(_MODS[n]._PLAN_PROMPT) for n in _STRATEGIES}
_REFLECT_LIVE = {n: as_fragment_text(_MODS[n]._REFLECT_PROMPT) for n in _STRATEGIES}
_ANALYZE_LIVE = {
    "http": as_fragment_text(HTTP_ANALYZE),
    "ws": as_fragment_text(WS_ANALYZE),
    "jsonrpc": as_fragment_text(RPC_ANALYZE),
}


def _render_collapsed(fragment_id: str, domain: dict[str, str]) -> str:
    """The USER turn of the collapsed template filled with one key's slots.

    Builds the SAME spec `render_prove_prompt` builds at runtime — one
    `user_fragments` entry, the slot table as `variables` — minus the per-call
    runtime fills, so `{title}` and friends stay literal, matching the live
    constant before `str.format`. TRANSCRIBE: the profile moves no byte.
    """
    spec = PromptSpec(
        id=f"collapse_{fragment_id.replace('/', '_')}",
        tier="prove",
        fragments=(),
        user_fragments=(fragment_id,),
        variables=domain,
    )
    return render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE).user


# ── the collapse itself: one template file per family ─────────────────────────

def test_exactly_one_template_fragment_per_family():
    """The five/five/three copies are gone; each family resolves ONE fragment.

    The registry holds a single `prove/plan`, `prove/reflect`, `prove/analyze` —
    the structural half of "collapsed": one skeleton to vary.
    """
    for fid in ("prove/plan", "prove/reflect", "prove/analyze"):
        registry.get(fid)  # raises if absent


def test_plan_template_exposes_its_four_slots():
    """`prove/plan` carries the four varying spans as `{…}` placeholders.

    Three were named in the plan (`persona`, `domain_rules`, `evidence_block`);
    the fourth, `body_example`, is required for byte parity because the JSON
    `body` exemplar also varies (cwe alone: "payload if POST") and sits outside
    all three named spans. A slot the template does not contain could never
    carry that strategy's text, so this guards the decomposition itself.
    """
    text = registry.get("prove/plan").text
    for slot in ("{persona}", "{domain_rules}", "{evidence_block}", "{body_example}"):
        assert slot in text, slot
    assert "{protocol}" not in text  # that slot belongs to analyze, not plan


def test_reflect_template_exposes_its_two_slots():
    text = registry.get("prove/reflect").text
    for slot in ("{persona}", "{domain_rules}"):
        assert slot in text, slot


def test_analyze_template_exposes_its_two_slots():
    text = registry.get("prove/analyze").text
    for slot in ("{protocol}", "{request_block}"):
        assert slot in text, slot


# ── HEADLINE: collapsed render == the shipped constant, byte for byte ─────────

def test_plan_collapse_matches_every_live_constant():
    # Anti-vacuous guard: cwe's live constant is the real, populated prompt.
    assert _PLAN_LIVE["cwe"].startswith(
        "You are a vulnerability researcher. Given this CWE finding,"
    )
    assert _PLAN_LIVE["cwe"].endswith('"expected_indicators":["indicator"]}')

    for name in _STRATEGIES:
        rendered = _render_collapsed("prove/plan", PROVE_PLAN_DOMAIN[name])
        assert rendered == _PLAN_LIVE[name], name


def test_reflect_collapse_matches_every_live_constant():
    assert _REFLECT_LIVE["cwe"].startswith(
        "You are a vulnerability researcher reflecting on failed"
    )
    for name in _STRATEGIES:
        rendered = _render_collapsed("prove/reflect", PROVE_REFLECT_DOMAIN[name])
        assert rendered == _REFLECT_LIVE[name], name


def test_analyze_collapse_matches_every_live_constant():
    assert _ANALYZE_LIVE["http"].startswith(
        "Did this HTTP response confirm the vulnerability?"
    )
    for proto in _PROTOCOLS:
        rendered = _render_collapsed("prove/analyze", PROVE_ANALYZE_DOMAIN[proto])
        assert rendered == _ANALYZE_LIVE[proto], proto


# ── the variation is confined to the slots ───────────────────────────────────

def test_only_the_slots_vary_across_the_plan_family():
    """Render every strategy with ONE fixed slot table; all outputs are equal.

    If any cross-strategy difference lived OUTSIDE the four slots — in the
    shared skeleton — feeding identical slot values would still produce
    different prompts. It does not: the skeleton is genuinely shared, and the
    only thing that moves the bytes is the slot table.
    """
    fixed = {"persona": "P", "domain_rules": "DR",
             "evidence_block": "EV\n", "body_example": "BODY"}
    rendered = {
        name: _render_collapsed("prove/plan", {**PROVE_PLAN_DOMAIN[name], **fixed})
        for name in _STRATEGIES
    }
    assert len(set(rendered.values())) == 1, rendered

    # And with each strategy's REAL domain_rules restored (persona/evidence/body
    # still fixed), the outputs differ pairwise — proving the slot is load-
    # bearing rather than ignored.
    varied = {
        name: _render_collapsed(
            "prove/plan",
            {**fixed, "domain_rules": PROVE_PLAN_DOMAIN[name]["domain_rules"]},
        )
        for name in _STRATEGIES
    }
    assert len(set(varied.values())) == len(_STRATEGIES), varied


# ── runtime fill: render_prove_prompt(real) == the old `_PROMPT.format(real)` ─
#
# The checks above leave `{title}` & co. as literal placeholders, matching the
# constant before `str.format`. They therefore CANNOT see a defect in how the
# runtime fills those placeholders — and there is a real trap here: `render._fill`
# substitutes in one pass and never rescans a value, so a `{code_snippet}` living
# INSIDE the cwe/owasp `evidence_block` slot value would survive verbatim unless
# `render_prove_prompt` resolves the domain table against the runtime first.
# These tests drive the actual runtime helper with REAL values and pin it to the
# bytes `_PLAN_PROMPT.format(...)` produced, the one the agent shipped.

_PLAN_RT = dict(
    title="SQL injection", category="CWE-89", description="user input in query",
    file_path="app/db.py", line_start=42, code_snippet="cur.execute(q)",
    verification_hints="try a quote", staging_url="http://staging",
    iteration=2, site_context="/api/users", prior_context="none",
)
_REFLECT_RT = dict(
    title="T", category="C", description="D", attempt_history="A1: GET /x -> 200",
)


def test_runtime_fill_matches_live_format_for_every_plan_strategy():
    # Item 4.5 added the Code/Hints evidence block to soc2/ssdf/chaos too, so
    # ALL five strategies now carry runtime code placeholders and are driven with
    # the full `_PLAN_RT`. BEFORE 4.5 only cwe/owasp used `_PLAN_RT`; soc2/ssdf/
    # chaos had no evidence block and used `_PLAN_RT_NO_EVIDENCE` (that variant is
    # gone).
    for name in _STRATEGIES:
        got = render_prove_prompt("prove/plan", PROVE_PLAN_DOMAIN[name], **_PLAN_RT)
        assert got == _MODS[name]._PLAN_PROMPT.format(**_PLAN_RT), name
        assert "cur.execute(q)" in got  # the evidence really was filled, not left {…}


def test_runtime_fill_matches_live_format_for_every_reflect_strategy():
    for name in _STRATEGIES:
        got = render_prove_prompt("prove/reflect", PROVE_REFLECT_DOMAIN[name], **_REFLECT_RT)
        assert got == _MODS[name]._REFLECT_PROMPT.format(**_REFLECT_RT), name


def test_runtime_fill_preserves_single_pass_when_a_value_holds_a_placeholder():
    """A runtime value carrying another key's placeholder must NOT be expanded.

    This is `_fill`'s value-is-not-template guarantee, seen end to end: the
    resolved domain table (a trusted library constant) is the only thing that
    may act as a template, and it is resolved exactly once. A code_snippet of
    `X{staging_url}Y` must reach the model as `X{staging_url}Y`, identically to
    what `str.format` did — never with the staging URL spliced in.
    """
    adversarial = {**_PLAN_RT, "code_snippet": "X{staging_url}Y{title}Z"}
    got = render_prove_prompt("prove/plan", PROVE_PLAN_DOMAIN["cwe"], **adversarial)
    assert got == cwe._PLAN_PROMPT.format(**adversarial)
    assert "Code: X{staging_url}Y{title}Z" in got
