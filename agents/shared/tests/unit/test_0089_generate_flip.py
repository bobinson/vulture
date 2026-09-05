"""Feature 0089 Phase 2.5 — the seven GENERATE call sites on the prompt library.

The flip: each scan agent's ``INSTRUCTIONS`` stopped being the source of its
system prompt. ``domains/<agent>`` is authoritative, the agent names that
fragment id at its own ``run_combined_audit`` call, and
``shared.prompt.manifests.generate.domain_instructions`` renders it.

WHY THIS FILE EXISTS. The flip is byte-neutral — measured, and that is the
point of a TRANSCRIBE-mode migration — so no comparison of prompt BYTES can
tell a call site that reads the library from one that kept a local copy. Every
parity test in ``tests/unit/prompt`` compares bytes that agree either way:
``test_0089_parity_generate.py`` rebuilds the live prompt from each agent's
``INSTRUCTIONS`` literal by AST, and ``test_0089_manifest_generate.py`` asserts
the fragment EQUALS that literal. Both stay green against a reverted call site.
``test_call_site_reads_the_fragment`` below is the assertion that cannot: it
mutates the registry entry and requires the agent's prompt to move with it.

The second contract is the one the task brief names as the hazard: the identity
must be rendered ONCE. A fragment list resolved by the runner ALONGSIDE a
still-populated ``instructions=`` would emit it twice, and a doubled system
prompt is invisible to every byte comparison in this feature (both halves are
correct bytes). ``test_identity_appears_exactly_once`` counts it.

HERMETIC. ``build_prior_context`` is stubbed, so no agent reaches the memory
API; ``run_combined_audit`` is stubbed at each agent's own module namespace, so
no audit, no scan and no model call happens. The agents are imported the way
``test_0079_shared_audit_kwargs.py`` imports them — by path insertion, mirroring
production's ``PYTHONPATH=shared:<agent>``.
"""

from __future__ import annotations

import dataclasses
import importlib
import pathlib
import sys

import pytest

from shared import audit_runner
from shared.prompt import registry
from shared.prompt.manifests.generate import GENERATE_SPECS, domain_instructions

AGENTS_ROOT = pathlib.Path(__file__).resolve().parents[3]

# agent name (as `domains/<name>` spells it) -> its package directory name.
# Only `chaos` differs from its directory, which is why this is a mapping and
# not a derivation. Asserted against `GENERATE_SPECS` below so neither side can
# gain an agent alone.
AGENT_PACKAGES: dict[str, str] = {
    "asvs": "asvs/asvs_agent",
    "chaos": "chaos_engineering/chaos_agent",
    "cwe": "cwe/cwe_agent",
    "do178c": "do178c/do178c_agent",
    "soc2": "soc2/soc2_agent",
    "ssdf": "ssdf/ssdf_agent",
    "xss": "xss/xss_agent",
}
AGENTS = tuple(sorted(AGENT_PACKAGES))

# The two agents that append a per-run catalog block to their identity. Listed
# so the composition is asserted rather than assumed: for these two the
# identity is a PREFIX of the system turn, for the other five it is the whole
# of it, and a flip that dropped the block would pass a bare `in` test.
WITH_CATALOG = frozenset({"asvs", "cwe"})

SENTINEL = "SENTINEL-0089-2-5"


def _agent_module(agent: str):
    """Import `<pkg>.agent`, mirroring production's sys.path layout."""
    pkg = AGENTS_ROOT / AGENT_PACKAGES[agent]
    root = str(pkg.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        return importlib.import_module(f"{pkg.name}.agent")
    except Exception as exc:
        pytest.skip(f"{agent} is not importable in this environment: {exc}")


def _captured_instructions(agent: str, monkeypatch, tmp_path) -> str:
    """Drive the agent's real `run_audit` and return the `instructions=` it sends.

    `run_combined_audit` is replaced in the AGENT's namespace, so the call site
    under test is the shipping one — the arguments are bound by the agent's own
    code, not reconstructed here.
    """
    mod = _agent_module(agent)
    seen: dict = {}

    def _capture(**kwargs):
        seen.update(kwargs)
        return iter(())

    monkeypatch.setattr(mod, "run_combined_audit", _capture)
    monkeypatch.setattr(
        "shared.audit_kwargs.build_prior_context",
        lambda *a, **k: "",
    )
    (tmp_path / "a.py").write_text("x = 1\n")

    list(mod.run_audit("flip-probe", str(tmp_path), {}, None))
    assert "instructions" in seen, (
        f"{agent}: run_audit did not reach run_combined_audit, so this test "
        f"asserted nothing; captured kwargs: {sorted(seen)}"
    )
    return seen["instructions"]


# ── contract 1: the call site reads the library ───────────────────────────


@pytest.mark.parametrize("agent", AGENTS)
def test_call_site_reads_the_fragment(agent: str, monkeypatch, tmp_path):
    """Mutate the FRAGMENT; the agent's prompt must change with it.

    The one assertion here that a byte-neutral flip cannot fake. A call site
    that kept building its prompt from its own `INSTRUCTIONS` constant passes
    every parity and golden test in this feature — all of them compare bytes
    that agree either way — and fails only this, because the sentinel exists
    nowhere but in the registry entry `domain_instructions()` reads.

    Patched through `registry.FRAGMENTS` rather than by writing the `.md` file,
    so the mutation is scoped to this test and cannot survive it.
    """
    fid = f"domains/{agent}"
    frag = registry.FRAGMENTS[fid]
    assert SENTINEL not in frag.text
    monkeypatch.setitem(
        registry.FRAGMENTS, fid,
        dataclasses.replace(frag, text=frag.text + f"\n{SENTINEL}"),
    )
    assert SENTINEL in _captured_instructions(agent, monkeypatch, tmp_path), (
        f"{agent}: the fragment was mutated and the prompt did not change — "
        f"this call site is not reading the prompt library"
    )


@pytest.mark.parametrize("agent", AGENTS)
def test_call_site_sends_the_rendered_fragment(agent: str, monkeypatch, tmp_path):
    """What the agent sends is what the library renders for its fragment.

    Byte-exact, and on the whole role string for the five agents with nothing
    to append. Not sufficient on its own (an unflipped call site satisfies it —
    that is what the test above is for); what it pins is that the fragment is
    the intended editing surface from now on.
    """
    sent = _captured_instructions(agent, monkeypatch, tmp_path)
    identity = domain_instructions(f"domains/{agent}")
    if agent in WITH_CATALOG:
        assert sent.startswith(identity), f"{agent}: identity is not the head"
        assert len(sent) > len(identity), (
            f"{agent} appends a per-run catalog block; it is missing"
        )
    else:
        assert sent == identity


# The four shapes `_generate_system_prompt` composes, as (source_in_system,
# fenced). Both booleans are per-run facts the agent does not control — the
# model family and whether the API can enforce a JSON shape — so a double
# render that only appeared on one branch would still reach production.
_SYSTEM_TURN_BRANCHES = (
    (False, False), (False, True), (True, False), (True, True),
)


@pytest.mark.parametrize("agent", AGENTS)
def test_identity_appears_exactly_once(agent: str, monkeypatch, tmp_path):
    """THE HAZARD. A doubled identity is correct bytes twice over.

    Resolving `domains/<agent>` inside the runner while `instructions=` still
    carries it would put the identity in the system turn twice, and nothing
    else in this feature could see that: every parity and golden assertion
    compares against a single rendered copy, and BOTH halves of a doubled turn
    are byte-correct. Counted, not eyeballed.

    Counted in the COMPOSED turn, not in the kwarg, because that is where the
    two channels would meet: `_generate_system_prompt` is what joins the
    agent's rendered head to `live_spec`'s suffix, so a domain fragment added
    to that spec is caught here and would not be caught at the call-site
    boundary. All four of its branches, since none is the agent's to choose.
    """
    sent = _captured_instructions(agent, monkeypatch, tmp_path)
    identity = domain_instructions(f"domains/{agent}")
    assert sent.count(identity) == 1, (
        f"{agent}: the identity appears {sent.count(identity)} times in the "
        f"`instructions=` the call site sends"
    )
    for source_in_system, fenced in _SYSTEM_TURN_BRANCHES:
        turn = audit_runner._generate_system_prompt(
            sent, "SRCBODY", frozenset({"ALPHA", "BETA"}),
            source_in_system=source_in_system, fenced=fenced,
        )
        assert turn.count(identity) == 1, (
            f"{agent}: the identity appears {turn.count(identity)} times in "
            f"the composed system turn (source_in_system={source_in_system}, "
            f"fenced={fenced}); {len(turn.encode())}B for a "
            f"{len(identity.encode())}B identity"
        )


# ── contract 2: the sweep is not vacuous ──────────────────────────────────


def test_the_flip_covers_every_generate_agent():
    """A guard that enumerates nothing passes silently.

    Seven agents have an LLM generate path (`owasp` is a categorizer over CWE
    findings and has none), so the parametrization above must be those seven
    and the same seven the tier's specs describe.
    """
    assert set(AGENTS) == set(GENERATE_SPECS)
    assert len(AGENTS) == 7
    for agent in AGENTS:
        assert (AGENTS_ROOT / AGENT_PACKAGES[agent] / "agent.py").is_file(), agent
        assert f"domains/{agent}" in registry.FRAGMENTS, agent


@pytest.mark.parametrize("agent", AGENTS)
def test_the_call_site_still_names_the_four_greppable_kwargs(agent: str):
    """`skill_map=SKILL_MAP`, `skill_tools`, `domain_label` and `instructions`
    stay AT the call site, in text.

    `shared/audit_kwargs.py`'s docstring makes that the standing contract ("What
    stays at each call site is exactly what the 0070 fleet guard needs to see")
    and `test_0070_fleet_skill_dispatch.py::
    test_the_bound_skill_map_is_the_one_handed_to_the_runner` greps the source
    for the first of them. 2.5 changed what `instructions=` is BUILT from, so
    this pins that it did not change where the kwarg is written.
    """
    src = (AGENTS_ROOT / AGENT_PACKAGES[agent] / "agent.py").read_text(encoding="utf-8")
    for needle in ("skill_map=SKILL_MAP", "skill_tools=", "domain_label=",
                   "instructions=", f'"domains/{agent}"'):
        assert needle in src, f"{agent}: {needle!r} is no longer at the call site"
