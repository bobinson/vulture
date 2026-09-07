"""Feature 0089 Phase 4.6 — DISCOVER adapts, and its exemplar becomes copyable.

Four changes, one item, and this file is the executable statement of each.

1. THE EXEMPLAR. `discover/suggest` shipped one worked example and it was not
   JSON:

       {"endpoints": ["/api/path1", "/api/path2", ...], "reasoning": "brief explanation"}

   The bare `...` is the defect. A model does what it is shown, and what it was
   shown does not parse — not by `json.loads`, and not by `extract_object`
   either, which Phase 2.1 put in front of the reader precisely to rescue
   fences and `<think>` preambles. It cannot rescue a syntax error, so a model
   that copied the shape lost the WHOLE suggestion round, silently, to the
   plugin's blanket `except`. `test_the_exemplar_survives_the_readers`
   round-trips the exemplar through the production reader rather than asserting
   that a string looks fine.

2. THE SYSTEM ROLE. Everything went in one user turn, because a transcription
   may not move a byte. The standing instructions (persona, focus list, output
   contract, rules) are the same on every call; only the discovered evidence
   varies. So they split: `discover/system` in the system turn,
   `discover/suggest` — the target-derived evidence and the ask — in the user
   turn. `Mode.ADAPT` is what makes the split conditional on the profile: a
   family with no system role (gemma) still receives every instruction, folded
   into the front of its single user turn, which is what
   `test_a_family_without_a_system_role_loses_nothing` pins.

3. ABSTENTION. Nothing in the prompt said an empty list was an answer, while
   ten numbered categories and "Limit to 20" said the opposite. `stance:
   BLESSES_ABSTENTION` is now declared, so `check_03_stance_conflict` will fail
   the day a tool-permitting fragment joins this spec.

4. THE PATH RULE. The rule admitted eight roots. The plugin's own filter admits
   any non-static path (`llm_suggest.py`: `ep.startswith("/") and not
   is_static_path(ep)`), so the prompt was the narrower of the two authorities
   and a real `/oauth/token` or `/.well-known/openid-configuration` was
   instructed away before the filter ever saw it.

WHAT MAKES THESE RED BEFORE THE CHANGE. Every assertion below drives
`render()` over the real manifest and reads the bytes it returns; none compares
a literal to a literal. Verified red as a set on the pre-4.6 tree.
"""

from __future__ import annotations

import json
import re

import pytest

from shared.prompt import Mode, gate, lint, profile_for, render
from shared.prompt.extract import extract_object
from shared.prompt.fragment import Role, Stance
from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST
from shared.prompt.registry import get

# A family WITH a system role and one WITHOUT. `gemma`'s chat template has no
# system turn at all (profile.py), which is the case the split has to survive.
_WITH_SYSTEM = "gpt-4o"
_NO_SYSTEM = "gemma"


def _adapt(model: str):
    return render(DISCOVER_SUGGEST, profile_for(model), mode=Mode.ADAPT)


def _exemplar(text: str) -> str:
    """The one worked example in the prompt, read back out of the prompt.

    Read rather than retyped: an exemplar this test file spelled out itself
    would be a second source of truth for the thing under test, and would stay
    green while the prompt shipped something else.
    """
    matches = re.findall(r'^\{".*\}$', text, re.MULTILINE)
    assert len(matches) == 1, f"expected exactly one JSON exemplar line, got {matches}"
    return matches[0]


# ── 1. the exemplar ───────────────────────────────────────────────────────

def test_the_exemplar_survives_the_readers():
    """A model that copies the shape it was shown must be understood.

    Both readers, because they fail differently: `json.loads` is what the
    plugin used before Phase 2.1 and `extract_object` is what it uses now. The
    old exemplar defeats both — the second one cannot repair a syntax error,
    only a wrapper around valid JSON — so the round trip is the assertion, not
    an eyeball on the string.
    """
    rp = _adapt(_WITH_SYSTEM)
    shown = _exemplar(rp.instructions + "\n" + rp.user)

    parsed = json.loads(shown)
    assert set(parsed) == {"endpoints", "reasoning"}, parsed
    assert isinstance(parsed["endpoints"], list) and parsed["endpoints"]
    assert all(isinstance(p, str) and p.startswith("/") for p in parsed["endpoints"])

    # And through the reader production actually runs, wrapped the way a local
    # model wraps it — the path that must not lose the round.
    assert extract_object(shown) == parsed
    assert extract_object(f"```json\n{shown}\n```") == parsed


def test_the_bare_ellipsis_is_gone_from_the_prompt():
    """Quoting the before, so the repair cannot be undone quietly.

    BEFORE: `{"endpoints": ["/api/path1", "/api/path2", ...], "reasoning": ...}`
    AFTER:  a two-element array of real-looking paths and nothing else.
    """
    rp = _adapt(_WITH_SYSTEM)
    body = rp.instructions + rp.user
    assert "..." not in body
    assert "/api/path1" not in body and "/api/path2" not in body


@pytest.mark.parametrize("check", ["exemplar_validity", "placeholder_echo"])
def test_the_two_exemplar_findings_no_longer_fire(check):
    """promptlint stops reporting them because the text no longer trips them."""
    rp = _adapt(_WITH_SYSTEM)
    assert [f for f in lint(DISCOVER_SUGGEST, rp) if f.check == check] == []


@pytest.mark.parametrize("check", ["exemplar_validity", "placeholder_echo"])
def test_the_two_allow_entries_are_retired(check):
    """A fixed defect must lose its annotation, or the gate starts lying.

    `_allow_stale` already fails an entry matching nothing, so leaving either
    behind is a red build rather than a silent one — this says which entry, and
    that retiring them is the intent rather than an accident.
    """
    keys = {(a.check, a.fragment) for a in DISCOVER_SUGGEST.allow}
    assert not [k for k in keys if k[0] == check], keys


def test_the_gate_is_clean_for_this_spec_on_every_family():
    """No unannotated finding and no stale annotation, family by family."""
    from shared.prompt.lint import family_models

    for family, model in family_models().items():
        report = gate(DISCOVER_SUGGEST, _adapt(model))
        assert report.ok, (family, report.findings, report.errors)


# ── 2. the system role ────────────────────────────────────────────────────

def test_the_instructions_move_to_the_system_turn():
    """Standing instructions in system, target-derived evidence in user."""
    rp = _adapt(_WITH_SYSTEM)
    assert [m["role"] for m in rp.messages] == ["system", "user"]
    assert rp.instructions.startswith("You are a web security expert.")
    assert "Return ONLY a JSON object" in rp.instructions
    assert "Rules:" in rp.instructions
    # The five interpolated blocks are the per-target half and stay in user.
    for placeholder in ("{technologies}", "{api_endpoints}", "{forms}",
                        "{headers}", "{framework_hints}"):
        assert placeholder in rp.user, placeholder
        assert placeholder not in rp.instructions, placeholder


def test_the_manifest_places_both_fragments_and_declares_their_roles():
    """The spec, not the renderer, decides the turn — so the spec is pinned."""
    # `core/language` appended by item 4.8: a second SYSTEM fragment, dropped
    # by rule 9 for every family that does not pin its output language.
    assert DISCOVER_SUGGEST.fragments == ("discover/system", "core/language")
    assert DISCOVER_SUGGEST.user_fragments == ("discover/suggest",)
    assert get("discover/system").role is Role.SYSTEM
    assert get("discover/suggest").role is Role.USER


def test_a_family_without_a_system_role_loses_nothing():
    """gemma has no system turn; every instruction must still arrive.

    Not "roughly the same content" — the exact concatenation, so a rule that
    silently dropped the system half on this family would fail here rather than
    ship a prompt with no output contract.
    """
    paired = _adapt(_WITH_SYSTEM)
    folded = _adapt(_NO_SYSTEM)
    assert [m["role"] for m in folded.messages] == ["user"]
    assert folded.instructions == ""
    assert folded.user == f"{paired.instructions}\n\n{paired.user}"


def test_transcribe_is_no_longer_what_this_spec_ships():
    """The two modes now differ for DISCOVER, which is why the flip is visible.

    Under TRANSCRIBE the renderer never consults `profile.system_role`, so
    gemma would receive a system message its chat template drops. That is the
    concrete thing ADAPT buys here, and it is asserted rather than assumed.
    """
    transcribed = render(DISCOVER_SUGGEST, profile_for(_NO_SYSTEM),
                         mode=Mode.TRANSCRIBE)
    assert [m["role"] for m in transcribed.messages] == ["system", "user"]
    assert transcribed.messages != _adapt(_NO_SYSTEM).messages


# ── 3. abstention ─────────────────────────────────────────────────────────

def test_abstention_is_declared_and_written():
    """The stance is machine-readable AND the sentence is in the prompt.

    Both, because either alone is a lie: a stance with no clause tells the
    linter something the model never sees, and a clause with no stance is
    invisible to `check_03_stance_conflict` the day tools are attached here.
    """
    frags = [get(i) for i in DISCOVER_SUGGEST.fragments + DISCOVER_SUGGEST.user_fragments]
    assert any(Stance.BLESSES_ABSTENTION in f.stance for f in frags)

    rp = _adapt(_WITH_SYSTEM)
    body = rp.instructions + rp.user
    assert "empty" in body.lower(), "no clause offers the empty answer"


def test_abstention_does_not_collide_with_a_tool_stance():
    """The measured defect this stance system exists for, checked here too."""
    rp = _adapt(_WITH_SYSTEM)
    assert [f for f in lint(DISCOVER_SUGGEST, rp) if f.check == "stance_conflict"] == []


# ── 4. the path rule ──────────────────────────────────────────────────────

# Roots a real target serves an API from that the transcribed rule excluded.
_WIDENED = ("/oauth/", "/.well-known/", "/actuator/", "/socket.io/", "/wp-json/")

_OLD_RULE = ("- Only suggest paths starting with /api/, /v1/, /v2/, /graphql, "
             "/rest/, /rpc/, /ws/, /auth/")


@pytest.mark.parametrize("root", _WIDENED)
def test_the_path_rule_admits_the_roots_it_used_to_forbid(root):
    """The prompt was narrower than the filter that consumes its output."""
    assert root in _adapt(_WITH_SYSTEM).instructions


def test_the_narrow_rule_is_gone():
    """Quoting the before, byte for byte."""
    rp = _adapt(_WITH_SYSTEM)
    assert _OLD_RULE not in rp.instructions + rp.user


def test_the_old_roots_are_all_still_admitted():
    """Widening may not narrow: every root the old rule named is still named."""
    instructions = _adapt(_WITH_SYSTEM).instructions
    for root in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/rpc/",
                 "/ws/", "/auth/"):
        assert root in instructions, root
