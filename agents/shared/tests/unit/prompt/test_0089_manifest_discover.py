"""Feature 0089 Phase 0.c — the DISCOVER tier, pinned against production.

The point of a transcription phase was that it changed NO bytes, so the test
that mattered was not "does it render" but "is the rendered text the same
string the shipping call site sends". The expected values are read out of
`discover_agent/plugins/llm_suggest.py` by AST, never retyped here: a golden
copied by hand is a second source of truth, which is the thing 0089 removes.

PHASE 4.6 CHANGED THE BYTES, and three of the assertions below with them. It is
the item that was allowed to: it split the single user turn into
`discover/system` (persona, focus list, output contract, rules) and
`discover/suggest` (the discovered evidence and the ask), replaced an invalid
JSON exemplar, added an abstention clause and widened the path rule. What did
NOT change is the arrangement this file defends: production still carries a
literal copy of each fragment, and each is still compared byte for byte.

Before 4.6 there was one literal, `_LLM_DISCOVER_PROMPT`, and it was a
`str.format` TEMPLATE — its JSON example was written `{{"endpoints": ...}}`,
doubled braces that `str.format` collapses. The expectation therefore had to be
the literal with each placeholder mapped to ITSELF, so that `.format` resolved
the escapes and left `{technologies}` & co. standing. Nothing calls `.format`
on the literals any more (`render._fill` does the substitution, and it is a
one-pass `{name}` -> value substitution for which `{{` is simply two literal
braces), so the literals now carry SINGLE braces, in the same syntax the
fragments use, and the comparison is direct.

That cost one guard, which is restored explicitly rather than dropped: the old
`.format` call raised KeyError if the call site grew a sixth interpolated
block. `test_the_five_interpolated_blocks_are_the_call_sites_own` reads the
keys `_prompt_variables` returns, by AST, and compares them to the placeholders
the fragments declare.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from shared.prompt import Mode, lint, profile_for, render
from shared.prompt.fragment import Role, Stance
from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST
from shared.prompt.registry import get

_AGENTS = Path(__file__).resolve().parents[4]
_SRC = _AGENTS / "discover" / "discover_agent" / "plugins" / "llm_suggest.py"


def _source_constant(path: Path, name: str) -> str:
    """The literal value of a module-level string constant, without importing.

    The plugin module imports the live discover agent package, which is not on
    this test suite's path; AST reads the same bytes with no import graph.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path}")


def _source_dict_keys(path: Path, func: str) -> tuple[str, ...]:
    """The string keys of the dict literal a function returns, by AST."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != func:
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict):
                return tuple(ast.literal_eval(k) for k in sub.value.keys)
    raise AssertionError(f"{func} has no dict return in {path}")


# The five interpolated blocks `llm_suggest._prompt_variables()` builds.
# Hardcoded so that a key added to the live call site — a sixth block, i.e. new
# prompt bytes — is a failure here instead of being quietly absent.
_LIVE_FORMAT_KEYS = (
    "technologies", "api_endpoints", "forms", "headers", "framework_hints",
)

# fragment id -> the production literal that must equal it, byte for byte.
# Two since Phase 4.6 split the turn; see the module docstring.
_FRAGMENT_LITERALS = {
    "discover/system": "_LLM_DISCOVER_SYSTEM",
    "discover/suggest": "_LLM_DISCOVER_USER",
}


@pytest.mark.parametrize("fragment_id", sorted(_FRAGMENT_LITERALS))
def test_discover_fragment_is_byte_exact(fragment_id):
    """Each fragment IS its production literal, byte for byte.

    Not "contains" and not "normalised": a reworded prompt, a changed example
    or a moved rule all fail. The literals hold the renderer's placeholder
    syntax directly (nothing calls `.format` on them), so `{{`/`}}` must not
    appear on either side — a doubled brace would ship two literal braces to
    the model inside the JSON exemplar, the one place the output contract has
    to be exact.
    """
    frag = get(fragment_id)
    assert frag.text == _source_constant(_SRC, _FRAGMENT_LITERALS[fragment_id])
    assert "{{" not in frag.text and "}}" not in frag.text


def test_discover_declares_a_system_turn_and_a_user_turn():
    """The split Phase 4.6 made, pinned on both halves.

    BEFORE 4.6: `fragments=()`, one USER fragment, and the plugin sent
    `messages=[{"role": "user", ...}]` with no system message at all.
    AFTER: the standing instructions are a SYSTEM fragment and only the
    per-target evidence stays in the user turn.

    Item 4.8 appended a second SYSTEM fragment, `core/language`. The split this
    test is about is unchanged — the standing instructions are still the system
    turn and the per-target evidence still the user turn — so the tuple grows
    rather than the claim changing.
    """
    assert get("discover/system").role is Role.SYSTEM
    assert get("discover/suggest").role is Role.USER
    assert get("core/language").role is Role.SYSTEM
    assert DISCOVER_SUGGEST.fragments == ("discover/system", "core/language")
    assert DISCOVER_SUGGEST.user_fragments == ("discover/suggest",)


def test_the_five_interpolated_blocks_are_the_call_sites_own():
    """The fragments interpolate exactly what the call site fills, no more.

    Restores the guard the old `.format`-based expectation gave for free: a
    sixth block added to `_prompt_variables` (new prompt bytes) or a
    placeholder added to a fragment that nothing fills (a `{name}` shipped
    verbatim to the model) both fail here.
    """
    assert _source_dict_keys(_SRC, "_prompt_variables") == _LIVE_FORMAT_KEYS
    declared = set(get("discover/system").variables()) | set(
        get("discover/suggest").variables())
    assert declared == set(_LIVE_FORMAT_KEYS)


def test_manifest_discover_renders():
    """The instructions land in the system turn, the evidence in the user turn.

    BEFORE 4.6 this read `rp.instructions == ""` and `[m["role"] ...] ==
    ["user"]`, because the transcription had no system fragment to place.

    `Mode.ADAPT` AS OF ITEM 4.8, and the mode is now load-bearing rather than
    incidental. The call site has rendered ADAPT since 4.6
    (`llm_suggest._suggest_messages`), and until 4.8 the two modes emitted the
    same bytes on this profile, so rendering TRANSCRIBE here compared
    production's oracle against a render production does not perform and got
    away with it. 4.8 lists `core/language`, which rule 9 drops for `gpt-4o`
    and TRANSCRIBE keeps — so the TRANSCRIBE render is now 476 bytes the
    plugin never sends, and the comparison against `_LLM_DISCOVER_SYSTEM`
    (which the plugin retains as its byte oracle) has to be against the mode
    the plugin uses. The language pin's own placement is asserted in
    `test_0089_4_8_language_pin.py`, on a profile that receives it.
    """
    rp = render(DISCOVER_SUGGEST, profile_for("gpt-4o"), mode=Mode.ADAPT)
    assert rp.instructions == _source_constant(_SRC, "_LLM_DISCOVER_SYSTEM")
    assert rp.user == _source_constant(_SRC, "_LLM_DISCOVER_USER")
    assert [m["role"] for m in rp.messages] == ["system", "user"]
    assert [m["content"] for m in rp.messages] == [rp.instructions, rp.user]
    # ADAPT arms `response_format` where the profile can enforce a shape, and
    # `gpt-4o` can. It was `is None` while this test rendered TRANSCRIBE. The
    # plugin takes `.messages` only and derives its own `response_format` from
    # `uses_custom_endpoint()`, a transport fact no profile carries — so this
    # asserts what the renderer emits, and `test_0089_4_6_discover_adapt.py`
    # is where the call site's discarding of it is pinned.
    assert rp.response_format == {"type": "json_object"}
    assert DISCOVER_SUGGEST.schema_fields == ("endpoints", "reasoning")


def test_discover_template_variables_are_unresolved():
    """The call site's `str.format` keys survive as placeholders.

    TRANSCRIBE with no `variables` substitutes nothing, which is what makes the
    golden a template rather than one captured request's contents.
    """
    assert get("discover/suggest").variables() == frozenset({
        "technologies", "api_endpoints", "forms", "headers", "framework_hints",
    })


def test_the_invalid_exemplar_audit_record_is_closed():
    """INVERTED BY PHASE 4.6. The example in the prompt now parses.

    BEFORE, and what this test asserted: `{"endpoints": ["/api/path1",
    "/api/path2", ...], "reasoning": "brief explanation"}` — a bare `...`
    inside the array, so `check_08_exemplar_validity` fired and the assertion
    was `assert exemplar, ...`. A model that copied the shape it was shown
    emitted something no reader could parse and the whole suggestion round was
    lost.

    AFTER: `{"endpoints": ["/api/users", "/api/auth/login"], "reasoning":
    "brief explanation"}`. The finding is gone, and so are the two allow
    entries that annotated it — `exemplar_validity` and the `placeholder_echo`
    the same `...` raised. The round trip through the production reader is
    `test_0089_4_6_discover_adapt.py`; what is asserted here is the manifest's
    own audit record, which is this file's subject.
    """
    rp = render(DISCOVER_SUGGEST, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    fired = {f.check for f in lint(DISCOVER_SUGGEST, rp)}
    assert "exemplar_validity" not in fired and "placeholder_echo" not in fired
    annotated = {a.check for a in DISCOVER_SUGGEST.allow}
    # Was `{"language_pin"}` until item 4.8 listed `core/language` here. This
    # manifest now carries no exemption at all, which is the strongest form of
    # the claim this test makes: the audit record is closed, not annotated.
    assert annotated == set(), annotated


@pytest.mark.parametrize("check", ["orphan_field", "duplicate_contract",
                                   "stance_conflict", "tool_announcement"])
def test_discover_manifest_is_otherwise_closed(check):
    """Every field the prompt asks for is in the schema, and no tools are
    attached — so the only findings left are the ones about the TEXT."""
    rp = render(DISCOVER_SUGGEST, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    assert [f for f in lint(DISCOVER_SUGGEST, rp) if f.check == check] == []


def test_discover_interpolates_target_bytes_with_no_untrusted_marker():
    """AUDIT RECORD: target-controlled bytes reach this prompt unmarked.

    `{headers}`, `{forms}` and `{technologies}` are filled from the SCANNED
    SITE — response headers, form actions and inputs parsed out of the
    target's HTML (`llm_suggest.py:84-104`). They are spliced into the prompt
    with no delimiter, no nonce and no MARKS_UNTRUSTED fragment, so a target
    that serves a crafted header is writing instructions into a prompt whose
    output is fed back into discovery.

    promptlint cannot see this: `check_05_slot_marking` only fires when the
    spec declares `slots`, and a transcription must declare none, because a
    wrapped slot changes the rendered bytes. So the gap is pinned here
    instead. Phase 2 makes these real slots and this test then asserts the
    opposite — deliberately, in a commit that changes the bytes.
    """
    frag = get("discover/suggest")
    target_controlled = {"technologies", "forms", "headers"}
    assert target_controlled <= frag.variables()
    rp = render(DISCOVER_SUGGEST, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    assert DISCOVER_SUGGEST.slots == ()
    assert Stance.MARKS_UNTRUSTED not in frag.stance
    assert [f for f in lint(DISCOVER_SUGGEST, rp) if f.check == "slot_marking"] == []
