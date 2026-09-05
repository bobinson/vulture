"""Feature 0089 Phase 0.c — the DISCOVER tier transcription.

The point of a transcription phase is that it changes NO bytes. So the test
that matters is not "does it render" but "is the rendered text the same string
the shipping call site sends today". The expected value is read out of
`discover_agent/plugins/llm_suggest.py` by AST, never retyped here: a golden
copied by hand is a second source of truth, which is the thing 0089 removes.

WHAT "BYTE FOR BYTE" IS MEASURED AGAINST, and why it is not the raw literal.
`_LLM_DISCOVER_PROMPT` is a `str.format` TEMPLATE, so its JSON example is
written `{{"endpoints": ...}}` — doubled braces that `str.format` collapses.
The bytes the model receives therefore carry SINGLE braces, and the fragment
holds the prompt, not the Python source that encodes it.

Nor could the fragment hold the escapes: the renderer's interpolation is
`render._fill`, a plain `{name}` -> value `.replace`, deliberately NOT
`str.format` (a `str.format`-based fill would raise on any prompt containing a
JSON brace, which is most of them). `{{` has no meaning in that syntax — it is
two literal braces — so an escaped fragment renders `{{` straight to the model
and `render()` can never reproduce the live request. That is exactly what
`test_0089_parity_discover*.py` measured: rendered 1411 chars against the live
plugin's 1409.

So the expectation here is the live literal with each placeholder mapped to
ITSELF (`_expected_fragment_text`): `str.format` resolves the escapes and
leaves `{technologies}` & co. standing. Still one source of truth, still
production's own bytes, and still byte equality — a reworded prompt, a changed
example or a tidied `...` all fail. The `...` (an invalid-JSON example, and the
audit record Phase 4.6 owns) is untouched by this and still linted below.
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


# The five keys `llm_suggest.discover()` passes to `.format` (llm_suggest.py:
# 85-104). Hardcoded so that a key added to the live call site — a sixth
# interpolated block, i.e. new prompt bytes — raises KeyError here instead of
# being quietly absent from the expectation.
_LIVE_FORMAT_KEYS = (
    "technologies", "api_endpoints", "forms", "headers", "framework_hints",
)


def _expected_fragment_text() -> str:
    """The live template as the renderer's placeholder syntax spells it.

    `str.format` with every placeholder bound to its own `{name}` resolves the
    `{{`/`}}` escapes and nothing else, so this is `_LLM_DISCOVER_PROMPT` with
    the `str.format` encoding removed and the template still a template.
    Derived from production; retypes none of it.
    """
    template = _source_constant(_SRC, "_LLM_DISCOVER_PROMPT")
    return template.format(**{k: "{" + k + "}" for k in _LIVE_FORMAT_KEYS})


def test_discover_fragment_is_byte_exact():
    """The fragment text IS `_LLM_DISCOVER_PROMPT`, byte for byte.

    Byte for byte against the template as SENT — `str.format`'s `{{`/`}}`
    encoding resolved (see the module docstring), the placeholders left
    standing, and the invalid `...` example untouched: a transcription that
    tidies the example is no longer a transcription, and Phase 4.6 loses the
    before/after it needs to prove a fix helped.
    """
    frag = get("discover/suggest")
    assert frag.text == _expected_fragment_text()
    # The escapes belong to `str.format`, not to the prompt: they must not
    # survive into the fragment, or `render()` sends `{{` to the model.
    assert "{{" not in frag.text and "}}" not in frag.text
    # Sent as a lone user message with no system role (llm_suggest.py:110-121).
    assert frag.role is Role.USER


def test_manifest_discover_renders():
    """TRANSCRIBE puts the whole prompt in the user turn and nothing in system."""
    rp = render(DISCOVER_SUGGEST, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    expected = _expected_fragment_text()
    assert rp.instructions == ""
    assert rp.user == expected
    assert [m["role"] for m in rp.messages] == ["user"]
    assert rp.messages[0]["content"] == expected
    assert rp.response_format is None
    assert DISCOVER_SUGGEST.schema_fields == ("endpoints", "reasoning")
    assert DISCOVER_SUGGEST.fragments == ()


def test_discover_template_variables_are_unresolved():
    """The call site's `str.format` keys survive as placeholders.

    TRANSCRIBE with no `variables` substitutes nothing, which is what makes the
    golden a template rather than one captured request's contents.
    """
    assert get("discover/suggest").variables() == frozenset({
        "technologies", "api_endpoints", "forms", "headers", "framework_hints",
    })


def test_lint_catches_discover_invalid_exemplar():
    """The one example in the prompt is not parseable JSON.

    `{"endpoints": ["/api/path1", "/api/path2", ...], ...}` — a bare `...`
    inside the array. A model that copies the shape it was shown emits
    something `json.loads` rejects, and the whole suggestion round is lost.
    This is an audit blocker recorded by the transcription, not fixed by it.
    """
    rp = render(DISCOVER_SUGGEST, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    findings = lint(DISCOVER_SUGGEST, rp)
    exemplar = [f for f in findings if f.check == "exemplar_validity"]
    assert exemplar, f"expected an exemplar_validity finding, got {findings}"
    assert all(f.fragment == "discover/suggest" for f in exemplar)
    assert any("endpoints" in f.message for f in exemplar)


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
