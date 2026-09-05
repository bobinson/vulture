"""Feature 0089 Phase 2.1 — the DISCOVER call site on the prompt library.

Two halves, both new behaviour with no prior coverage:

1. The prompt is assembled by `render(DISCOVER_SUGGEST, ...)`, not by an inline
   `str.format`. Byte parity with the old builder is pinned in the shared
   suite (`tests/unit/prompt/test_0089_manifest_discover.py` compares the
   fragment to `_LLM_DISCOVER_PROMPT` read out of production by AST). The flip
   was byte-neutral, which is the point and also the difficulty: no comparison
   of prompt bytes can tell a call site that reads the library from one that
   kept a local copy. `test_call_site_reads_the_fragment` is the single
   assertion in this file that can, and it was verified by reverting the
   prompt build to the inline literal — 12 of these 13 tests stayed green.

2. The response is read by `shared.prompt.extract.extract_object`, not by a
   bare `json.loads`. That is the reason the flip is worth doing: `json.loads`
   needs the response to BE the object and nothing else, so a fenced block or
   a reasoning model's `<think>` preamble lost the entire suggestion round —
   and `response_format` is withheld from exactly the custom endpoints
   (LM Studio, vLLM) whose local models fence and think.
"""

from __future__ import annotations

import asyncio
import dataclasses
import types

import litellm
import pytest
from discover_agent.plugins.llm_suggest import (
    LLMEndpointPlugin,
    _prompt_variables,
)
from shared.discovery.plugin_base import DiscoveryContext
from shared.discovery.sitemap import SiteMap
from shared.prompt import Mode, profile_for, registry, render
from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST

_OBJECT = '{"endpoints": ["/api/token", "/api/admin/users"], "reasoning": "next"}'
_SUGGESTED = ["/api/token", "/api/admin/users"]


def _site() -> SiteMap:
    """Built per call so no test can leak state into another through it."""
    return SiteMap(
        urls=["/"],
        forms=[{"method": "POST", "action": "/login", "inputs": ["user"]}],
        api_endpoints=["/api/users"],
        headers={"Server": "nginx/1.25.3"},
        technologies=["Next.js 14"],
    )


def _reply(content: str):
    return types.SimpleNamespace(choices=[types.SimpleNamespace(
        message=types.SimpleNamespace(content=content))])


def _run(monkeypatch, content: str) -> tuple[list[dict], list[str]]:
    """Drive the shipping plugin against `content`; return (messages, endpoints).

    `discover()` swallows every exception, so the captured request is asserted
    non-empty by the caller — a plugin that stopped calling the model would
    otherwise leave these tests passing on nothing.
    """
    seen: list[dict] = []

    async def _capture(**kwargs):
        seen.append(kwargs)
        return _reply(content)

    monkeypatch.setattr(litellm, "acompletion", _capture)
    ctx = DiscoveryContext(staging_url="http://fixture.invalid",
                           http_client=None, site=_site())
    result = asyncio.run(LLMEndpointPlugin().discover(ctx))
    assert len(seen) == 1, f"the plugin did not build one LLM request: {seen!r}"
    return seen[0]["messages"], result.endpoints


def test_wire_bytes_agree_with_the_library(monkeypatch):
    """What goes on the wire is what `render()` produces for the same spec.

    Deliberately NOT claimed here: that the call site consulted the library at
    all. Both sides render from one fragment, and the flip was byte-neutral, so
    an inline literal would satisfy this too — `test_call_site_reads_the_fragment`
    is the assertion that can tell those apart. What this pins is agreement: the
    moment the fragment is edited (the intended editing surface from now on) and
    the plugin does not follow, this goes red.
    """
    messages, _ = _run(monkeypatch, _OBJECT)
    expected = render(
        dataclasses.replace(DISCOVER_SUGGEST, variables=_prompt_variables(_site())),
        profile_for(), mode=Mode.TRANSCRIBE,
    )
    assert messages == expected.messages
    # The plugin has always sent one user turn and no system turn.
    assert [m["role"] for m in messages] == ["user"]
    assert expected.instructions == ""


def test_call_site_reads_the_fragment(monkeypatch):
    """Mutate the FRAGMENT; the prompt on the wire must change with it.

    The one assertion here that a byte-neutral flip cannot fake. A call site
    that kept building its prompt from a local literal passes every other test
    in this file and every parity test in the shared suite — all of them
    compare bytes that agree either way — and fails only this one, because the
    sentinel exists nowhere but in the registry entry `render()` reads.

    Patched through `registry.FRAGMENTS` rather than by writing the `.md` file
    so the mutation is scoped to this test and cannot survive it.
    """
    frag = registry.FRAGMENTS["discover/suggest"]
    marker = "SENTINEL-0089-2-1"
    assert marker not in frag.text
    monkeypatch.setitem(
        registry.FRAGMENTS, "discover/suggest",
        dataclasses.replace(frag, text=frag.text.replace(
            "Return ONLY a JSON object:", f"Return ONLY a JSON object ({marker}):")),
    )
    messages, _ = _run(monkeypatch, _OBJECT)
    assert marker in messages[0]["content"], (
        "the fragment was mutated and the prompt did not change — this call "
        "site is not reading the prompt library"
    )


def test_interpolated_values_reach_the_prompt(monkeypatch):
    """The five blocks are still filled from the discovered site.

    A render that silently dropped `spec.variables` would leave the
    placeholders standing and still be a "library" prompt, so the fixture's
    own strings are looked for and the raw placeholders are asserted gone.
    """
    messages, _ = _run(monkeypatch, _OBJECT)
    body = messages[0]["content"]
    for expected in ("Next.js 14", "  /api/users", "  POST /login inputs=['user']",
                     "  Server: nginx/1.25.3",
                     "  - Next.js (API routes in /api/*, NextAuth.js common)"):
        assert expected in body, f"{expected!r} missing from the prompt"
    for placeholder in ("{technologies}", "{api_endpoints}", "{forms}",
                        "{headers}", "{framework_hints}"):
        assert placeholder not in body, f"{placeholder} was never filled"


@pytest.mark.parametrize("label,content", [
    ("bare object", _OBJECT),
    ("json fence", f"```json\n{_OBJECT}\n```"),
    ("unlabelled fence", f"```\n{_OBJECT}\n```"),
    ("reasoning preamble", f"<think>\nweighing the stack\n</think>\n{_OBJECT}"),
    ("unclosed reasoning", f"<think>\ntruncated mid-thought\n{_OBJECT}"),
    ("prose preamble", f"Here are my suggestions:\n{_OBJECT}"),
    ("prose and fence", f"Sure!\n```json\n{_OBJECT}\n```\nHope that helps."),
])
def test_endpoints_survive_every_wrapping(monkeypatch, label, content):
    """Every one of these except the first was a total loss under `json.loads`.

    Same payload in all seven, so the parameter under test is the WRAPPING and
    nothing else; a regression to a bare reader fails six of the seven.
    """
    _, endpoints = _run(monkeypatch, content)
    assert endpoints == _SUGGESTED, f"{label}: lost the suggestion round"


@pytest.mark.parametrize("content", ["", "I cannot help with that.", "null"])
def test_unreadable_response_degrades_quietly(monkeypatch, content):
    """No object anywhere is an empty result, not an exception.

    `discover()` returning normally is the contract the plugin registry relies
    on; the old reader reached the same outcome by raising into the blanket
    `except`, so this pins the behaviour, not the mechanism.
    """
    _, endpoints = _run(monkeypatch, content)
    assert endpoints == []
