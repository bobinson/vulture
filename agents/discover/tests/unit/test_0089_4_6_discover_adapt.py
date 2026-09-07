"""Feature 0089 Phase 4.6 — the DISCOVER call site, end to end.

`agents/shared/tests/unit/prompt/test_0089_4_6_discover_adapt.py` pins what
`render()` produces. This file pins what the PLUGIN does with it, which is a
different question and the one the item is actually about:

* the request now carries a system turn where the model has one, and the
  evidence stays in the user turn;
* a model that answers with exactly the example it was shown is understood.

The second is the whole point of fixing the exemplar and it is only decidable
here, because the reader (`extract_object`) and the post-filter
(`is_static_path`, the already-known-endpoint check) live in
`LLMEndpointPlugin.discover()`, not in the prompt library. Before 4.6 the
exemplar was `{"endpoints": ["/api/path1", "/api/path2", ...], ...}`, a bare
`...` inside the array; feeding it back returns ZERO endpoints, and `discover()`
swallows the parse failure, so the round is lost with nothing in the result to
say so.

No network, no key: `litellm.acompletion` is replaced by a capturing stub, as
in the sibling Phase 2.1 file.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import types

import litellm

from discover_agent.plugins.llm_suggest import (
    LLMEndpointPlugin,
    _prompt_variables,
)
from shared.discovery.plugin_base import DiscoveryContext
from shared.discovery.sitemap import SiteMap
from shared.prompt import Mode, profile_for, render
from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST


def _site() -> SiteMap:
    """Built per call so no test can leak state into another through it.

    Deliberately does NOT already know the endpoints the shipped exemplar
    names: `discover()` drops a suggestion the site has already found, so a
    fixture that listed them would make the exemplar round trip look like a
    loss.
    """
    return SiteMap(
        urls=["/"],
        forms=[{"method": "POST", "action": "/login", "inputs": ["user"]}],
        api_endpoints=["/api/orders"],
        headers={"Server": "nginx/1.25.3"},
        technologies=["Next.js 14"],
    )


def _reply(content: str):
    return types.SimpleNamespace(choices=[types.SimpleNamespace(
        message=types.SimpleNamespace(content=content))])


def _run(monkeypatch, content: str) -> tuple[list[dict], list[str]]:
    """Drive the shipping plugin against `content`; return (messages, endpoints).

    `discover()` swallows every exception, so the captured request is asserted
    non-empty — a plugin that stopped calling the model would otherwise leave
    these tests passing on nothing.
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


def _shipped() -> str:
    """Every byte of the prompt this plugin would send, both turns."""
    rp = render(dataclasses.replace(DISCOVER_SUGGEST,
                                    variables=_prompt_variables(_site())),
                profile_for(), mode=Mode.ADAPT)
    return "\n".join(m["content"] for m in rp.messages)


def _exemplar() -> str:
    """The worked example, read out of the prompt rather than retyped here."""
    matches = re.findall(r'^\{".*\}$', _shipped(), re.MULTILINE)
    assert len(matches) == 1, f"expected one JSON exemplar line, got {matches}"
    return matches[0]


def test_a_model_that_copies_the_exemplar_keeps_its_round(monkeypatch):
    """The measurement this item exists for.

    The response IS the example the prompt shows, verbatim. Before 4.6 that
    produced no endpoints at all, because the example did not parse.
    """
    shown = _exemplar()
    expected = json.loads(shown)["endpoints"]
    assert expected, "the exemplar shows no endpoints to recover"

    _, endpoints = _run(monkeypatch, shown)
    assert endpoints == expected, (
        "a model answering with the exact example it was shown lost the "
        f"suggestion round: prompt showed {shown!r}, plugin returned {endpoints!r}"
    )


def test_the_copied_exemplar_survives_a_fence(monkeypatch):
    """The same, wrapped the way a local model wraps it.

    `response_format` is withheld from custom endpoints (LM Studio, vLLM), so
    the fenced shape is the common one exactly where the exemplar is most
    likely to be copied literally.
    """
    shown = _exemplar()
    _, endpoints = _run(monkeypatch, f"```json\n{shown}\n```")
    assert endpoints == json.loads(shown)["endpoints"]


def test_the_wire_carries_a_system_turn_when_the_model_has_one(monkeypatch):
    """The request envelope, from the plugin rather than from the renderer."""
    messages, _ = _run(monkeypatch, '{"endpoints": [], "reasoning": "none"}')
    profile = profile_for()
    if not profile.system_role:                      # pragma: no cover
        assert [m["role"] for m in messages] == ["user"]
        return
    assert [m["role"] for m in messages] == ["system", "user"]
    assert [sorted(m) for m in messages] == [["content", "role"], ["content", "role"]]
    assert "Return ONLY a JSON object" in messages[0]["content"]


def test_the_evidence_stays_in_the_user_turn(monkeypatch):
    """Target-derived bytes belong with the data, not with the instructions."""
    messages, _ = _run(monkeypatch, '{"endpoints": [], "reasoning": "none"}')
    user = [m for m in messages if m["role"] == "user"]
    assert len(user) == 1
    body = user[0]["content"]
    for expected in ("Next.js 14", "  /api/orders", "  POST /login inputs=['user']",
                     "  Server: nginx/1.25.3",
                     "  - Next.js (API routes in /api/*, NextAuth.js common)"):
        assert expected in body, f"{expected!r} missing from the user turn"
    system = "".join(m["content"] for m in messages if m["role"] == "system")
    assert "nginx/1.25.3" not in system, "target bytes leaked into the system turn"
