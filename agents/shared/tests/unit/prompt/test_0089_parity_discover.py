"""Feature 0089 Phase 1 — ASSEMBLED byte parity for the DISCOVER tier.

`test_0089_manifest_discover.py` already pins the TEMPLATES: each fragment's
text equals its production literal byte for byte. That is necessary and not
sufficient. What the shipping plugin actually sends is the template *after*
interpolation, wrapped in chat turns, so that is what is compared here.

PHASE 4.6 moved two things under this file. The call site renders in
`Mode.ADAPT` and the spec declares a system fragment, so the envelope is two
turns where the model has a system role — the assertions that read
`len(live_messages) == 1` and `rp.instructions == ""` were pinning the
transcription and now pin the split. And the expected side renders with
`profile_for()`, the same resolution the plugin performs, because under ADAPT
the profile decides placement: a hardcoded model here could disagree with the
one production resolves and report that as drift.

The live side is not re-implemented: the real `LLMEndpointPlugin.discover()`
runs against a fixture `SiteMap` with `litellm.acompletion` replaced by a
capturing stub, so the compared string is the one that would have gone on the
wire. No network, no model, no key.

Both sides are driven from the same fixture strings (`_TECH`, `_ENDPOINT`,
`_FORM`, `_HEADER`): the SiteMap carries them into the plugin's own
interpolation, and `_VARS` carries them into `spec.variables`. The `"  "` /
`"  - "` prefixes are written out on the `_VARS` side because the library has
no derivation layer yet — that formatting is exactly what Phase 2 turns into
declared slots. The framework-hint TEXT is single-sourced from
`_build_framework_hints` instead of being retyped, because a reworded hint is
a domain-data change, not a prompt drift, and must not be reported as one.
"""

from __future__ import annotations

import asyncio
import dataclasses
import difflib
import types

import litellm

from discover_agent.plugins.llm_suggest import (
    LLMEndpointPlugin,
    _build_framework_hints,
)
from shared.discovery.plugin_base import DiscoveryContext
from shared.discovery.sitemap import SiteMap
from shared.prompt import Mode, profile_for, render
from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST

# ── the fixture, in one place, feeding both sides ─────────────────────────────

_TECH = "Next.js 14"
_ENDPOINT = "/api/users"
_FORM = {"method": "POST", "action": "/login", "inputs": ["user", "pass"]}
_HEADER = ("Server", "nginx/1.25.3")


def _site() -> SiteMap:
    """A discovered site carrying the fixture strings. Built per call so the
    plugin cannot leak state into another test through a shared mutable."""
    return SiteMap(
        urls=["/"],
        forms=[dict(_FORM)],
        api_endpoints=[_ENDPOINT],
        headers={_HEADER[0]: _HEADER[1]},
        technologies=[_TECH],
    )


def _vars() -> dict[str, str]:
    """The same fixture strings, shaped the way `llm_suggest.discover()` shapes
    them before `str.format` (`llm_suggest.py:85-104`)."""
    return {
        "technologies": _TECH,
        "api_endpoints": f"  {_ENDPOINT}",
        "forms": f"  {_FORM['method']} {_FORM['action']} inputs={_FORM['inputs']}",
        "headers": f"  {_HEADER[0]}: {_HEADER[1]}",
        "framework_hints": "\n".join(f"  - {h}" for h in _build_framework_hints(_site())),
    }


# ── the live side: run the shipping plugin, capture what it would send ────────

_CANNED = types.SimpleNamespace(
    choices=[types.SimpleNamespace(
        message=types.SimpleNamespace(content='{"endpoints": [], "reasoning": "fixture"}')
    )]
)


def _live_messages(monkeypatch) -> list[dict]:
    """The `messages` payload `LLMEndpointPlugin.discover()` really builds."""
    seen: list[dict] = []

    async def _capture(**kwargs):
        seen.append(kwargs)
        return _CANNED

    monkeypatch.setattr(litellm, "acompletion", _capture)
    ctx = DiscoveryContext(staging_url="http://fixture.invalid", http_client=None,
                           site=_site())
    asyncio.run(LLMEndpointPlugin().discover(ctx))

    # `discover()` swallows every exception (llm_suggest.py:130-134), so a stub
    # that never ran, or a call site that stopped calling acompletion, would
    # otherwise leave this test passing on an empty comparison. It must not.
    assert len(seen) == 1, f"the plugin did not build one LLM request: {seen!r}"
    return seen[0]["messages"]


def _diff(rendered: str, live: str) -> str:
    lines = difflib.unified_diff(
        rendered.splitlines(keepends=True), live.splitlines(keepends=True),
        fromfile="render(DISCOVER_SUGGEST)", tofile="llm_suggest.py (live)",
    )
    return (
        "assembled DISCOVER prompt is NOT byte-identical to the live builder\n"
        f"rendered {len(rendered)} chars, live {len(live)} chars\n" + "".join(lines)
    )


def test_parity_discover(monkeypatch):
    """The assembled DISCOVER prompt matches the live builder, byte for byte."""
    profile = profile_for()
    live_messages = _live_messages(monkeypatch)
    rp = render(dataclasses.replace(DISCOVER_SUGGEST, variables=_vars()),
                profile, mode=Mode.ADAPT)

    # Envelope. BEFORE 4.6 this read `len(live_messages) == 1`, `role ==
    # "user"` and `rp.instructions == ""`: the transcription declared no system
    # fragment, so the plugin sent one turn. It now sends two where the model
    # has a system role, and one — everything folded — where it does not.
    #
    # NOT compared: the live request also carries `model`, `timeout` and
    # `response_format`, which the call site derives from
    # `uses_custom_endpoint()` rather than from the render.
    expected_roles = ["system", "user"] if profile.system_role else ["user"]
    assert [m["role"] for m in live_messages] == expected_roles
    assert bool(rp.instructions) is profile.system_role

    live_user = next(m for m in live_messages if m["role"] == "user")["content"]
    assert rp.user == live_user, _diff(rp.user, live_user)
    assert rp.messages == live_messages
