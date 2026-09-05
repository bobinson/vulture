"""Feature 0089 Phase 1 — ASSEMBLED byte parity for the DISCOVER tier.

`test_0089_manifest_discover.py` already pins the TEMPLATE: the fragment text
equals `_LLM_DISCOVER_PROMPT` byte for byte. That is necessary and not
sufficient. What the shipping plugin actually sends is the template *after*
interpolation — `_LLM_DISCOVER_PROMPT.format(technologies=..., forms=..., ...)`
at `discover_agent/plugins/llm_suggest.py:85-104`, wrapped in
`messages=[{"role": "user", ...}]` at :110-113. Phase 2 can only swap the call
site for `render()` if the ASSEMBLED bytes agree, so that is what is compared
here.

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
    live_messages = _live_messages(monkeypatch)
    rp = render(dataclasses.replace(DISCOVER_SUGGEST, variables=_vars()),
                profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)

    # Envelope: the plugin sends one user turn and no system turn at all.
    # NOT compared: the live request also carries `model`, `timeout` and
    # `response_format={"type": "json_object"}` (llm_suggest.py:106-115), and
    # TRANSCRIBE returns `response_format=None` by construction
    # (render.py:129). That half of the envelope becomes comparable only under
    # ADAPT, so asserting it here would fail for a reason that is not drift.
    assert len(live_messages) == 1
    assert live_messages[0]["role"] == "user"
    assert rp.instructions == ""

    assert rp.user == live_messages[0]["content"], _diff(rp.user, live_messages[0]["content"])
    assert rp.messages == live_messages
