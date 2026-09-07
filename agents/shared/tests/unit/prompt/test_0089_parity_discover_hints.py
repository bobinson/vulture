"""Feature 0089 Phase 1 — closing the two blind spots in DISCOVER byte parity.

`test_0089_parity_discover.py` is sound and is not weakened or replaced by this
file. It has two bounded insensitivities, both of which let a change that
really does reach the model pass unseen. Phase 1 may not edit production code
and may not edit an existing test, so they are closed here instead of in place.

1. SELF-COMPARED DOMAIN TEXT. That file's `_vars()` calls the live
   `_build_framework_hints()` and feeds its output into the RENDERED side,
   while `discover()` calls the same function for the LIVE side, so that
   substring is compared to itself — 50 of 1409 compared bytes (3.5%). Proven
   empirically: a length-preserving rewording of the Next.js hint in
   `llm_suggest.py` left the failure byte-identical. Those bytes egress to the
   model, so a reworded hint was undetectable.

   Closed twice over. `test_framework_hints_pinned` retypes the hint table as
   literals HERE and pins the live function to it — that test is GREEN today,
   so a rewording turns a passing test red, which is an unambiguous signal even
   while assembled parity stays red for an unrelated reason. And
   `test_parity_discover_multi` renders from those same literals rather than
   from production, so 100% of its compared bytes are independently sourced.
   Attribution — the reason the green team single-sourced the hint in the first
   place — is kept by `_attribution()`: a hint-text change is named as DOMAIN
   DATA, never reported as prompt-template drift.

2. UNEXERCISED SEPARATORS. The fixture next door carries exactly one endpoint,
   one form and one header, and a one-element `"\\n".join(...)` emits no
   separator at all: none of the interpolation separator bytes were compared
   there, so `"\\n".join` -> `", ".join` in the plugin was invisible. The
   fixture here carries two technologies, three endpoints, two forms and two
   headers, which also drives `_build_framework_hints` down three different
   branches (two technology-derived, one endpoint-derived), so every join
   separator lands inside the compared bytes.

The live side is the shipping `LLMEndpointPlugin.discover()` run against a
fixture `SiteMap` with `litellm.acompletion` replaced by a capturing stub, so
the compared string is the one that would have gone on the wire. No network, no
model, no key. The fixture VALUES are test-owned and may legitimately feed both
sides; the interpolation SHAPING and the hint TEXT are production behaviour and
are therefore written out as literals below, never imported.
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

# ── fixture VALUES: test-owned, so they may drive both sides ──────────────────

_TECHS = ["Next.js 14", "React 18"]
_ENDPOINTS = ["/api/users", "/api/orders", "/api/firebase/config"]
_FORMS = [
    {"method": "POST", "action": "/login", "inputs": ["user", "pass"]},
    {"method": "GET", "action": "/search", "inputs": ["q"]},
]
_HEADERS = {"Server": "nginx/1.25.3", "X-Powered-By": "Next.js"}


def _site() -> SiteMap:
    """A discovered site carrying the fixture values. Built per call so the
    plugin cannot leak state into another test through a shared mutable."""
    return SiteMap(
        urls=["/"],
        forms=[dict(f) for f in _FORMS],
        api_endpoints=list(_ENDPOINTS),
        headers=dict(_HEADERS),
        technologies=list(_TECHS),
    )


# ── production TEXT and production SHAPING: retyped, never imported ──────────

# `_build_framework_hints` (llm_suggest.py:140-167), read off the source and
# retyped. Pinned by `test_framework_hints_pinned`; a rewording of any of these
# strings must fail that test rather than pass silently through both sides.
_HINTS = [
    "Next.js (API routes in /api/*, NextAuth.js common)",   # tech "Next.js 14"
    "React SPA (likely REST API backend)",                  # tech "React 18"
    "Firebase detected in API endpoints",                   # /api/firebase/config
]

# The five interpolated blocks exactly as `discover()` shapes them before
# `str.format` (llm_suggest.py:85-104): `", ".join` for technologies, `"\n".join`
# with a two-space indent for endpoints/forms/headers, `"  - "` for hints, and
# `inputs=` carrying the Python list repr. Written out because that shaping is
# the thing under test — Phase 2 turns it into declared slots.
_VARS = {
    "technologies": "Next.js 14, React 18",
    "api_endpoints": "  /api/users\n  /api/orders\n  /api/firebase/config",
    "forms": "  POST /login inputs=['user', 'pass']\n  GET /search inputs=['q']",
    "headers": "  Server: nginx/1.25.3\n  X-Powered-By: Next.js",
    "framework_hints": (
        "  - Next.js (API routes in /api/*, NextAuth.js common)\n"
        "  - React SPA (likely REST API backend)\n"
        "  - Firebase detected in API endpoints"
    ),
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


def _rendered():
    """`Mode.ADAPT` and `profile_for()` since Phase 4.6 — what the plugin does.

    Under TRANSCRIBE the profile could not affect a byte, so `"gpt-4o"` was
    free. Under ADAPT it decides turn placement, and a model string hardcoded
    here that disagreed with the one production resolves would be reported as
    prompt drift.
    """
    return render(dataclasses.replace(DISCOVER_SUGGEST, variables=dict(_VARS)),
                  profile_for(), mode=Mode.ADAPT)


def _attribution() -> str:
    """Say which side of the Phase 1 contract a divergence belongs to.

    The hint text is domain data. Pinning it here makes a rewording visible
    (which is the repair) but must not make it look like prompt drift (which
    was the green team's reason for single-sourcing it), so the diff names
    which of the two it is."""
    live_hints = _build_framework_hints(_site())
    if live_hints != _HINTS:
        return (
            "ATTRIBUTION: framework-hint DOMAIN DATA changed — live "
            f"{live_hints!r} != pinned {_HINTS!r}. This is a domain-data edit, "
            "NOT prompt drift: update _HINTS and _VARS in this test file, and "
            "do not touch the fragment.\n"
        )
    return (
        "ATTRIBUTION: framework-hint domain data is unchanged, so the "
        "divergence below is in the prompt TEMPLATE or in the interpolation "
        "shaping — real drift between the fragment and the live builder.\n"
    )


def _diff(rendered: str, live: str) -> str:
    lines = difflib.unified_diff(
        rendered.splitlines(keepends=True), live.splitlines(keepends=True),
        fromfile="render(DISCOVER_SUGGEST)", tofile="llm_suggest.py (live)",
    )
    return (
        "assembled DISCOVER prompt is NOT byte-identical to the live builder\n"
        + _attribution()
        + f"rendered {len(rendered)} chars, live {len(live)} chars\n"
        + "".join(lines)
    )


def test_framework_hints_pinned():
    """The hint TEXT that egresses to the model, pinned byte for byte.

    Assembled parity single-sources this text into both of its sides, so this
    is the only assertion in Phase 1 that can see it change. It compares the
    live list to literals retyped in this file: byte equality, no membership
    test, no normalisation."""
    assert _build_framework_hints(_site()) == _HINTS, (
        "framework-hint domain data drifted from the pin in this test file.\n"
        f"live:   {_build_framework_hints(_site())!r}\n"
        f"pinned: {_HINTS!r}\n"
        "This text is interpolated into {framework_hints} and egresses to the "
        "model. If the change is intended, update _HINTS and the "
        "'framework_hints' entry of _VARS here — never the fragment."
    )


def test_framework_hint_table_pinned():
    """Every hint string the function can emit, not just the three this
    fixture reaches.

    `test_framework_hints_pinned` covers the three branches the parity fixture
    drives. The other six strings egress to the model just as directly on a
    Django or Rails target and would otherwise be pinned by nothing at all, so
    the whole table is driven branch by branch and compared byte for byte. The
    `elif` chain is order-sensitive and the endpoint-derived hint is
    suppressed when a Firebase technology hint is already present; both facts
    shape what reaches the model, so both are pinned here."""
    def hints(techs: list[str], eps: list[str] | None = None) -> list[str]:
        return _build_framework_hints(
            SiteMap(technologies=techs, api_endpoints=list(eps or []))
        )

    actual = {
        "next": hints(["Next.js 14"]),
        "react": hints(["React 18"]),
        "django": hints(["Django 5.0"]),
        "express": hints(["Express 4"]),
        "graphql": hints(["GraphQL"]),
        "firebase": hints(["Firebase"]),
        "laravel": hints(["Laravel 11"]),
        "rails": hints(["Rails 7"]),
        "unknown": hints(["Cobol"]),
        "endpoint_only": hints([], ["/api/firebase/config"]),
        "endpoint_suppressed": hints(["Firebase"], ["/api/firebase/config"]),
    }
    expected = {
        "next": ["Next.js (API routes in /api/*, NextAuth.js common)"],
        "react": ["React SPA (likely REST API backend)"],
        "django": ["Django (REST framework, admin/, api-auth/)"],
        "express": ["Express.js (REST routes, middleware)"],
        "graphql": ["GraphQL detected (queries, mutations, subscriptions)"],
        "firebase": ["Firebase (Firestore, Auth, Functions at /api/)"],
        "laravel": ["Laravel (api/ prefix, sanctum auth)"],
        "rails": ["Ruby on Rails (RESTful routes, Devise auth)"],
        "unknown": [],
        "endpoint_only": ["Firebase detected in API endpoints"],
        # the tech hint already says Firebase, so the endpoint hint is dropped
        "endpoint_suppressed": ["Firebase (Firestore, Auth, Functions at /api/)"],
    }
    assert actual == expected, (
        "framework-hint domain data drifted from the table pinned in this test "
        "file. These strings are interpolated into {framework_hints} and "
        "egress to the model. If the change is intended, update the table "
        "here — never the fragment."
    )


def test_parity_discover_multi(monkeypatch):
    """Assembled DISCOVER parity with every compared byte independently sourced.

    The fragment supplies the template, this file supplies the interpolated
    values and the hint text, and the live plugin supplies the comparison — so
    no substring is compared to itself. Multi-element blocks mean the join
    separators are compared too."""
    live_messages = _live_messages(monkeypatch)
    rp = _rendered()

    # Envelope. BEFORE 4.6: one user turn, no system turn, `rp.instructions ==
    # ""`. The split makes it two turns where the model has a system role.
    # NOT compared: the live request also carries `model`, `timeout` and
    # `response_format`, which the call site derives from
    # `uses_custom_endpoint()` rather than from the render.
    profile = profile_for()
    expected_roles = ["system", "user"] if profile.system_role else ["user"]
    assert [m["role"] for m in live_messages] == expected_roles
    assert bool(rp.instructions) is profile.system_role

    live_user = next(m for m in live_messages if m["role"] == "user")["content"]
    assert rp.user == live_user, _diff(rp.user, live_user)
    assert rp.messages == live_messages


def test_discover_envelope_shape(monkeypatch):
    """The request envelope, asserted where it can actually execute.

    Envelope equality lives at the END of both parity tests, after the content
    assertion, so it never ran while the content assertion was failing on the
    renderer's `{{`/`}}` defect. A turn appearing or disappearing, or an extra
    key on the message dict, is therefore checked here where nothing can fail
    ahead of it.

    PHASE 4.6 IS THE TRANSITION THIS TEST WAS WRITTEN FOR. It previously
    asserted `["user"]`, `rp.instructions == ""`, `fragments == ()` and closed
    with: "When a second id is added here, ordering becomes a real surface and
    the byte comparison above starts covering it — this pin is what makes that
    transition visible instead of silent." A second id has now been added, so
    the pin is updated to the new shape rather than deleted, and ordering is
    covered by `test_parity_discover_multi` above.
    """
    live_messages = _live_messages(monkeypatch)
    rp = _rendered()
    profile = profile_for()

    expected_roles = ["system", "user"] if profile.system_role else ["user"]
    assert [m["role"] for m in live_messages] == expected_roles
    assert [sorted(m) for m in live_messages] == [["content", "role"]] * len(expected_roles)
    assert [m["role"] for m in rp.messages] == [m["role"] for m in live_messages]
    assert [sorted(m) for m in rp.messages] == [sorted(m) for m in live_messages]
    assert bool(rp.instructions) is profile.system_role

    assert DISCOVER_SUGGEST.fragments == ("discover/system", "core/language")
    assert DISCOVER_SUGGEST.user_fragments == ("discover/suggest",)
