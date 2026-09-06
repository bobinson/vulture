"""LLMEndpointPlugin — LLM-powered endpoint suggestion (priority 80).

Analyzes the discovered technology stack and suggests additional API endpoints
that likely exist but weren't found by automated scanning. Degrades gracefully
if no LLM is configured.
"""

import dataclasses
import logging
import os

from shared.discovery.helpers import is_static_path
from shared.discovery.plugin_base import (
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
)
from shared.prompt import Mode, profile_for, render
from shared.prompt.extract import extract_object
from shared.prompt.manifests.discover_suggest import DISCOVER_SUGGEST

logger = logging.getLogger(__name__)

# NOT the prompt source — feature 0089 Phase 2.1 moved that into the fragment
# library, and 4.6 split it in two: `discover/system` and `discover/suggest`,
# which `DISCOVER_SUGGEST` names and `render()` assembles (see
# `_suggest_messages`). These literals stay because
# they are this call site's only INDEPENDENT oracle: both sides of
# `test_0089_parity_discover*.py` go through `render()` and therefore compare
# the library to itself, while `test_0089_manifest_discover.py` reads these
# constants out of this file by AST and asserts each fragment equals its own
# literal byte for byte. Keeping the duplicate SAFE rather than deleting it is
# this repo's established treatment of a surviving prompt literal — see
# `tests/unit/prompt/test_0089_no_second_source_of_truth.py`, which does the
# same for the seven agents' `INSTRUCTIONS` constants and names deletion as a
# separate follow-up.
#
# ONE turn until 0089 Phase 4.6, which split them: the standing instructions
# are the same on every call and the discovered evidence is not, so the first
# goes in the system turn where the model has one. `Mode.ADAPT` folds them back
# into a single user turn for a family whose chat template has no system role.
#
# These are NOT `str.format` templates any more (nothing calls `.format` on
# them; `render._fill` does the substitution), so they carry SINGLE braces —
# the same syntax the fragments use. Do not reword, reformat or delete them:
# edit the fragment, then this, together.
_LLM_DISCOVER_SYSTEM = """You are a web security expert. Given discovered information about a web application, suggest additional API endpoints that likely exist but weren't found by automated scanning.

Based on the technology stack, suggest additional API endpoints that commonly exist. Focus on:
1. REST API CRUD endpoints (GET/POST/PUT/DELETE for known resources)
2. Authentication endpoints (login, register, session, token, refresh, password reset)
3. GraphQL endpoints (common paths, mutations, subscriptions)
4. WebSocket/real-time endpoints
5. Admin/management endpoints
6. File upload/download endpoints
7. Search/filter endpoints
8. Webhook/callback endpoints
9. Health/status/metrics endpoints
10. Configuration/settings endpoints exposed by the framework

Return ONLY a JSON object:
{"endpoints": ["/api/users", "/api/auth/login"], "reasoning": "brief explanation"}

Rules:
- Only suggest paths starting with one of these API roots: /api/, /v1/, /v2/, /rest/, /rpc/, /jsonrpc, /graphql, /gql, /ws/, /wss/, /socket.io/, /auth/, /oauth/, /oauth2/, /.well-known/, /internal/, /actuator/, /healthz, /metrics, /wp-json/
- A path that extends one already listed under "Known API endpoints" also qualifies, whatever root it starts with
- Do NOT suggest static file paths (.js, .css, images)
- Do NOT suggest HTML page paths (/login, /dashboard, etc.)
- Focus on backend API endpoints that accept/return JSON
- Limit to 20 most likely endpoints
- Suggest only what the discovered evidence supports. If it supports none, answer with an empty endpoints array and give the reason; an empty array is a complete answer, and padding the list with guesses is not"""

_LLM_DISCOVER_USER = """Discovered information about the target web application:

Technologies detected: {technologies}
Known API endpoints: {api_endpoints}
Forms found: {forms}
Response headers: {headers}
Framework signals: {framework_hints}

Suggest additional API endpoints that likely exist on this application, as the JSON object described above."""


@register_plugin
class LLMEndpointPlugin(DiscoveryPlugin):
    """Use LLM to suggest hidden API endpoints based on discovered tech stack."""

    name = "llm_suggest"
    priority = 80

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        """Only run if LLM is configured.

        Feature 0043: route the env-var read through the shared helper
        ``shared.llm.mode.is_skills_only()`` so discover honors the
        platform-wide skills/LLM contract consistently with prove and
        the scan agents. A separate provider-key check ensures we
        skip even when use_llm=true is set but no key is available
        (avoids litellm AuthenticationError entries when the operator
        forgot to set the key).
        """
        from shared.llm.mode import is_skills_only

        if is_skills_only():
            return False
        has_key = bool(
            os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("OLLAMA_API_BASE")
        )
        return has_key

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        """Suggest endpoints via LLM analysis of discovered tech stack."""
        result = DiscoveryResult()

        messages = _suggest_messages(ctx.site)

        try:
            import litellm

            from shared.llm.provider import resolve_model_for_litellm, uses_custom_endpoint

            model = resolve_model_for_litellm()
            kwargs: dict = {
                "model": model,
                "messages": messages,
                "timeout": 30.0,
            }
            # Custom endpoints (vLLM, LM Studio) may not support response_format
            if not uses_custom_endpoint():
                kwargs["response_format"] = {"type": "json_object"}
            resp = await litellm.acompletion(**kwargs)
            text = resp.choices[0].message.content or ""
            # `json.loads(text)` until 0089 Phase 2.1: it needs the response to
            # BE the object and nothing else, so a fenced ```json block or a
            # reasoning model's `<think>` preamble lost the whole suggestion
            # round — and `response_format` is withheld from exactly the custom
            # endpoints (LM Studio, vLLM) whose local models fence and think.
            data = extract_object(text)
            if data is None:
                logger.warning(
                    "LLM endpoint suggestion returned no JSON object (%d chars)",
                    len(text),
                )
                return result
            endpoints = data.get("endpoints", [])
            for ep in endpoints:
                if isinstance(ep, str) and ep.startswith("/") and not is_static_path(ep):
                    if ep not in ctx.site.api_endpoints:
                        result.endpoints.append(ep)
                    if ep not in ctx.site.urls:
                        result.urls.append(ep)
            if result.endpoints:
                reasoning = data.get("reasoning", "")
                logger.info(
                    "LLM suggested %d new endpoints: %s",
                    len(result.endpoints), reasoning[:100],
                )
        except ImportError:
            logger.info("litellm not available, skipping LLM endpoint suggestion")
        except Exception as exc:
            logger.warning("LLM endpoint suggestion failed: %s", exc)

        return result


def _prompt_variables(site) -> dict[str, str]:
    """The five interpolated blocks, shaped as the prompt expects them.

    Lifted verbatim out of the pre-0089 inline ``.format(...)`` call — the same
    joins, the same two-space indents, the same ``or`` fallbacks — so the values
    are unchanged and only their destination moved. This shaping is still the
    call site's job: ``discover/suggest`` declares ``{technologies}`` & co. as
    plain placeholders, and they are still not declared slots — see the
    manifest docstring for the untrusted-bytes finding that leaves open.
    """
    return {
        "technologies": ", ".join(site.technologies) or "unknown",
        "api_endpoints": "\n".join(
            f"  {e}" for e in site.api_endpoints[:20]
        ) or "none found",
        "forms": "\n".join(
            f"  {f['method']} {f['action']} inputs={f.get('inputs', [])}"
            for f in site.forms[:10]
        ) or "none found",
        "headers": "\n".join(
            f"  {k}: {v}" for k, v in site.headers.items()
        ) or "none",
        "framework_hints": "\n".join(
            f"  - {h}" for h in _build_framework_hints(site)
        ) or "none detected",
    }


def _suggest_messages(site) -> list[dict]:
    """The request turns for one endpoint-suggestion round.

    ADAPT since 0089 Phase 4.6 (TRANSCRIBE through Phases 2-3, when a pure
    refactor was not allowed to move a byte). The spec now declares a system
    fragment, and ADAPT is what makes its placement conditional on the model:
    a family with a system role gets two turns, and one without — gemma's chat
    template has none — gets everything folded into a single user turn instead
    of a system message its template would silently drop.

    ``response_format`` is deliberately NOT taken from the render here: the
    caller decides it from ``uses_custom_endpoint()``, because a gateway that
    proxies an OpenAI-compatible endpoint may not accept the field at all,
    which is a transport fact the model profile does not carry.
    """
    spec = dataclasses.replace(DISCOVER_SUGGEST, variables=_prompt_variables(site))
    return render(spec, profile_for(), mode=Mode.ADAPT).messages


def _build_framework_hints(site) -> list[str]:
    """Extract framework hints from discovered technologies."""
    hints = []
    for tech in site.technologies:
        tl = tech.lower()
        if "next" in tl:
            hints.append("Next.js (API routes in /api/*, NextAuth.js common)")
        elif "react" in tl:
            hints.append("React SPA (likely REST API backend)")
        elif "django" in tl:
            hints.append("Django (REST framework, admin/, api-auth/)")
        elif "express" in tl:
            hints.append("Express.js (REST routes, middleware)")
        elif "graphql" in tl:
            hints.append("GraphQL detected (queries, mutations, subscriptions)")
        elif "firebase" in tl:
            hints.append("Firebase (Firestore, Auth, Functions at /api/)")
        elif "laravel" in tl:
            hints.append("Laravel (api/ prefix, sanctum auth)")
        elif "rails" in tl:
            hints.append("Ruby on Rails (RESTful routes, Devise auth)")

    if any("firebase" in ep.lower() for ep in site.api_endpoints) and not any(
        "Firebase" in h for h in hints
    ):
        hints.append("Firebase detected in API endpoints")

    return hints
