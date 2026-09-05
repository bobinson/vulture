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

# NOT the prompt source any more — feature 0089 Phase 2.1 moved that to the
# fragment `discover/suggest`, which `DISCOVER_SUGGEST` names and `render()`
# assembles (see `_suggest_messages`). This literal stays because it is the
# transcription's only INDEPENDENT oracle: once both sides of
# `test_0089_parity_discover*.py` go through `render()` those tests compare the
# library to itself, and `test_0089_manifest_discover.py` — which reads this
# constant out of this file by AST and asserts the fragment equals it byte for
# byte, `str.format`'s `{{`/`}}` encoding resolved — becomes the one assertion
# that can still see the fragment drift from the prompt this agent shipped.
# Do not reword, reformat or delete it: edit the fragment, then this, together.
_LLM_DISCOVER_PROMPT = """You are a web security expert. Given the following discovered information about a web application, suggest additional API endpoints that likely exist but weren't found by automated scanning.

Technologies detected: {technologies}
Known API endpoints: {api_endpoints}
Forms found: {forms}
Response headers: {headers}
Framework signals: {framework_hints}

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
{{"endpoints": ["/api/path1", "/api/path2", ...], "reasoning": "brief explanation"}}

Rules:
- Only suggest paths starting with /api/, /v1/, /v2/, /graphql, /rest/, /rpc/, /ws/, /auth/
- Do NOT suggest static file paths (.js, .css, images)
- Do NOT suggest HTML page paths (/login, /dashboard, etc.)
- Focus on backend API endpoints that accept/return JSON
- Limit to 20 most likely endpoints"""


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

    Lifted verbatim out of the old ``_LLM_DISCOVER_PROMPT.format(...)`` call —
    the same joins, the same two-space indents, the same ``or`` fallbacks — so
    the values are unchanged and only their destination moved. This shaping is
    still the call site's job: the fragment declares ``{technologies}`` & co.
    as plain placeholders, and 0089 Phase 2 has not yet turned them into
    declared slots.
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

    TRANSCRIBE, not ADAPT: 0089 Phase 2 is a pure refactor, and every adaptive
    rule changes bytes. The spec declares no system fragments, so ``render``
    returns the single user turn this plugin has always sent.
    """
    spec = dataclasses.replace(DISCOVER_SUGGEST, variables=_prompt_variables(site))
    return render(spec, profile_for(), mode=Mode.TRANSCRIBE).messages


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
