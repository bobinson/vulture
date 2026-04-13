"""CWE finding verification strategy with self-learning."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from prove_agent.llm_helper import llm_json_call
from prove_agent.strategies.base import (
    AttemptRecord,
    BaseStrategy,
    ExecutionResult,
    ProofPlan,
    ReflectionResult,
    ReviewResult,
)
from prove_agent.strategies.shared import (
    _is_upload_finding,
    build_fallback_plan,
    build_prior_context,
    execute_and_analyze,
    filter_site_context,
    format_attempt_history,
    is_static_asset,
)

if TYPE_CHECKING:
    from prove_agent.protocols.detection import TargetCapabilities

logger = logging.getLogger(__name__)

_PLAN_PROMPT = """You are a vulnerability researcher. Given this CWE finding, create an HTTP request to verify the vulnerability on the staging server.

RULES:
1. Use the discovered site map below to pick REAL URLs that exist on the target.
2. Do NOT use "/" as the url_path — pick a specific endpoint.
3. NEVER target static files (.js, .css, .png, .svg, .woff, .map files) or build artifacts (_next/static/*, _buildManifest.js, etc.). These are NOT API endpoints.
4. PREFER API endpoints (/api/*, /v1/*, /graphql), form actions, and backend routes.
5. Each attempt MUST target a DIFFERENT endpoint or use a different payload.
6. For injection: craft payloads specific to the CWE type (SQL, XSS, command, path traversal).
7. For hardcoded credentials: check config endpoints and API responses (NOT .js files).
8. For file upload: target upload endpoints with malicious filenames.

Finding: {title}
Category: {category}
Description: {description}
File: {file_path}:{line_start}
Code: {code_snippet}
Hints: {verification_hints}
Staging URL: {staging_url}
Attempt: {iteration}
{prior_context}
{site_context}

Reply with ONLY a JSON object (no markdown, no explanation):
{{"description":"what this tests","method":"GET or POST","url_path":"/real-path","headers":{{}},"body":"payload if POST","expected_indicators":["indicator"]}}"""

_REFLECT_PROMPT = """You are a vulnerability researcher reflecting on failed verification attempts.

Finding: {title}
Category: {category}
Description: {description}

Previous attempts:
{attempt_history}

Analyze:
1. WHY were these attempts inconclusive? What did each response tell us?
2. What does the target's behavior reveal about its defenses or architecture?
3. What DIFFERENT approach should we try next? (not a variation — a fundamentally different technique)
4. How confident are you (0-100) that this vulnerability actually exists on the target?
5. What reusable insights did you learn that apply to other findings on this target?

Reply with JSON only:
{{"analysis":"why inconclusive","suggested_approach":"what to try differently","confidence":50,"learnings":["insight1","insight2"]}}"""


class CweStrategy(BaseStrategy):
    """Verification strategy for CWE findings."""

    async def plan(
        self, finding: dict, staging_url: str, iteration: int,
        *, site_context: str = "",
        prior_attempts: list[AttemptRecord] | None = None,
        reflection: ReflectionResult | None = None,
        cross_learnings: list[str] | None = None,
    ) -> ProofPlan:
        ctx = filter_site_context(site_context, finding)
        prior_context = build_prior_context(
            prior_attempts, reflection, cross_learnings,
        )
        hints = finding.get("verification_hints", [])
        hints_str = ", ".join(hints) if hints else "None"
        result = await llm_json_call(
            _PLAN_PROMPT.format(
                title=finding.get("title", ""),
                category=finding.get("category", ""),
                description=finding.get("description", ""),
                file_path=finding.get("file_path", ""),
                line_start=finding.get("line_start", 0),
                code_snippet=finding.get("code_snippet", ""),
                verification_hints=hints_str,
                staging_url=staging_url,
                iteration=iteration,
                site_context=ctx,
                prior_context=prior_context,
            ),
            required_fields=["url_path", "description"],
        )
        url_path = result.get("url_path", "")
        if not url_path or url_path == "/" or is_static_asset(url_path):
            logger.info("LLM returned invalid path (%s), using fallback plan", url_path)
            return build_fallback_plan(finding, site_context, prior_attempts)

        # Detect file upload plans and enable multipart
        title = finding.get("title", "")
        category = finding.get("category", "")
        is_upload = _is_upload_finding(title, category)
        method = result.get("method", "GET")
        body = result.get("body", "")
        filename = result.get("filename", "")

        # Auto-detect multipart from LLM output or finding type
        multipart = is_upload and method.upper() in ("POST", "PUT")
        if not filename and multipart:
            filename = "shell.php"

        return ProofPlan(
            description=result.get("description", ""),
            method=method,
            url_path=url_path,
            headers=result.get("headers", {}),
            body=body,
            expected_indicators=result.get("expected_indicators", []),
            is_multipart=multipart,
            filename=filename,
        )

    async def review(
        self, plan: ProofPlan, staging_url: str,
    ) -> ReviewResult:
        return ReviewResult(safe=True, reasoning="Staging environment — probing allowed")

    async def execute(
        self, plan: ProofPlan, staging_url: str,
        *, capabilities: TargetCapabilities | None = None,
    ) -> ExecutionResult:
        if capabilities:
            from prove_agent.protocols.dispatcher import execute_plan
            return await execute_plan(
                plan, staging_url, capabilities,
                finding_category="CWE",
                finding_title=plan.description,
            )
        return await execute_and_analyze(
            plan, staging_url,
            finding_category="CWE",
            finding_title=plan.description,
        )

    async def reflect(
        self, finding: dict, attempts: list[AttemptRecord],
    ) -> ReflectionResult:
        history = format_attempt_history(attempts)
        result = await llm_json_call(_REFLECT_PROMPT.format(
            title=finding.get("title", ""),
            category=finding.get("category", ""),
            description=finding.get("description", ""),
            attempt_history=history,
        ))
        return ReflectionResult(
            analysis=result.get("analysis", ""),
            suggested_approach=result.get("suggested_approach", ""),
            confidence=min(100, max(0, result.get("confidence", 50))),
            learnings=result.get("learnings", []),
        )
