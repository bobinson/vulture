"""Shared utilities for verification strategies."""

import json
import logging
import os
import re

import httpx

from prove_agent.llm_helper import llm_json_call
from prove_agent.strategies.base import (
    AttemptRecord, ExecutionResult, FailureReason, ProofPlan, ReflectionResult,
)
from prove_agent.strategies.rule_analyzer import analyze_response
from prove_agent.techniques import pick_next_technique

logger = logging.getLogger(__name__)

# File extensions that are never API endpoints (static assets)
_STATIC_EXTENSIONS = frozenset({
    ".js", ".mjs", ".cjs", ".jsx", ".tsx", ".ts",
    ".css", ".scss", ".less", ".sass",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".json.map", ".js.map", ".css.map",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".tar", ".gz",
})

# Path patterns that indicate static assets
_STATIC_PATTERN = re.compile(
    r"(_next/static|_next/data|_next/image|__next|/static/|/assets/|/public/|"
    r"node_modules|\.chunk\.|\.bundle\.|buildManifest|ssgManifest|"
    r"_buildManifest|_ssgManifest|webpack|favicon|manifest\.json|"
    r"workbox-|sw\.js|service-worker|\.hot-update\.)",
    re.IGNORECASE,
)


# Max lines of site context to include per plan() call.
_MAX_SITE_CONTEXT_LINES = 40


def filter_site_context(site_context: str, finding: dict) -> str:
    """Filter site context to URLs relevant to the finding, capped at budget.

    Prioritizes API endpoints and URLs matching finding keywords,
    then fills remaining budget with other discovered paths. Prevents
    sending the full sitemap (potentially hundreds of URLs) on every
    plan() call — saving significant tokens across iterations.
    """
    if not site_context:
        return "No site map available — probe common paths."
    title = finding.get("title", "").lower()
    category = finding.get("category", "").lower()
    keywords = set(title.split()) | set(category.split())
    keywords -= {"the", "a", "an", "in", "of", "for", "to", "and", "or", "is", "on"}

    lines = site_context.strip().splitlines()
    relevant: list[str] = []
    other: list[str] = []
    for line in lines:
        lower = line.lower().strip()
        if not lower or not lower.startswith("/"):
            other.append(line)
            continue
        if any(kw in lower for kw in keywords) or "/api/" in lower or "/auth" in lower:
            relevant.append(line)
        else:
            other.append(line)

    selected = relevant[:_MAX_SITE_CONTEXT_LINES]
    remaining = _MAX_SITE_CONTEXT_LINES - len(selected)
    if remaining > 0:
        selected.extend(other[:remaining])
    return "DISCOVERED SITE MAP (filtered):\n" + "\n".join(selected)


def is_static_asset(path: str) -> bool:
    """Return True if the path is a static asset, never a testable endpoint."""
    lower = path.lower()
    for ext in _STATIC_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return bool(_STATIC_PATTERN.search(path))


def build_prior_context(
    attempts: list[AttemptRecord] | None,
    reflection: ReflectionResult | None,
    cross_learnings: list[str] | None,
) -> str:
    """Build rich context from prior attempts, reflection, and cross-finding learnings.

    Caps attempts to last 5 and learnings to last 5 to prevent context
    overflow on small models.
    """
    # H: Context Budget — limit inputs to prevent overflow
    if attempts and len(attempts) > 5:
        attempts = attempts[-5:]
    if cross_learnings and len(cross_learnings) > 5:
        cross_learnings = cross_learnings[-5:]

    parts = []
    if attempts:
        parts.append("PREVIOUS ATTEMPTS (do NOT repeat these — try something fundamentally different):")
        for a in attempts:
            reason_hint = ""
            if a.failure_reason != FailureReason.NONE:
                reason_hint = f" [FAILURE: {a.failure_reason.value}]"
            proto_hint = f" [{a.protocol}]" if a.protocol != "http" else ""
            parts.append(
                f"  Attempt {a.iteration}: {a.method} {a.url_path} → HTTP {a.status_code}{reason_hint}{proto_hint}\n"
                f"    Evidence: {a.evidence}\n"
                f"    Response snippet: {a.response_snippet[:200]}"
            )
    if reflection:
        parts.append(f"\nLAST REFLECTION (confidence: {reflection.confidence}%):")
        parts.append(f"  Analysis: {reflection.analysis}")
        parts.append(f"  Suggested approach: {reflection.suggested_approach}")
    if cross_learnings:
        parts.append("\nLEARNINGS FROM OTHER FINDINGS ON THIS TARGET:")
        for learning in cross_learnings[:10]:
            parts.append(f"  - {learning}")
    return "\n".join(parts)


def format_attempt_history(attempts: list[AttemptRecord]) -> str:
    """Format attempt history for reflection prompt."""
    parts = []
    for a in attempts:
        headers_str = json.dumps(a.response_headers) if a.response_headers else "{}"
        proto_line = f"  Protocol: {a.protocol}\n" if a.protocol != "http" else ""
        parts.append(
            f"Attempt {a.iteration}: {a.method} {a.url_path}\n"
            f"  Plan: {a.plan_description}\n"
            f"{proto_line}"
            f"  Status: HTTP {a.status_code}\n"
            f"  Headers: {headers_str}\n"
            f"  Response: {a.response_snippet[:300]}\n"
            f"  Evidence: {a.evidence}\n"
            f"  Conclusive: {a.conclusive}, Reproduced: {a.reproduced}"
        )
    return "\n\n".join(parts)


def extract_interesting_headers(response: httpx.Response) -> dict[str, str]:
    """Extract security-relevant headers from response."""
    interesting = [
        "server", "x-powered-by", "x-frame-options",
        "content-security-policy", "strict-transport-security",
        "x-content-type-options", "access-control-allow-origin",
        "set-cookie", "www-authenticate", "content-type",
    ]
    return {
        h: response.headers[h]
        for h in interesting
        if h in response.headers
    }


def extract_urls_from_site_context(site_context: str) -> list[str]:
    """Extract URL paths from site context text, filtering out static assets."""
    urls: list[str] = []
    seen: set[str] = set()
    for line in site_context.splitlines():
        line = line.strip()
        # Match lines like "  /path/to/page" or "  /api/endpoint"
        if line.startswith("/") and len(line) > 1:
            path = line.split()[0]  # take just the path, not annotations
            if path not in seen and path != "/" and not is_static_asset(path):
                urls.append(path)
                seen.add(path)
    # Also extract from inline patterns like "action=/login method=POST"
    for match in re.finditer(r'(?:^|\s)(/[a-zA-Z0-9_./-]+)', site_context):
        path = match.group(1)
        if path not in seen and path != "/" and not is_static_asset(path):
            urls.append(path)
            seen.add(path)

    # Prioritize: API endpoints first, then pages
    api_urls = [u for u in urls if re.search(r'/api/|/v[0-9]+/|/graphql|/auth/', u, re.I)]
    page_urls = [u for u in urls if u not in set(api_urls)]
    return api_urls + page_urls


def pick_untried_url(
    site_context: str,
    prior_attempts: list[AttemptRecord] | None,
) -> str:
    """Pick a URL from site context that hasn't been tried yet."""
    urls = extract_urls_from_site_context(site_context)
    if not urls:
        return ""
    tried = {a.url_path for a in prior_attempts} if prior_attempts else set()
    for url in urls:
        if url not in tried:
            return url
    # All tried — cycle back through with different intent
    return urls[len(tried) % len(urls)] if urls else ""


_UPLOAD_ENDPOINTS = [
    "/api/upload", "/upload", "/api/files", "/api/media",
    "/api/attachments", "/api/images", "/api/documents",
    "/files/upload", "/media/upload",
]

_DANGEROUS_FILENAMES = [
    "shell.php",
    "test.jsp",
    "payload.aspx",
    "script.html",
]


def _is_upload_finding(title: str, category: str) -> bool:
    """Check if a finding is about file upload vulnerabilities."""
    lower = title.lower()
    return any(kw in lower for kw in (
        "upload", "file upload", "unrestricted", "cwe-434",
        "file type", "file extension",
    )) or "434" in category


def build_fallback_plan(
    finding: dict,
    site_context: str,
    prior_attempts: list[AttemptRecord] | None,
) -> ProofPlan:
    """Generate a deterministic fallback plan when LLM fails to produce one.

    Prefers discovered URLs from site context, adapted with technique payloads
    and methods from the technique library. Falls back to hardcoded technique
    paths only when no discovered endpoints are available.
    """
    title = finding.get("title", "")
    category = finding.get("category", "")
    tried = {a.url_path for a in prior_attempts} if prior_attempts else set()

    # File upload findings get specialized handling
    if _is_upload_finding(title, category):
        return _build_upload_fallback(title, category, site_context, tried)

    # Get technique for this finding type (for method/payload/indicators)
    technique = pick_next_technique(title, category, tried)

    # Get a relevant discovered URL from site context
    discovered_url = _pick_relevant_url(site_context, title, category, tried)

    if technique and discovered_url:
        # Best case: combine technique payload with real discovered URL
        return ProofPlan(
            description=f"{technique.description} via {discovered_url}",
            method=technique.method,
            url_path=discovered_url,
            headers=dict(technique.headers),
            body=technique.payload,
            expected_indicators=list(technique.expected_indicators),
            is_multipart=technique.is_multipart,
            filename=technique.filename,
        )

    if technique:
        # Have technique but no discovered URL — use hardcoded technique path
        return ProofPlan(
            description=technique.description,
            method=technique.method,
            url_path=technique.path_pattern,
            headers=dict(technique.headers),
            body=technique.payload,
            expected_indicators=list(technique.expected_indicators),
            is_multipart=technique.is_multipart,
            filename=technique.filename,
        )

    if discovered_url:
        # Have discovered URL but no technique — generic probe
        return ProofPlan(
            description=f"Probe {title} via {discovered_url}",
            method="GET",
            url_path=discovered_url,
            headers={"Accept": "application/json"},
            body="",
            expected_indicators=[category, title],
        )

    # Last resort: common security-relevant endpoints
    fallbacks = [
        "/login", "/api/auth/session", "/profile", "/admin",
        "/api/users", "/settings", "/dashboard", "/api/config",
    ]
    url = next((fb for fb in fallbacks if fb not in tried), fallbacks[0])
    return ProofPlan(
        description=f"Fallback probe: {title} via {url}",
        method="GET",
        url_path=url,
        headers={},
        body="",
        expected_indicators=[category, title],
    )


def _pick_relevant_url(
    site_context: str,
    title: str,
    category: str,
    tried: set[str],
) -> str:
    """Pick a discovered URL relevant to the finding type, preferring API endpoints."""
    urls = extract_urls_from_site_context(site_context)
    if not urls:
        return ""

    untried = [u for u in urls if u not in tried]
    if not untried:
        return ""

    lower_title = title.lower()

    # Match by finding keywords: auth findings → auth URLs, injection → form URLs, etc.
    keyword_groups = [
        (("auth", "login", "credential", "session", "password", "bypass"),
         ("auth", "login", "session", "signin", "signup", "register", "callback")),
        (("injection", "sqli", "sql ", "xss", "script"),
         ("api/", "graphql", "search", "query", "form")),
        (("traversal", "path", "lfi", "directory", "file"),
         ("file", "download", "upload", "media", "document", "asset")),
        (("config", "secret", "key", "credential", "hardcod", "expos", "disclos"),
         ("config", "env", "settings", "status", "debug", "info", "health")),
        (("header", "cors", "csp", "hsts", "cookie"),
         ("api/", "/")),
    ]
    for title_kws, url_kws in keyword_groups:
        if any(kw in lower_title for kw in title_kws):
            for u in untried:
                if any(kw in u.lower() for kw in url_kws):
                    return u

    # No keyword match — return first untried API endpoint, then any page
    return untried[0]


def _build_upload_fallback(
    title: str,
    category: str,
    site_context: str,
    tried: set[str],
) -> ProofPlan:
    """Build a multipart file upload probe for CWE-434 findings."""
    # Find upload endpoints from site context
    upload_url = ""
    upload_re = re.compile(r"(/[^\s]*(?:upload|file|media|attach|image|document)[^\s]*)", re.I)
    for match in upload_re.finditer(site_context):
        path = match.group(1).split()[0]
        if path not in tried and not is_static_asset(path):
            upload_url = path
            break

    # Fall back to common upload paths
    if not upload_url:
        for ep in _UPLOAD_ENDPOINTS:
            if ep not in tried:
                upload_url = ep
                break
        if not upload_url:
            upload_url = _UPLOAD_ENDPOINTS[0]

    # Pick a dangerous filename not yet tried
    used_filenames = set()
    for url_path in tried:
        # Extract filename from prior attempt descriptions if possible
        for fn in _DANGEROUS_FILENAMES:
            if fn in str(tried):
                used_filenames.add(fn)
    filename = _DANGEROUS_FILENAMES[0]
    for fn in _DANGEROUS_FILENAMES:
        if fn not in used_filenames:
            filename = fn
            break

    return ProofPlan(
        description=f"Upload dangerous file '{filename}' to {upload_url}",
        method="POST",
        url_path=upload_url,
        headers={},
        body="<?php echo 'VULTURE_UPLOAD_TEST'; ?>",
        expected_indicators=["upload", "file", "path", "url", "success"],
        is_multipart=True,
        filename=filename,
    )


_REQUEST_TIMEOUT = 10.0
def _safe_int_env(name: str, default: int) -> int:
    val = os.environ.get(name, "")
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


_MAX_RESPONSE_BYTES = _safe_int_env("VULTURE_PROVE_MAX_RESPONSE_BYTES", 1024 * 1024)

# --- Stepped poll backoff ---
_STEP_DELAYS = [0.5, 1.0, 2.0, 3.0, 5.0]  # seconds per iteration step


def stepped_backoff_delay(iteration: int) -> float:
    """Return a stepped backoff delay based on iteration number (1-indexed).

    Early iterations are fast; later ones slow down to avoid hammering targets.
    Caps at the last value in _STEP_DELAYS.

    Args:
        iteration: Current iteration (1-indexed).

    Returns:
        Delay in seconds before next attempt.
    """
    idx = min(max(0, iteration - 1), len(_STEP_DELAYS) - 1)
    return _STEP_DELAYS[idx]


def stepped_backoff_delay_adaptive(iteration: int, last_status_code: int = 0) -> float:
    """Adaptive backoff: reset to fast delay on progress (2xx), otherwise step up.

    Args:
        iteration: Current iteration (1-indexed).
        last_status_code: HTTP status of most recent attempt (0 if unknown).

    Returns:
        Delay in seconds.
    """
    if last_status_code and last_status_code < 400:
        return _STEP_DELAYS[0]
    return stepped_backoff_delay(iteration)


# --- Error classification (ported from prior deployment's FailoverReason) ---

_RATE_LIMIT_PATTERNS = re.compile(
    r"(rate[_ ]limit|too many requests|429|quota|resource.exhausted|throttl)",
    re.IGNORECASE,
)
_AUTH_PATTERNS = re.compile(
    r"(unauthorized|forbidden|invalid.?api.?key|invalid.?token|"
    r"authentication|access.denied|expired|no.credentials|401|403)",
    re.IGNORECASE,
)
_TIMEOUT_PATTERNS = re.compile(
    r"(timeout|timed.out|deadline.exceeded|ETIMEDOUT|ECONNRESET|ECONNABORTED)",
    re.IGNORECASE,
)


def classify_failure(
    status_code: int = 0,
    error_message: str = "",
) -> FailureReason:
    """Classify an HTTP response or exception into a failure reason.

    Checks status code first (fast path), then falls back to pattern
    matching on error messages for connection-level errors.
    """
    if status_code == 401 or status_code == 403:
        return FailureReason.AUTH_REQUIRED
    if status_code == 429:
        return FailureReason.RATE_LIMITED
    if status_code == 404:
        return FailureReason.NOT_FOUND
    if status_code == 400:
        return FailureReason.FORMAT_ERROR
    if status_code == 408 or status_code == 504:
        return FailureReason.TIMEOUT
    if 500 <= status_code < 600:
        return FailureReason.SERVER_ERROR

    # Pattern-match on error messages (connection-level failures)
    if error_message:
        if _RATE_LIMIT_PATTERNS.search(error_message):
            return FailureReason.RATE_LIMITED
        if _AUTH_PATTERNS.search(error_message):
            return FailureReason.AUTH_REQUIRED
        if _TIMEOUT_PATTERNS.search(error_message):
            return FailureReason.TIMEOUT
        if any(kw in error_message.lower() for kw in (
            "connect", "dns", "resolve", "refused", "unreachable",
        )):
            return FailureReason.CONNECTION_ERROR

    return FailureReason.NONE


# --- Retry with exponential backoff + jitter (ported from prior deployment) ---

_RETRY_ATTEMPTS = 3
_RETRY_MIN_DELAY = 0.3   # seconds
_RETRY_MAX_DELAY = 10.0   # seconds
_RETRY_JITTER = 0.2       # ±20% randomization

_RETRYABLE_REASONS = frozenset({
    FailureReason.TIMEOUT,
    FailureReason.RATE_LIMITED,
    FailureReason.SERVER_ERROR,
    FailureReason.CONNECTION_ERROR,
})


def _is_retryable(exc: Exception) -> bool:
    """Check if an httpx exception is worth retrying."""
    return isinstance(exc, (httpx.TimeoutException, httpx.ConnectError))


async def retry_with_backoff(
    coro_factory,
    *,
    attempts: int = _RETRY_ATTEMPTS,
    min_delay: float = _RETRY_MIN_DELAY,
    max_delay: float = _RETRY_MAX_DELAY,
    jitter: float = _RETRY_JITTER,
):
    """Execute an async callable with exponential backoff + jitter on transient failures.

    Args:
        coro_factory: Zero-arg callable returning an awaitable (called fresh each attempt).
        attempts: Max number of attempts.
        min_delay: Base delay in seconds.
        max_delay: Cap on delay.
        jitter: Random factor (±jitter * delay).

    Returns the result of the first successful call.
    Raises the last exception if all attempts fail.
    """
    import asyncio
    import random

    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            if attempt >= attempts - 1 or not _is_retryable(exc):
                raise
            base_delay = min_delay * (2 ** attempt)
            delay = min(base_delay, max_delay)
            offset = (random.random() * 2 - 1) * jitter  # noqa: S311
            delay = max(0, delay * (1 + offset))
            logger.info(
                "Retrying after %.1fs (attempt %d/%d): %s",
                delay, attempt + 1, attempts, exc,
            )
            await asyncio.sleep(delay)
    raise last_exc  # type: ignore[misc]

_ANALYZE_PROMPT = """Did this HTTP response confirm the vulnerability?

Finding: {title} ({category})
Request: {method} {url}
Status: {status_code}
Response headers: {response_headers}
Response (truncated): {response_snippet}
Expected indicators: {expected_indicators}

Reply with JSON only:
{{"conclusive":true,"reproduced":true,"evidence":"explanation"}}"""


async def execute_and_analyze(
    plan: ProofPlan,
    staging_url: str,
    finding_category: str,
    finding_title: str,
    client: httpx.AsyncClient | None = None,
) -> ExecutionResult:
    """Execute an HTTP probe and analyze the response.

    Uses retry with exponential backoff for transient failures,
    deterministic rule-based analysis first, falling back to LLM
    only when rules don't match.

    Args:
        client: Optional shared httpx.AsyncClient to reuse TCP connections.
    """
    url = staging_url.rstrip("/") + plan.url_path

    async def _do_request() -> httpx.Response:
        _client = client or httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT, follow_redirects=True,
        )
        _managed = client is None
        try:
            if plan.is_multipart and plan.filename:
                file_content = (plan.body or "<?php echo 'test'; ?>").encode()
                files = {"file": (plan.filename, file_content)}
                return await _client.request(
                    method=plan.method,
                    url=url,
                    headers={k: v for k, v in plan.headers.items()
                             if k.lower() != "content-type"},
                    files=files,
                )
            return await _client.request(
                method=plan.method,
                url=url,
                headers=plan.headers,
                content=plan.body if plan.body else None,
            )
        finally:
            if _managed:
                await _client.aclose()

    try:
        response = await retry_with_backoff(_do_request)

        # I: Request body guard — prevent OOM on large responses
        if len(response.content) > _MAX_RESPONSE_BYTES:
            snippet = response.text[:500]
            return ExecutionResult(
                conclusive=False,
                evidence=f"Response too large ({len(response.content)} bytes, limit {_MAX_RESPONSE_BYTES})",
                status_code=response.status_code,
                response_snippet=snippet,
                response_headers=extract_interesting_headers(response),
                failure_reason=FailureReason.PAYLOAD_TOO_LARGE,
            )

        snippet = response.text[:500]
        resp_headers = extract_interesting_headers(response)
        failure = classify_failure(status_code=response.status_code)

        # Phase 1: Deterministic rule-based analysis (always works)
        rule_result = analyze_response(
            status_code=response.status_code,
            headers=resp_headers,
            body=snippet,
            plan_body=plan.body,
            finding_category=finding_category,
            finding_title=finding_title,
            upload_filename=plan.filename if plan.is_multipart else "",
        )
        if rule_result:
            rule_result.status_code = response.status_code
            rule_result.response_snippet = snippet
            rule_result.response_headers = resp_headers
            rule_result.failure_reason = failure
            logger.info("Rule-based analysis: %s", rule_result.evidence)
            return rule_result

        # Phase 2: LLM analysis (may fail with small models)
        llm_result = await llm_json_call(_ANALYZE_PROMPT.format(
            title=plan.description,
            category=finding_category,
            method=plan.method,
            url=url,
            status_code=response.status_code,
            response_headers=json.dumps(resp_headers),
            response_snippet=snippet,
            expected_indicators=json.dumps(plan.expected_indicators),
        ))
        return ExecutionResult(
            conclusive=llm_result.get("conclusive", False),
            reproduced=llm_result.get("reproduced", False),
            evidence=llm_result.get("evidence", f"HTTP {response.status_code}"),
            status_code=response.status_code,
            response_snippet=snippet,
            response_headers=resp_headers,
            failure_reason=failure,
        )
    except httpx.TimeoutException:
        return ExecutionResult(
            conclusive=False, evidence="Request timed out",
            failure_reason=FailureReason.TIMEOUT,
        )
    except httpx.ConnectError as exc:
        return ExecutionResult(
            conclusive=False, evidence=f"Connection failed: {exc}",
            failure_reason=FailureReason.CONNECTION_ERROR,
        )
