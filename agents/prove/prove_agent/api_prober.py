"""API endpoint security prober — parallel, comprehensive, self-learning.

Extends the prove agent beyond scanner findings: for each discovered API
endpoint, runs targeted security probes concurrently and reports issues.

Probe categories:
  1. Auth bypass — unauthenticated access to protected endpoints
  2. Information disclosure — config/status/debug endpoints leaking data
  3. CORS misconfiguration — arbitrary origin reflection
  4. CSRF protection — forms accepting requests without tokens
  5. HTTP method tampering — destructive methods on read-only endpoints
  6. GraphQL security — introspection, query complexity, mutation auth
  7. Header injection — missing security headers, host header injection
  8. Open redirect — redirect parameters accepting external URLs
  9. Rate limit — brute-force protection on auth endpoints
  10. JWT analysis — weak signing, missing expiry, exposed claims
"""

import asyncio
import logging
import re

import httpx

from prove_agent.learning_store import (
    SessionLearnings,
    record_endpoint_behavior,
    record_successful_probe,
)
from prove_agent.strategies.rule_analyzer import analyze_response
from prove_agent.strategies.shared import extract_interesting_headers

logger = logging.getLogger(__name__)

_TIMEOUT = 8.0
_MAX_CONCURRENT = 10


async def probe_api_endpoints(
    staging_url: str,
    api_endpoints: list[str],
    forms: list[dict],
    learnings: SessionLearnings | None = None,
) -> list[dict]:
    """Probe discovered API endpoints for security issues (parallel).

    Returns a list of findings dicts (same format as scanner findings).
    """
    base = staging_url.rstrip("/")
    findings: list[dict] = []
    _learnings = learnings or SessionLearnings()

    async with httpx.AsyncClient(
        timeout=_TIMEOUT, follow_redirects=True,
    ) as client:
        # Run all probe categories in parallel
        probe_tasks = [
            _probe_auth_bypass(client, base, api_endpoints, _learnings),
            _probe_info_disclosure(client, base, api_endpoints, _learnings),
            _probe_cors(client, base, api_endpoints),
            _probe_csrf(client, base, forms),
            _probe_method_tampering(client, base, api_endpoints),
            _probe_graphql(client, base, api_endpoints, _learnings),
            _probe_security_headers(client, base, api_endpoints),
            _probe_open_redirect(client, base, api_endpoints),
            _probe_rate_limit(client, base, api_endpoints),
            _probe_jwt(client, base, api_endpoints),
        ]
        results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.warning("Probe failed: %s", result)

    return findings


def _make_finding(
    probe_id: str, title: str, severity: str, category: str,
    file_path: str, evidence: str,
) -> dict:
    """Create a standardized finding dict."""
    return {
        "id": f"api-{probe_id}",
        "title": title,
        "severity": severity,
        "category": category,
        "agent_type": "owasp",
        "file_path": file_path,
        "evidence": evidence,
        "status": "verified",
    }


# --- 1. Auth Bypass ---

async def _probe_auth_bypass(
    client: httpx.AsyncClient, base: str,
    endpoints: list[str], learnings: SessionLearnings,
) -> list[dict]:
    """Test if protected endpoints return data without authentication."""
    auth_required = [
        ep for ep in endpoints
        if any(kw in ep.lower() for kw in (
            "/users", "/profile", "/admin", "/settings",
            "/account", "/dashboard", "/config", "/me",
        ))
        and "/auth/" not in ep.lower()
    ]

    async def _check(ep: str) -> dict | None:
        try:
            resp = await client.get(
                f"{base}{ep}",
                headers={"Accept": "application/json"},
            )
            ct = resp.headers.get("content-type", "")
            if resp.status_code == 200 and "json" in ct:
                body = resp.text[:500]
                if len(body) > 20 and '"error"' not in body.lower():
                    record_endpoint_behavior(
                        learnings, ep, auth_required=False,
                        vulnerability="auth_bypass",
                    )
                    record_successful_probe(
                        learnings, "auth_bypass", "GET", ep,
                    )
                    return _make_finding(
                        f"auth-bypass-{ep.replace('/', '-')}",
                        f"Unauthenticated access to {ep}",
                        "HIGH", "auth_bypass", ep,
                        f"GET {ep} returned {resp.status_code} with JSON data without auth",
                    )
            elif resp.status_code in (401, 403):
                record_endpoint_behavior(learnings, ep, auth_required=True)
        except Exception:
            pass
        return None

    tasks = [_check(ep) for ep in auth_required[:_MAX_CONCURRENT]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


# --- 2. Information Disclosure ---

async def _probe_info_disclosure(
    client: httpx.AsyncClient, base: str,
    endpoints: list[str], learnings: SessionLearnings,
) -> list[dict]:
    sensitive = [
        ep for ep in endpoints
        if any(kw in ep.lower() for kw in (
            "/config", "/status", "/health", "firebase",
            "/env", "/debug", "/.env", "/info", "/metrics",
        ))
    ]

    async def _check(ep: str) -> dict | None:
        try:
            resp = await client.get(f"{base}{ep}")
            if resp.status_code != 200:
                return None
            body = resp.text[:1000]
            rule_result = analyze_response(
                status_code=resp.status_code,
                headers=extract_interesting_headers(resp),
                body=body, plan_body="",
                finding_category="OWASP",
                finding_title=f"Information disclosure check on {ep}",
            )
            if rule_result and rule_result.reproduced:
                record_endpoint_behavior(
                    learnings, ep, vulnerability="info_disclosure",
                )
                return _make_finding(
                    f"info-disclosure-{ep.replace('/', '-')}",
                    f"Information disclosure at {ep}",
                    "MEDIUM", "info_disclosure", ep, rule_result.evidence,
                )
        except Exception:
            pass
        return None

    tasks = [_check(ep) for ep in sensitive[:_MAX_CONCURRENT]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


# --- 3. CORS ---

async def _probe_cors(
    client: httpx.AsyncClient, base: str, endpoints: list[str],
) -> list[dict]:
    api_eps = [ep for ep in endpoints if ep.startswith("/api/")][:5]
    sem = asyncio.Semaphore(5)

    async def _check_ep(ep: str) -> dict | None:
        async with sem:
            try:
                resp = await client.options(
                    f"{base}{ep}",
                    headers={
                        "Origin": "https://evil.attacker.com",
                        "Access-Control-Request-Method": "POST",
                    },
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                if acao == "*" or acao == "https://evil.attacker.com":
                    return _make_finding(
                        f"cors-{ep.replace('/', '-')}",
                        f"CORS misconfiguration at {ep}",
                        "MEDIUM", "cors_misconfiguration", ep,
                        f"Access-Control-Allow-Origin: {acao} reflects arbitrary origin",
                    )
            except Exception:
                pass
        return None

    results = await asyncio.gather(*[_check_ep(ep) for ep in api_eps])
    return [r for r in results if r is not None][:1]


# --- 4. CSRF ---

async def _probe_csrf(
    client: httpx.AsyncClient, base: str, forms: list[dict],
) -> list[dict]:
    findings = []
    post_forms = [f for f in forms if f.get("method", "").upper() == "POST"]
    for form in post_forms[:5]:
        action = form.get("action", "")
        if not action.startswith("/"):
            continue
        inputs = form.get("inputs", [])
        if any("csrf" in inp.lower() or "token" in inp.lower() for inp in inputs):
            continue
        try:
            resp = await client.post(
                f"{base}{action}",
                data={inp: "test" for inp in inputs if "csrf" not in inp.lower()},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code not in (401, 403, 405):
                findings.append(_make_finding(
                    f"csrf-{action.replace('/', '-')}",
                    f"Missing CSRF protection on {action}",
                    "MEDIUM", "csrf_missing", action,
                    f"POST {action} accepted without CSRF token (HTTP {resp.status_code})",
                ))
        except Exception:
            pass
    return findings


# --- 5. HTTP Method Tampering ---

async def _probe_method_tampering(
    client: httpx.AsyncClient, base: str, endpoints: list[str],
) -> list[dict]:
    readonly_eps = [
        ep for ep in endpoints
        if ep.startswith("/api/") and "auth" not in ep.lower()
    ][:5]

    async def _check(ep: str) -> dict | None:
        try:
            resp = await client.delete(f"{base}{ep}")
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                return _make_finding(
                    f"method-{ep.replace('/', '-')}",
                    f"Unprotected DELETE method on {ep}",
                    "HIGH", "method_tampering", ep,
                    f"DELETE {ep} returned 200 OK — destructive method unprotected",
                )
        except Exception:
            pass
        return None

    tasks = [_check(ep) for ep in readonly_eps]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


# --- 6. GraphQL Security ---

async def _probe_graphql(
    client: httpx.AsyncClient, base: str,
    endpoints: list[str], learnings: SessionLearnings,
) -> list[dict]:
    """Test GraphQL endpoints for introspection, complexity, and auth issues."""
    findings = []
    gql_eps = [ep for ep in endpoints if "graphql" in ep.lower() or "gql" in ep.lower()]

    for ep in gql_eps[:3]:
        url = f"{base}{ep}"

        # Test 1: Introspection enabled (information disclosure)
        try:
            resp = await client.post(
                url,
                json={"query": "{ __schema { types { name kind } } }"},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    types = data["data"]["__schema"].get("types", [])
                    user_types = [t["name"] for t in types if not t["name"].startswith("__")]
                    findings.append(_make_finding(
                        f"gql-introspection-{ep.replace('/', '-')}",
                        f"GraphQL introspection enabled at {ep}",
                        "MEDIUM", "info_disclosure", ep,
                        f"Introspection reveals {len(user_types)} types: {', '.join(user_types[:10])}",
                    ))
                    record_endpoint_behavior(
                        learnings, ep, vulnerability="graphql_introspection",
                    )
        except Exception:
            pass

        # Test 2: Query complexity / DoS via nested queries
        try:
            nested = '{ __typename ' + ''.join([f'a{i}: __typename ' for i in range(100)]) + '}'
            resp = await client.post(
                url, json={"query": nested},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                # Server accepted highly complex query — no complexity limits
                findings.append(_make_finding(
                    f"gql-complexity-{ep.replace('/', '-')}",
                    f"No query complexity limit at {ep}",
                    "LOW", "dos_vulnerability", ep,
                    "GraphQL accepted query with 100 fields without rate limiting",
                ))
        except Exception:
            pass

        # Test 3: Mutation without auth
        try:
            resp = await client.post(
                url,
                json={"query": "mutation { __typename }"},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 and "errors" not in resp.json():
                findings.append(_make_finding(
                    f"gql-mutation-auth-{ep.replace('/', '-')}",
                    f"GraphQL mutations accessible without auth at {ep}",
                    "HIGH", "auth_bypass", ep,
                    "Mutation endpoint accessible without authentication",
                ))
        except Exception:
            pass

    return findings


# --- 7. Security Headers ---

async def _probe_security_headers(
    client: httpx.AsyncClient, base: str, endpoints: list[str],
) -> list[dict]:
    """Check for missing security headers on API responses."""
    # Test a few representative endpoints
    test_eps = endpoints[:3] if endpoints else ["/"]
    findings = []

    for ep in test_eps:
        try:
            resp = await client.get(f"{base}{ep}")
            headers = {k.lower(): v for k, v in resp.headers.items()}

            missing = []
            if "strict-transport-security" not in headers:
                missing.append("HSTS")
            if "x-content-type-options" not in headers:
                missing.append("X-Content-Type-Options")
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                missing.append("X-Frame-Options/CSP")

            # Check for server version disclosure
            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")
            version_leak = []
            if re.search(r"\d+\.\d+", server):
                version_leak.append(f"Server: {server}")
            if powered_by:
                version_leak.append(f"X-Powered-By: {powered_by}")

            if missing and len(missing) >= 2:
                findings.append(_make_finding(
                    f"headers-{ep.replace('/', '-')}",
                    f"Missing security headers on {ep}",
                    "LOW", "security_misconfig", ep,
                    f"Missing: {', '.join(missing)}",
                ))

            if version_leak:
                findings.append(_make_finding(
                    f"version-leak-{ep.replace('/', '-')}",
                    f"Server version disclosure on {ep}",
                    "LOW", "info_disclosure", ep,
                    f"Version leaked: {'; '.join(version_leak)}",
                ))
            break  # One endpoint check is enough for headers
        except Exception:
            pass

    return findings


# --- 8. Open Redirect ---

async def _probe_open_redirect(
    client: httpx.AsyncClient, base: str, endpoints: list[str],
) -> list[dict]:
    """Test for open redirect vulnerabilities in auth/redirect endpoints."""
    redirect_eps = [
        ep for ep in endpoints
        if any(kw in ep.lower() for kw in (
            "/login", "/auth", "/callback", "/redirect", "/return",
            "/signin", "/signout", "/logout",
        ))
    ]
    sem = asyncio.Semaphore(5)

    async def _check_ep_param(ep: str, param: str) -> dict | None:
        async with sem:
            try:
                resp = await client.get(
                    f"{base}{ep}",
                    params={param: "https://evil.attacker.com"},
                    follow_redirects=False,
                )
                location = resp.headers.get("location", "")
                if "evil.attacker.com" in location:
                    return _make_finding(
                        f"redirect-{ep.replace('/', '-')}",
                        f"Open redirect at {ep}",
                        "MEDIUM", "open_redirect", ep,
                        f"GET {ep}?{param}=https://evil.attacker.com redirects to {location[:100]}",
                    )
            except Exception:
                pass
        return None

    params = ["redirect", "return_to", "next", "url", "callback", "redirect_uri"]
    tasks = [_check_ep_param(ep, p) for ep in redirect_eps[:5] for p in params]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None][:1]


# --- 9. Rate Limit ---

async def _probe_rate_limit(
    client: httpx.AsyncClient, base: str, endpoints: list[str],
) -> list[dict]:
    """Test if auth endpoints have rate limiting."""
    auth_eps = [
        ep for ep in endpoints
        if any(kw in ep.lower() for kw in ("/login", "/signin", "/auth/callback"))
    ]

    for ep in auth_eps[:2]:
        try:
            # Send 5 rapid requests
            responses = await asyncio.gather(*[
                client.post(
                    f"{base}{ep}",
                    json={"username": "test", "password": "wrong"},
                    headers={"Content-Type": "application/json"},
                )
                for _ in range(5)
            ], return_exceptions=True)

            valid = [r for r in responses if isinstance(r, httpx.Response)]
            if len(valid) >= 5:
                # Check if any response indicates rate limiting
                rate_limited = any(
                    r.status_code == 429
                    or "rate" in r.headers.get("x-ratelimit-remaining", "").lower()
                    or "retry-after" in r.headers
                    for r in valid
                )
                if not rate_limited:
                    return [_make_finding(
                        f"rate-limit-{ep.replace('/', '-')}",
                        f"No rate limiting on {ep}",
                        "MEDIUM", "brute_force", ep,
                        f"5 rapid POST requests to {ep} accepted without rate limiting",
                    )]
        except Exception:
            pass
    return []


# --- 10. JWT Analysis ---

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


async def _probe_jwt(
    client: httpx.AsyncClient, base: str, endpoints: list[str],
) -> list[dict]:
    """Check for JWT tokens in responses and analyze them."""
    findings = []
    auth_eps = [
        ep for ep in endpoints
        if any(kw in ep.lower() for kw in ("/auth/", "/session", "/token", "/login"))
    ]

    for ep in auth_eps[:3]:
        try:
            resp = await client.get(f"{base}{ep}")
            body = resp.text[:2000]

            # Look for JWT in response body or cookies
            jwt_match = _JWT_RE.search(body)
            if not jwt_match:
                cookies = resp.headers.get("set-cookie", "")
                jwt_match = _JWT_RE.search(cookies)

            if jwt_match:
                token = jwt_match.group()
                # Decode header (base64url) to check algorithm
                import base64
                header_b64 = token.split(".")[0]
                # Add padding
                padding = 4 - len(header_b64) % 4
                header_b64 += "=" * padding
                try:
                    import json
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    alg = header.get("alg", "")

                    if alg == "none":
                        findings.append(_make_finding(
                            f"jwt-none-{ep.replace('/', '-')}",
                            f"JWT with 'none' algorithm at {ep}",
                            "CRITICAL", "crypto_failure", ep,
                            "JWT token uses 'none' algorithm — signature bypass",
                        ))
                    elif alg in ("HS256", "HS384", "HS512"):
                        findings.append(_make_finding(
                            f"jwt-symmetric-{ep.replace('/', '-')}",
                            f"JWT uses symmetric signing ({alg}) at {ep}",
                            "LOW", "crypto_weakness", ep,
                            f"JWT uses {alg} — vulnerable to brute-force if secret is weak",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    return findings
