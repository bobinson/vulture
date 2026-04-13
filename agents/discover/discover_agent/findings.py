"""Security finding generators for discovered attack surface.

Analyzes the SiteMap produced by discovery plugins to identify
security exposures — missing headers, exposed debug endpoints,
introspection-enabled APIs, directory listings, etc.
"""

from __future__ import annotations

import logging
from typing import Any

from shared.discovery.sitemap import SiteMap

logger = logging.getLogger(__name__)


def analyze_security_exposures(
    site: SiteMap,
    target_url: str,
) -> list[dict[str, Any]]:
    """Analyze discovered site map for security exposures.

    Returns a list of finding dicts ready for AgUiEventEmitter.finding_event().
    """
    findings: list[dict[str, Any]] = []
    findings.extend(_check_missing_security_headers(site))
    findings.extend(_check_exposed_debug_endpoints(site))
    findings.extend(_check_graphql_introspection(site, target_url))
    findings.extend(_check_server_version_disclosure(site))
    findings.extend(_check_directory_listing_risk(site, target_url))
    findings.extend(_check_sensitive_file_exposure(site, target_url))

    # Deduplicate by title
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        title = f.get("title", "")
        if title not in seen:
            seen.add(title)
            unique.append(f)
    return unique


def _check_missing_security_headers(site: SiteMap) -> list[dict[str, Any]]:
    """Check for missing HTTP security headers."""
    findings: list[dict[str, Any]] = []
    headers_lower = {k.lower(): v for k, v in site.headers.items()}

    required_headers = {
        "strict-transport-security": (
            "high",
            "Missing HSTS Header",
            "The server does not set Strict-Transport-Security, allowing downgrade attacks.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        ),
        "x-content-type-options": (
            "medium",
            "Missing X-Content-Type-Options Header",
            "The server does not set X-Content-Type-Options, enabling MIME-type sniffing.",
            "Add 'X-Content-Type-Options: nosniff' header.",
        ),
        "x-frame-options": (
            "medium",
            "Missing X-Frame-Options Header",
            "The server does not set X-Frame-Options, potentially enabling clickjacking.",
            "Add 'X-Frame-Options: DENY' or use Content-Security-Policy frame-ancestors.",
        ),
        "content-security-policy": (
            "medium",
            "Missing Content-Security-Policy Header",
            "No CSP header detected, increasing risk of XSS and data injection attacks.",
            "Implement a strict Content-Security-Policy header.",
        ),
    }

    for header, (severity, title, description, recommendation) in required_headers.items():
        if header not in headers_lower:
            findings.append({
                "severity": severity,
                "category": "security-headers",
                "title": title,
                "description": description,
                "recommendation": recommendation,
            })
    return findings


def _check_exposed_debug_endpoints(site: SiteMap) -> list[dict[str, Any]]:
    """Check for debug/admin endpoints that should not be publicly accessible."""
    findings: list[dict[str, Any]] = []
    debug_patterns = [
        "/debug", "/_debug", "/api/debug", "/admin", "/_admin",
        "/phpinfo", "/server-status", "/server-info",
        "/.env", "/config", "/api/config",
        "/actuator", "/metrics", "/api/metrics",
        "/swagger", "/api-docs", "/graphql-playground",
    ]

    for ep in site.api_endpoints:
        ep_lower = ep.lower()
        for pattern in debug_patterns:
            if ep_lower == pattern or ep_lower.startswith(pattern + "/"):
                findings.append({
                    "severity": "high",
                    "category": "exposed-endpoint",
                    "title": f"Exposed Debug/Admin Endpoint: {ep}",
                    "description": (
                        f"The endpoint {ep} appears to be a debug or admin endpoint "
                        "that should not be publicly accessible."
                    ),
                    "recommendation": (
                        "Restrict access to this endpoint via authentication "
                        "or remove it from production."
                    ),
                })
                break
    return findings


def _check_graphql_introspection(
    site: SiteMap, target_url: str = "",
) -> list[dict[str, Any]]:
    """Check if GraphQL introspection is actually enabled.

    Only reports a finding when introspection responds with schema data,
    not merely because a /graphql endpoint exists.
    """
    import httpx

    findings: list[dict[str, Any]] = []
    graphql_eps = [ep for ep in site.api_endpoints if "graphql" in ep.lower()]
    if not graphql_eps or not target_url:
        return findings

    base = target_url.rstrip("/")
    introspection_query = '{"query":"{ __schema { queryType { name } } }"}'

    try:
        with httpx.Client(timeout=5.0) as client:
            for ep in graphql_eps[:3]:
                url = base + ep if ep.startswith("/") else base + "/" + ep
                try:
                    resp = client.post(
                        url,
                        content=introspection_query,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    schema = data.get("data", {}).get("__schema")
                    if schema:
                        findings.append({
                            "severity": "medium",
                            "category": "graphql-exposure",
                            "title": f"GraphQL Introspection Enabled: {ep}",
                            "description": (
                                f"GraphQL endpoint {ep} has introspection enabled. "
                                "Attackers can enumerate the entire schema."
                            ),
                            "recommendation": (
                                "Disable GraphQL introspection in production. "
                                "Use query complexity limits and depth limiting."
                            ),
                        })
                        break  # One finding is enough
                except Exception:
                    continue
    except Exception as exc:
        logger.warning("GraphQL introspection check failed: %s", exc)

    return findings


def _check_server_version_disclosure(site: SiteMap) -> list[dict[str, Any]]:
    """Check if server version is disclosed in headers."""
    findings: list[dict[str, Any]] = []
    headers_lower = {k.lower(): v for k, v in site.headers.items()}

    server = headers_lower.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "severity": "low",
            "category": "information-disclosure",
            "title": f"Server Version Disclosed: {server}",
            "description": (
                f"The Server header reveals version information: '{server}'. "
                "This helps attackers identify known vulnerabilities."
            ),
            "recommendation": "Remove or obscure the Server header version information.",
        })

    x_powered = headers_lower.get("x-powered-by", "")
    if x_powered:
        findings.append({
            "severity": "low",
            "category": "information-disclosure",
            "title": f"X-Powered-By Header Disclosed: {x_powered}",
            "description": (
                f"The X-Powered-By header reveals: '{x_powered}'. "
                "This helps attackers fingerprint the technology stack."
            ),
            "recommendation": "Remove the X-Powered-By header.",
        })
    return findings


def _check_directory_listing_risk(
    site: SiteMap, target_url: str = "",
) -> list[dict[str, Any]]:
    """Verify directory listing by probing a sample of directory-style paths."""
    import httpx

    findings: list[dict[str, Any]] = []
    listing_indicators = [
        ep for ep in site.urls
        if ep.endswith("/") and ep.count("/") >= 2 and ep not in ("/", "//")
    ]
    if len(listing_indicators) <= 10 or not target_url:
        return findings

    # Probe a sample to verify actual directory listing
    base = target_url.rstrip("/")
    listing_sigs = ("index of", "directory listing", "<pre>", "parent directory")
    confirmed = 0
    try:
        with httpx.Client(
            timeout=5.0,
            headers={"User-Agent": "Vulture-Discover/1.0"},
        ) as client:
            for path in listing_indicators[:5]:
                try:
                    resp = client.get(base + path, follow_redirects=True)
                    if resp.status_code != 200:
                        continue
                    body = resp.text[:2000].lower()
                    if any(sig in body for sig in listing_sigs):
                        confirmed += 1
                except httpx.HTTPError:
                    continue
    except Exception as exc:
        logger.warning("Directory listing check failed: %s", exc)

    if confirmed > 0:
        findings.append({
            "severity": "medium",
            "category": "directory-listing",
            "title": "Directory Listing Enabled",
            "description": (
                f"Confirmed directory listing on {confirmed} of "
                f"{min(len(listing_indicators), 5)} sampled paths. "
                "Internal file structure is exposed."
            ),
            "recommendation": "Disable directory listing in the web server configuration.",
        })
    return findings


def _check_sensitive_file_exposure(
    site: SiteMap,
    target_url: str,
) -> list[dict[str, Any]]:
    """Check for sensitive files that are actually accessible (HTTP 200).

    Only reports findings for paths that return a 200 response with content,
    eliminating false positives from redirects or 404s.
    """
    import httpx

    findings: list[dict[str, Any]] = []
    sensitive_patterns = {
        ".env": ("critical", "Environment File Exposed"),
        ".git": ("critical", "Git Repository Exposed"),
        "wp-config.php": ("critical", "WordPress Config Exposed"),
        ".htaccess": ("high", "htaccess File Exposed"),
        "web.config": ("high", "Web.config File Exposed"),
        "composer.json": ("medium", "Composer Config Exposed"),
        "package.json": ("low", "Package.json Exposed"),
    }

    # Collect candidate paths from the SiteMap
    all_paths = set(site.urls) | set(site.api_endpoints)
    candidates: list[tuple[str, str, str]] = []  # (path, severity, title)
    for path in all_paths:
        basename = path.rstrip("/").rsplit("/", 1)[-1].lower()
        if basename in sensitive_patterns:
            severity, title = sensitive_patterns[basename]
            candidates.append((path, severity, title))

    if not candidates:
        return findings

    # Verify each candidate with an actual HTTP request
    base = target_url.rstrip("/")
    try:
        with httpx.Client(
            timeout=5.0,
            follow_redirects=True,
            headers={"User-Agent": "Vulture-Discover/1.0"},
        ) as client:
            for path, severity, title in candidates:
                url = base + path if path.startswith("/") else base + "/" + path
                try:
                    resp = client.get(url)
                    if resp.status_code != 200:
                        continue
                    # Must have non-trivial content (not an empty page or error page)
                    body = resp.text[:500].lower()
                    if len(resp.content) < 5:
                        continue
                    # HTML error pages are not real file exposures
                    if "<!doctype" in body or "<html" in body:
                        continue
                    findings.append({
                        "severity": severity,
                        "category": "sensitive-file",
                        "title": f"{title}: {path}",
                        "description": (
                            f"The file at {path} is publicly accessible and returned "
                            f"{len(resp.content)} bytes of content. "
                            "It may contain credentials, configuration, or internal structure."
                        ),
                        "recommendation": (
                            "Block access to this file in the web server configuration."
                        ),
                    })
                except httpx.HTTPError:
                    continue
    except Exception as exc:
        logger.warning("Sensitive file verification failed: %s", exc)

    return findings
