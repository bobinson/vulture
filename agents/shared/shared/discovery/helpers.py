"""Discovery helpers — HTML extraction, URL filtering, and common paths."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from shared.discovery.sitemap import SiteMap

# Paths to probe for additional discovery
COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api/docs",
    "/docs",
    "/api",
    "/api/v1",
    "/graphql",
    "/.env",
    "/config",
    "/health",
    "/status",
    "/version",
    "/login",
    "/admin",
    "/register",
    "/signup",
    "/dashboard",
    "/settings",
    "/profile",
    "/api/users",
    "/api/auth",
    "/api/config",
    "/api/health",
    "/api/status",
    "/api/auth/session",
    "/api/auth/providers",
    "/api/auth/csrf",
    "/api/auth/signin",
    "/api/auth/callback",
    "/api/auth/signout",
    "/wp-admin",
    "/wp-login.php",
    "/wp-json/wp/v2/users",
    "/_debug",
    "/debug",
    "/phpinfo.php",
    "/server-info",
    "/server-status",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/package.json",
    "/composer.json",
    "/_next/data",
    "/404",
    "/500",
]


STATIC_EXTENSIONS = frozenset({
    ".js", ".mjs", ".cjs", ".jsx", ".tsx", ".ts",
    ".css", ".scss", ".less", ".sass",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".json.map", ".js.map", ".css.map",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".tar", ".gz",
})

STATIC_PATH_RE = re.compile(
    r"(_next/static|_next/data|_next/image|__next|/static/|/assets/|/public/|"
    r"/node_modules/|\.chunk\.|\.bundle\.|buildManifest|ssgManifest|"
    r"_buildManifest|_ssgManifest|webpack|favicon|manifest\.json|"
    r"workbox-|sw\.js|service-worker)",
    re.IGNORECASE,
)

PAGE_PATHS = frozenset({
    "/login", "/register", "/signup", "/dashboard", "/settings",
    "/profile", "/admin", "/discover", "/home", "/about",
    "/contact", "/help", "/faq", "/pricing", "/terms", "/privacy",
})


def is_static_path(path: str) -> bool:
    """Check if a path looks like a static asset (not an API endpoint)."""
    lower = path.lower()
    for ext in STATIC_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return bool(STATIC_PATH_RE.search(lower))


def is_page_path(path: str) -> bool:
    """Check if a path is an HTML page, not a real API endpoint."""
    lower = path.lower().rstrip("/")
    if lower in PAGE_PATHS:
        return True
    for page in PAGE_PATHS:
        if lower.startswith(page + "/") and "/api/" not in lower:
            return True
    return False


def filter_static_endpoints(site: SiteMap) -> None:
    """Remove static files and HTML pages from api_endpoints list."""
    site.api_endpoints = [
        ep for ep in site.api_endpoints
        if not is_static_path(ep) and not is_page_path(ep)
    ]


# --- HTML extraction helpers ---

_HREF_RE = re.compile(r'href=["\']([^"\'#]+)', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\'#]+)', re.IGNORECASE)
_ACTION_RE = re.compile(
    r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>",
    re.IGNORECASE | re.DOTALL,
)
_METHOD_RE = re.compile(
    r"<form[^>]*method=[\"']([^\"']*)[\"'][^>]*>",
    re.IGNORECASE | re.DOTALL,
)
_INPUT_RE = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*/?>',
    re.IGNORECASE,
)


def extract_links(html: str, base: str, site: SiteMap) -> None:
    """Extract href and src links from HTML, filtering to same-origin."""
    base_host = urlparse(base).hostname
    for match in _HREF_RE.finditer(html):
        url = match.group(1)
        resolved = urljoin(base + "/", url)
        parsed = urlparse(resolved)
        if parsed.hostname == base_host and parsed.path:
            path = parsed.path
            if not is_static_path(path):
                site.urls.append(path)
            if any(seg in path.lower() for seg in ("/api/", "/v1/", "/v2/", "/graphql")):
                site.api_endpoints.append(path)
    for match in _SRC_RE.finditer(html):
        url = match.group(1)
        resolved = urljoin(base + "/", url)
        parsed = urlparse(resolved)
        if parsed.hostname == base_host and parsed.path:
            site.urls.append(parsed.path)


def extract_forms(html: str, base: str, site: SiteMap) -> None:
    """Extract form actions and input names from HTML."""
    form_starts = [m.start() for m in re.finditer(r"<form", html, re.IGNORECASE)]
    for start in form_starts:
        chunk = html[start:start + 2000]
        action_m = _ACTION_RE.search(chunk)
        method_m = _METHOD_RE.search(chunk)
        action = action_m.group(1) if action_m else "/"
        method = method_m.group(1).upper() if method_m else "GET"

        if not action.startswith("http"):
            action = urlparse(urljoin(base + "/", action)).path

        inputs = _INPUT_RE.findall(chunk)

        site.forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })
        site.urls.append(action)


def _resolve_headers(headers_or_resp: object) -> dict[str, str]:
    """Accept either a dict-like headers object or an httpx Response."""
    if hasattr(headers_or_resp, "headers"):
        return headers_or_resp.headers  # type: ignore[return-value]
    return headers_or_resp  # type: ignore[return-value]


def extract_headers(headers_or_resp: object, site: SiteMap) -> None:
    """Extract security-relevant response headers.

    Accepts either a headers dict or an httpx Response object.
    """
    headers = _resolve_headers(headers_or_resp)
    interesting = [
        "server", "x-powered-by", "x-frame-options",
        "content-security-policy", "strict-transport-security",
        "x-content-type-options", "access-control-allow-origin",
        "set-cookie", "www-authenticate",
    ]
    for header in interesting:
        val = headers.get(header)
        if val:
            site.headers[header] = val


def extract_technologies(headers_or_resp: object, body: str, site: SiteMap) -> None:
    """Detect technologies from response headers and content.

    Accepts either a headers dict or an httpx Response object.
    """
    headers = _resolve_headers(headers_or_resp)
    server = headers.get("server", "")
    if server:
        site.technologies.append(f"Server: {server}")
    powered = headers.get("x-powered-by", "")
    if powered:
        site.technologies.append(f"X-Powered-By: {powered}")

    body_lower = body[:3000].lower()
    tech_signals = {
        "react": "react",
        "next.js": "next",
        "vue": "vue",
        "angular": "angular",
        "django": "django",
        "flask": "flask",
        "laravel": "laravel",
        "express": "express",
        "wordpress": "wp-content",
        "rails": "rails",
        "spring": "spring",
    }
    for tech, signal in tech_signals.items():
        if signal in body_lower:
            site.technologies.append(tech)


def extract_json_urls(text: str, base: str, site: SiteMap) -> None:
    """Extract URL paths from JSON API responses."""
    import json as _json
    base_host = urlparse(base).hostname
    try:
        data = _json.loads(text)
    except (_json.JSONDecodeError, ValueError):
        return
    walk_json_for_urls(data, base_host, site)


_MAX_JSON_DEPTH = 20


def walk_json_for_urls(
    obj: object, base_host: str, site: SiteMap, _depth: int = 0,
) -> None:
    """Recursively walk JSON to find URL strings (depth-limited)."""
    if _depth > _MAX_JSON_DEPTH:
        return
    if isinstance(obj, str):
        if obj.startswith("http"):
            parsed = urlparse(obj)
            if parsed.hostname == base_host and parsed.path:
                path = parsed.path
                if not is_static_path(path):
                    site.urls.append(path)
                if "/api/" in path or "/v1/" in path or "/v2/" in path:
                    site.api_endpoints.append(path)
        elif obj.startswith("/") and len(obj) > 1:
            if not is_static_path(obj):
                site.urls.append(obj)
            if "/api/" in obj or "/v1/" in obj or "/v2/" in obj:
                site.api_endpoints.append(obj)
    elif isinstance(obj, dict):
        for val in obj.values():
            walk_json_for_urls(val, base_host, site, _depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            walk_json_for_urls(item, base_host, site, _depth + 1)
