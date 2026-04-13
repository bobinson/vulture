"""Playwright-based deep discovery — intercept real API calls by browsing.

Uses headless Chromium to load pages, intercept XHR/fetch/WebSocket
traffic, submit forms, and detect GraphQL, REST, OpenAPI, RPC endpoints.
Static assets (JS, CSS, images, fonts) are filtered out.
"""

import asyncio
import logging
import re
from urllib.parse import urlparse

from shared.discovery.sitemap import SiteMap

logger = logging.getLogger(__name__)

_TIMEOUT_MS = 10_000  # per-page timeout
_NAVIGATION_TIMEOUT_MS = 15_000
_MAX_PAGES = 15  # limit total pages to keep discovery under 3 minutes

# File extensions that are never API endpoints
_STATIC_EXTENSIONS = frozenset({
    ".js", ".mjs", ".cjs", ".jsx", ".tsx", ".ts",
    ".css", ".scss", ".less", ".sass",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".json.map", ".js.map", ".css.map",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".tar", ".gz",
})

# Path patterns that indicate static assets (not API endpoints)
_STATIC_PATH_PATTERNS = re.compile(
    r"(_next/static|_next/data|_next/image|__next|/static/|/assets/|/public/|"
    r"/node_modules/|\.chunk\.|\.bundle\.|buildManifest|ssgManifest|"
    r"_buildManifest|_ssgManifest|webpack|favicon|manifest\.json|"
    r"workbox-|sw\.js|service-worker)",
    re.IGNORECASE,
)

# Patterns that strongly indicate an API endpoint
_API_PATTERNS = re.compile(
    r"(/api/|/v[0-9]+/|/graphql|/rest/|/rpc/|/ws/|/webhook|"
    r"/auth/|/login|/logout|/register|/signup|/session|"
    r"/users|/account|/profile|/settings|/admin|"
    r"/search|/upload|/download|/export|/import|"
    r"/cart|/checkout|/order|/payment|"
    r"/token|/oauth|/callback|/csrf)",
    re.IGNORECASE,
)


def _is_static_asset(url: str) -> bool:
    """Return True if the URL is a static asset, not an API endpoint."""
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Check file extension
    for ext in _STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True

    # Check known static path patterns
    if _STATIC_PATH_PATTERNS.search(path):
        return True

    return False


def _is_api_like(url: str, method: str, content_type: str) -> bool:
    """Return True if the request looks like an API call."""
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Non-GET methods are almost always API calls
    if method.upper() != "GET":
        return True

    # Check for API-like path patterns
    if _API_PATTERNS.search(path):
        return True

    # JSON responses are typically API endpoints
    if "json" in content_type.lower():
        return True

    return False


def _classify_endpoint(url: str, method: str, content_type: str, post_data: str | None) -> str:
    """Classify an endpoint type: graphql, rest, websocket, rpc, form, or page."""
    path = urlparse(url).path.lower()

    if "graphql" in path or (post_data and '"query"' in post_data):
        return "graphql"
    if "ws://" in url or "wss://" in url:
        return "websocket"
    if "/rpc" in path or (post_data and '"jsonrpc"' in post_data):
        return "rpc"
    if method.upper() == "POST" and "form" in content_type.lower():
        return "form"
    if _API_PATTERNS.search(path) or "json" in content_type.lower():
        return "rest"
    return "page"


async def deep_discover(staging_url: str, seed_paths: list[str] | None = None) -> SiteMap:
    """Use Playwright to browse the site and intercept real API calls.

    Args:
        staging_url: Base URL of the staging environment.
        seed_paths: Optional list of paths to visit (from prior discovery).

    Returns:
        SiteMap with discovered API endpoints, forms, and URLs.
    """
    site = SiteMap()
    base = staging_url.rstrip("/")
    base_host = urlparse(base).hostname
    intercepted: dict[str, dict] = {}  # path -> {method, content_type, type}
    ws_urls: list[str] = []

    # Pages to visit: homepage + common pages + seed paths (limited)
    pages_to_visit = ["/"]
    pages_to_visit.extend([
        "/login", "/register", "/dashboard",
        "/settings", "/admin",
    ])
    if seed_paths:
        pages_to_visit.extend(seed_paths[:10])
    # Deduplicate while preserving order, cap total
    seen_pages: set[str] = set()
    unique_pages: list[str] = []
    for p in pages_to_visit:
        if p not in seen_pages:
            seen_pages.add(p)
            unique_pages.append(p)
    pages_to_visit = unique_pages[:_MAX_PAGES]

    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Vulture Security Scanner) Chromium/Headless",
            ignore_https_errors=True,
        )
        context.set_default_timeout(_TIMEOUT_MS)
        context.set_default_navigation_timeout(_NAVIGATION_TIMEOUT_MS)

        page = await context.new_page()

        # Intercept network requests
        def on_request(request):
            try:
                url = request.url
                parsed = urlparse(url)
                if parsed.hostname != base_host:
                    return
                path = parsed.path or "/"
                if _is_static_asset(url):
                    return
                method = request.method
                post_data = request.post_data or ""
                # We'll get content_type from response, store request info
                intercepted[f"{method}:{path}"] = {
                    "path": path,
                    "method": method,
                    "post_data": post_data[:500],
                    "content_type": "",  # filled from response
                    "resource_type": request.resource_type,
                }
            except Exception:
                pass

        def on_response(response):
            try:
                url = response.url
                parsed = urlparse(url)
                if parsed.hostname != base_host:
                    return
                path = parsed.path or "/"
                method = response.request.method
                key = f"{method}:{path}"
                ct = response.headers.get("content-type", "")
                if key in intercepted:
                    intercepted[key]["content_type"] = ct
                elif not _is_static_asset(url):
                    intercepted[key] = {
                        "path": path,
                        "method": method,
                        "post_data": "",
                        "content_type": ct,
                        "resource_type": response.request.resource_type,
                    }
            except Exception:
                pass

        def on_websocket(ws):
            try:
                ws_urls.append(ws.url)
            except Exception:
                pass

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("websocket", on_websocket)

        # Visit each page and interact
        for path in pages_to_visit:
            try:
                url = f"{base}{path}"
                resp = await page.goto(url, wait_until="networkidle", timeout=_NAVIGATION_TIMEOUT_MS)
                if resp and resp.status < 400:
                    site.urls.append(path)

                # Wait for dynamic content to load
                await page.wait_for_timeout(300)

                # Extract links from the rendered DOM (SPA-aware)
                await _extract_dom_links(page, base_host, site)

                # Extract forms from rendered DOM
                await _extract_dom_forms(page, base_host, site)

                # Try clicking interactive elements to trigger API calls
                await _click_interactive_elements(page)

                # Check for inline GraphQL schemas or API configs
                await _extract_inline_api_info(page, site)

            except Exception as exc:
                logger.debug("Failed to visit %s: %s", path, exc)

        # Also try to find GraphQL introspection
        await _try_graphql_introspection(page, base, site)

        await browser.close()

    # Process intercepted requests into the site map
    _process_intercepted(intercepted, ws_urls, site)

    site.deduplicate()
    logger.info(
        "Deep discovery: %d API endpoints, %d forms, %d total URLs, %d WebSocket",
        len(site.api_endpoints), len(site.forms), len(site.urls), len(ws_urls),
    )
    return site


def _process_intercepted(
    intercepted: dict[str, dict],
    ws_urls: list[str],
    site: SiteMap,
) -> None:
    """Classify intercepted network traffic into API endpoints, forms, etc."""
    for key, info in intercepted.items():
        path = info["path"]
        method = info["method"]
        ct = info["content_type"]
        post_data = info["post_data"]
        resource_type = info.get("resource_type", "")

        # Skip document/stylesheet/image resource types
        if resource_type in ("stylesheet", "image", "font", "media"):
            continue

        if _is_api_like(path, method, ct):
            endpoint_type = _classify_endpoint(path, method, ct, post_data)
            if path not in site.api_endpoints:
                site.api_endpoints.append(path)
            if path not in site.urls:
                site.urls.append(path)
            # Add type annotation to technologies
            if endpoint_type == "graphql" and "GraphQL" not in site.technologies:
                site.technologies.append("GraphQL")
            elif endpoint_type == "websocket" and "WebSocket" not in site.technologies:
                site.technologies.append("WebSocket")
            elif endpoint_type == "rpc" and "JSON-RPC" not in site.technologies:
                site.technologies.append("JSON-RPC")

            # Record form submissions
            if endpoint_type == "form" or (method == "POST" and "form" in ct.lower()):
                site.forms.append({
                    "action": path,
                    "method": method,
                    "inputs": [],  # couldn't extract input names from network intercept
                })
        else:
            # Non-API paths that are actual pages (HTML responses)
            if "html" in ct.lower() and path not in site.urls:
                site.urls.append(path)

    # WebSocket endpoints
    for ws_url in ws_urls:
        parsed = urlparse(ws_url)
        path = parsed.path or "/"
        if path not in site.api_endpoints:
            site.api_endpoints.append(path)
        if "WebSocket" not in site.technologies:
            site.technologies.append("WebSocket")


async def _extract_dom_links(page, base_host: str, site: SiteMap) -> None:
    """Extract links from the rendered DOM (works with SPAs)."""
    try:
        links = await page.eval_on_selector_all(
            "a[href]",
            """elements => elements.map(el => el.href).filter(h =>
                h && !h.startsWith('javascript:') && !h.startsWith('#')
            )""",
        )
        for href in links:
            parsed = urlparse(href)
            if parsed.hostname == base_host and parsed.path:
                path = parsed.path
                if not _is_static_asset(href) and path not in site.urls:
                    site.urls.append(path)
                if _API_PATTERNS.search(path) and path not in site.api_endpoints:
                    site.api_endpoints.append(path)
    except Exception:
        pass


async def _extract_dom_forms(page, base_host: str, site: SiteMap) -> None:
    """Extract form data from the rendered DOM."""
    try:
        forms = await page.eval_on_selector_all(
            "form",
            """forms => forms.map(f => ({
                action: f.action || window.location.pathname,
                method: (f.method || 'GET').toUpperCase(),
                inputs: Array.from(f.querySelectorAll('input[name], select[name], textarea[name]'))
                    .map(i => i.name)
            }))""",
        )
        for form_data in forms:
            action = form_data.get("action", "/")
            parsed = urlparse(action)
            # Resolve to path
            path = parsed.path or "/"
            if parsed.hostname and parsed.hostname != base_host:
                continue
            method = form_data.get("method", "GET")
            inputs = form_data.get("inputs", [])
            site.forms.append({
                "action": path,
                "method": method,
                "inputs": inputs,
            })
            if path not in site.urls:
                site.urls.append(path)
            if _API_PATTERNS.search(path) and path not in site.api_endpoints:
                site.api_endpoints.append(path)
    except Exception:
        pass


async def _click_interactive_elements(page) -> None:
    """Click buttons and interactive elements to trigger API calls."""
    try:
        # Click ALL buttons (including submit) — we want to see what APIs they call
        buttons = await page.query_selector_all(
            "button, [role='button'], [data-action], input[type='submit'], "
            "a[href*='api'], [onclick]"
        )
        for btn in buttons[:10]:  # increased from 5
            try:
                if await btn.is_visible():
                    await btn.click(timeout=2000)
                    await page.wait_for_timeout(200)
            except Exception:
                pass
    except Exception:
        pass


async def _extract_inline_api_info(page, site: SiteMap) -> None:
    """Extract API configuration from inline scripts (Next.js, SPA configs)."""
    try:
        # Look for common patterns in page scripts and runtime objects
        api_urls = await page.evaluate("""() => {
            const urls = new Set();

            // Check Next.js runtime config and page props
            if (window.__NEXT_DATA__) {
                const data = JSON.stringify(window.__NEXT_DATA__);
                // API routes
                const apiMatches = data.match(/\\/api\\/[a-zA-Z0-9_\\/-]+/g);
                if (apiMatches) apiMatches.forEach(m => urls.add(m));
                // GraphQL endpoints
                const gqlMatches = data.match(/\\/graphql[a-zA-Z0-9_\\/-]*/g);
                if (gqlMatches) gqlMatches.forEach(m => urls.add(m));
                // URLs in props
                const urlMatches = data.match(/https?:\\/\\/[^"'\\s]+\\/api\\/[^"'\\s]+/g);
                if (urlMatches) urlMatches.forEach(m => {
                    try { urls.add(new URL(m).pathname); } catch {}
                });
            }

            // Check for environment config objects
            for (const key of Object.keys(window)) {
                try {
                    if (key.includes('config') || key.includes('CONFIG') ||
                        key.includes('env') || key.includes('ENV') ||
                        key.includes('API') || key.includes('firebase')) {
                        const val = JSON.stringify(window[key]);
                        const apiMatches = val.match(/\\/(?:api|v[0-9]+|graphql|rest|rpc)\\/[a-zA-Z0-9_\\/-]+/g);
                        if (apiMatches) apiMatches.forEach(m => urls.add(m));
                        // Also look for full URLs
                        const fullUrls = val.match(/https?:\\/\\/[^"'\\s]+\\/(?:api|v[0-9]+|graphql)\\/[^"'\\s]*/g);
                        if (fullUrls) fullUrls.forEach(m => {
                            try { urls.add(new URL(m).pathname); } catch {}
                        });
                    }
                } catch {}
            }

            // Scan ALL script tags for API endpoint patterns
            document.querySelectorAll('script').forEach(s => {
                const text = s.textContent || s.innerText || '';
                if (!text || text.length > 500000) return;
                // API paths in strings
                const pathMatches = text.match(/["'`](\\/(api|v[0-9]+|graphql|rest|rpc|auth|webhook)\\/[a-zA-Z0-9_\\/-]*)["'`]/g);
                if (pathMatches) {
                    pathMatches.forEach(m => {
                        const clean = m.replace(/["'`]/g, '');
                        if (clean.length > 3 && clean.length < 200) urls.add(clean);
                    });
                }
                // fetch/axios calls
                const fetchMatches = text.match(/(?:fetch|axios|\\$http|request)\\s*\\(\\s*["'`](\\/[a-zA-Z0-9_\\/-]+)["'`]/g);
                if (fetchMatches) {
                    fetchMatches.forEach(m => {
                        const pathMatch = m.match(/["'`](\\/[a-zA-Z0-9_\\/-]+)["'`]/);
                        if (pathMatch && pathMatch[1].length > 3) urls.add(pathMatch[1]);
                    });
                }
            });

            // Check meta tags for API base URLs
            document.querySelectorAll('meta[name*="api"], meta[name*="url"], meta[property*="api"]').forEach(m => {
                const content = m.getAttribute('content') || '';
                if (content.startsWith('/') || content.includes('/api/')) {
                    try {
                        const path = content.startsWith('http') ? new URL(content).pathname : content;
                        if (path.length > 3) urls.add(path);
                    } catch {}
                }
            });

            return Array.from(urls);
        }""")
        for api_url in api_urls:
            if not _is_static_asset(api_url):
                if api_url not in site.api_endpoints:
                    site.api_endpoints.append(api_url)
                if api_url not in site.urls:
                    site.urls.append(api_url)
    except Exception:
        pass


async def _try_graphql_introspection(page, base: str, site: SiteMap) -> None:
    """Try GraphQL introspection to discover schema, mutations, and subscriptions."""
    graphql_paths = ["/graphql", "/api/graphql", "/gql", "/query", "/api/gql"]
    # Full introspection query that gets query/mutation/subscription types + fields
    introspection_query = _json_dumps({
        "query": """{ __schema {
            queryType { name fields { name } }
            mutationType { name fields { name } }
            subscriptionType { name fields { name } }
            types { name kind }
        } }"""
    })

    for gql_path in graphql_paths:
        try:
            response = await page.evaluate(
                """async ([url, body]) => {
                    try {
                        const resp = await fetch(url, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: body,
                        });
                        const ct = resp.headers.get('content-type') || '';
                        if (resp.ok && ct.includes('json')) {
                            const data = await resp.json();
                            if (data.data && data.data.__schema) {
                                const s = data.data.__schema;
                                return {
                                    found: true,
                                    types: s.types ? s.types.length : 0,
                                    queries: s.queryType && s.queryType.fields
                                        ? s.queryType.fields.map(f => f.name) : [],
                                    mutations: s.mutationType && s.mutationType.fields
                                        ? s.mutationType.fields.map(f => f.name) : [],
                                    subscriptions: s.subscriptionType && s.subscriptionType.fields
                                        ? s.subscriptionType.fields.map(f => f.name) : [],
                                };
                            }
                        }
                        // Also try if we get a non-200 but revealing error
                        if (resp.status === 400) {
                            return { found: false, exists: true };
                        }
                        return { found: false };
                    } catch { return { found: false }; }
                }""",
                [f"{base}{gql_path}", introspection_query],
            )
            if response.get("found"):
                if gql_path not in site.api_endpoints:
                    site.api_endpoints.append(gql_path)
                queries = response.get("queries", [])
                mutations = response.get("mutations", [])
                subscriptions = response.get("subscriptions", [])
                tech_info = (
                    f"GraphQL ({gql_path}: "
                    f"{len(queries)} queries, {len(mutations)} mutations, "
                    f"{len(subscriptions)} subscriptions, "
                    f"{response['types']} types)"
                )
                # Remove old simple GraphQL tech entry
                site.technologies = [
                    t for t in site.technologies if "GraphQL" not in t
                ]
                site.technologies.append(tech_info)
                logger.info("GraphQL introspection at %s: %s", gql_path, tech_info)
            elif response.get("exists"):
                # GraphQL endpoint exists but introspection disabled
                if gql_path not in site.api_endpoints:
                    site.api_endpoints.append(gql_path)
                if not any("GraphQL" in t for t in site.technologies):
                    site.technologies.append(f"GraphQL ({gql_path}, introspection disabled)")
        except Exception:
            pass


def _json_dumps(obj) -> str:
    """Compact JSON serialization."""
    import json
    return json.dumps(obj, separators=(",", ":"))
