"""Tests for shared strategy utilities."""


from prove_agent.strategies.base import AttemptRecord
from prove_agent.strategies.shared import (
    build_fallback_plan,
    build_prior_context,
    extract_urls_from_site_context,
    is_static_asset,
    pick_untried_url,
)


class TestIsStaticAsset:
    """Static asset detection."""

    def test_js_file(self):
        assert is_static_asset("/app.js") is True

    def test_css_file(self):
        assert is_static_asset("/styles/main.css") is True

    def test_image_file(self):
        assert is_static_asset("/images/logo.png") is True

    def test_font_file(self):
        assert is_static_asset("/fonts/roboto.woff2") is True

    def test_next_static(self):
        assert is_static_asset("/_next/static/chunks/main.js") is True

    def test_build_manifest(self):
        assert is_static_asset("/_buildManifest.js") is True

    def test_next_data(self):
        assert is_static_asset("/_next/data/abc123/index.json") is True

    def test_api_endpoint(self):
        assert is_static_asset("/api/users") is False

    def test_login_page(self):
        assert is_static_asset("/login") is False

    def test_graphql(self):
        assert is_static_asset("/graphql") is False


class TestExtractUrlsFromSiteContext:
    """URL extraction from site context text."""

    def test_extracts_paths(self):
        ctx = "URLs:\n  /login\n  /api/users\n  /dashboard"
        urls = extract_urls_from_site_context(ctx)
        assert "/login" in urls
        assert "/api/users" in urls
        assert "/dashboard" in urls

    def test_filters_static(self):
        ctx = "/login\n/_next/static/chunk.js\n/api/auth"
        urls = extract_urls_from_site_context(ctx)
        assert "/login" in urls
        assert "/api/auth" in urls
        assert "/_next/static/chunk.js" not in urls

    def test_api_endpoints_first(self):
        ctx = "/dashboard\n/api/users\n/settings\n/api/auth/login"
        urls = extract_urls_from_site_context(ctx)
        # API endpoints should come before page URLs
        api_idx = [urls.index(u) for u in urls if "/api/" in u]
        page_idx = [urls.index(u) for u in urls if "/api/" not in u]
        if api_idx and page_idx:
            assert max(api_idx) < min(page_idx)

    def test_skips_root(self):
        ctx = "/\n/login"
        urls = extract_urls_from_site_context(ctx)
        assert "/" not in urls
        assert "/login" in urls

    def test_deduplicates(self):
        ctx = "/login\n/login\n/api/users\n/api/users"
        urls = extract_urls_from_site_context(ctx)
        assert urls.count("/login") == 1
        assert urls.count("/api/users") == 1


class TestPickUntriedUrl:
    """URL selection for verification attempts."""

    def test_picks_first_untried(self):
        ctx = "/login\n/api/users\n/dashboard"
        attempts = [AttemptRecord(
            iteration=1, method="GET", url_path="/login",
            status_code=200, response_snippet="", response_headers={},
            evidence="", conclusive=False, reproduced=False, plan_description="",
        )]
        url = pick_untried_url(ctx, attempts)
        assert url != "/login"
        assert url in ("/api/users", "/dashboard")

    def test_picks_first_when_no_attempts(self):
        ctx = "/api/auth\n/login"
        url = pick_untried_url(ctx, None)
        assert url == "/api/auth"

    def test_cycles_when_all_tried(self):
        ctx = "/login\n/api/users"
        attempts = [
            AttemptRecord(
                iteration=i, method="GET", url_path=p,
                status_code=200, response_snippet="", response_headers={},
                evidence="", conclusive=False, reproduced=False, plan_description="",
            )
            for i, p in enumerate(["/login", "/api/users"], 1)
        ]
        url = pick_untried_url(ctx, attempts)
        assert url in ("/login", "/api/users")

    def test_empty_context(self):
        url = pick_untried_url("", None)
        assert url == ""


class TestBuildFallbackPlan:
    """Fallback plan generation."""

    def test_picks_from_technique_chain_first(self):
        """Technique library takes precedence over site context URLs."""
        plan = build_fallback_plan(
            {"title": "SQL Injection", "category": "OWASP"},
            "/api/users\n/login",
            None,
        )
        # SQL injection technique chain starts with /api/auth/login POST
        assert plan.method == "POST"
        assert "injection" in plan.description.lower() or "sql" in plan.description.lower()

    def test_falls_through_to_site_context(self):
        """When all techniques exhausted, falls through to site context."""
        from prove_agent.techniques import get_technique_chain
        chain = get_technique_chain("SQL Injection", "OWASP")
        # Mark all technique paths as tried
        tried_attempts = [
            AttemptRecord(
                iteration=i, method="GET", url_path=t.path_pattern,
                status_code=200, response_snippet="", response_headers={},
                evidence="", conclusive=False, reproduced=False, plan_description="",
            )
            for i, t in enumerate(chain, 1)
        ]
        plan = build_fallback_plan(
            {"title": "SQL Injection", "category": "OWASP"},
            "/api/users\n/login",
            tried_attempts,
        )
        assert plan.url_path in ("/api/users", "/login")

    def test_uses_common_fallbacks_when_no_context(self):
        plan = build_fallback_plan(
            {"title": "Test", "category": "CWE"},
            "",
            None,
        )
        assert plan.url_path in (
            "/login", "/api/auth/session", "/profile", "/admin",
            "/api/users", "/settings", "/dashboard", "/api/config",
        )

    def test_skips_tried_urls(self):
        attempts = [AttemptRecord(
            iteration=1, method="GET", url_path="/login",
            status_code=200, response_snippet="", response_headers={},
            evidence="", conclusive=False, reproduced=False, plan_description="",
        )]
        plan = build_fallback_plan(
            {"title": "Test", "category": "OWASP"},
            "/login\n/api/users",
            attempts,
        )
        assert plan.url_path == "/api/users"


class TestBuildFallbackPlanUpload:
    """Fallback plan generation for file upload findings."""

    def test_upload_finding_generates_multipart_plan(self):
        plan = build_fallback_plan(
            {"title": "Unrestricted file upload", "category": "CWE"},
            "/api/upload\n/login",
            None,
        )
        assert plan.is_multipart is True
        assert plan.filename in ("shell.php", "test.jsp", "payload.aspx", "script.html")
        assert plan.method == "POST"
        assert "/upload" in plan.url_path

    def test_cwe434_finding_generates_multipart_plan(self):
        plan = build_fallback_plan(
            {"title": "CWE-434 vulnerability", "category": "CWE"},
            "/api/files\n/dashboard",
            None,
        )
        assert plan.is_multipart is True
        assert plan.method == "POST"

    def test_upload_fallback_uses_common_endpoints(self):
        plan = build_fallback_plan(
            {"title": "Unrestricted file upload", "category": "CWE"},
            "",  # no site context
            None,
        )
        assert plan.is_multipart is True
        assert plan.url_path in (
            "/api/upload", "/upload", "/api/files", "/api/media",
            "/api/attachments", "/api/images", "/api/documents",
            "/files/upload", "/media/upload",
        )

    def test_non_upload_finding_not_multipart(self):
        plan = build_fallback_plan(
            {"title": "SQL Injection", "category": "OWASP"},
            "/api/users\n/login",
            None,
        )
        assert plan.is_multipart is False
        assert plan.filename == ""


class TestBuildPriorContext:
    """Prior context formatting."""

    def test_empty_context(self):
        ctx = build_prior_context(None, None, None)
        assert ctx == ""

    def test_with_attempts(self):
        attempts = [AttemptRecord(
            iteration=1, method="GET", url_path="/login",
            status_code=200, response_snippet="OK",
            response_headers={}, evidence="No vuln found",
            conclusive=False, reproduced=False, plan_description="Test login",
        )]
        ctx = build_prior_context(attempts, None, None)
        assert "GET /login" in ctx
        assert "HTTP 200" in ctx

    def test_with_learnings(self):
        ctx = build_prior_context(None, None, ["Server uses Next.js"])
        assert "Server uses Next.js" in ctx
