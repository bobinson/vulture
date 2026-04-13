"""Tests for technique library with fallback chains."""

import pytest

from prove_agent.techniques import (
    FILE_UPLOAD_CHAIN,
    SQL_INJECTION_CHAIN,
    XSS_CHAIN,
    Technique,
    get_technique_chain,
    pick_next_technique,
)


class TestGetTechniqueChain:
    """Technique chain lookup by finding category."""

    def test_sql_injection_chain(self):
        chain = get_technique_chain("SQL Injection in login", "OWASP")
        assert len(chain) > 0
        assert all(isinstance(t, Technique) for t in chain)

    def test_xss_chain(self):
        chain = get_technique_chain("Cross-Site Scripting (XSS)", "OWASP")
        assert len(chain) > 0

    def test_path_traversal_chain(self):
        chain = get_technique_chain("Path Traversal in downloads", "CWE")
        assert len(chain) > 0

    def test_file_upload_chain(self):
        chain = get_technique_chain("Unrestricted file upload", "CWE")
        assert len(chain) > 0
        assert all(t.is_multipart for t in chain)

    def test_cwe434_by_category(self):
        chain = get_technique_chain("Some vulnerability", "CWE-434")
        assert len(chain) > 0
        assert chain[0].is_multipart

    def test_auth_bypass_chain(self):
        chain = get_technique_chain("Broken Authentication bypass", "OWASP")
        assert len(chain) > 0

    def test_info_disclosure_chain(self):
        chain = get_technique_chain("Information Disclosure via errors", "OWASP")
        assert len(chain) > 0

    def test_security_headers_chain(self):
        chain = get_technique_chain("Missing HSTS header", "OWASP")
        assert len(chain) > 0

    def test_cookie_security_chain(self):
        chain = get_technique_chain("Insecure session cookie", "OWASP")
        assert len(chain) > 0

    def test_cors_chain(self):
        chain = get_technique_chain("CORS misconfiguration", "OWASP")
        assert len(chain) > 0

    def test_csrf_chain(self):
        chain = get_technique_chain("Missing CSRF protection", "OWASP")
        assert len(chain) > 0

    def test_unknown_category_returns_empty(self):
        chain = get_technique_chain("Some random thing", "UNKNOWN")
        assert chain == []


class TestPickNextTechnique:
    """Technique chain progression."""

    def test_picks_first_when_none_tried(self):
        tech = pick_next_technique("SQL Injection", "OWASP", set())
        assert tech is not None
        assert tech == SQL_INJECTION_CHAIN[0]

    def test_skips_tried_paths(self):
        first = SQL_INJECTION_CHAIN[0]
        tech = pick_next_technique(
            "SQL Injection", "OWASP", {first.path_pattern},
        )
        assert tech is not None
        assert tech != first
        assert tech == SQL_INJECTION_CHAIN[1]

    def test_returns_none_when_all_exhausted(self):
        all_paths = {t.path_pattern for t in SQL_INJECTION_CHAIN}
        tech = pick_next_technique("SQL Injection", "OWASP", all_paths)
        assert tech is None

    def test_chain_order_preserved(self):
        """Techniques should be tried in order."""
        tried: set[str] = set()
        chain = get_technique_chain("SQL Injection", "OWASP")
        for expected in chain:
            tech = pick_next_technique("SQL Injection", "OWASP", tried)
            assert tech == expected
            tried.add(tech.path_pattern)

    def test_unknown_finding_returns_none(self):
        tech = pick_next_technique("Random finding", "UNKNOWN", set())
        assert tech is None


class TestTechniqueChainContent:
    """Verify technique chain data quality."""

    def test_sql_injection_uses_post_for_login(self):
        chain = get_technique_chain("SQL Injection", "CWE")
        login_techniques = [t for t in chain if "login" in t.path_pattern]
        assert len(login_techniques) > 0
        assert login_techniques[0].method == "POST"

    def test_xss_includes_script_payloads(self):
        chain = get_technique_chain("Cross-Site Scripting", "OWASP")
        payloads = [t.payload for t in chain if t.payload]
        assert any("<script>" in p for p in payloads)

    def test_file_upload_all_have_filenames(self):
        chain = get_technique_chain("Unrestricted file upload", "CWE")
        for tech in chain:
            assert tech.filename, f"Upload technique missing filename: {tech.description}"
            assert tech.is_multipart, f"Upload technique not multipart: {tech.description}"

    def test_file_upload_uses_dangerous_extensions(self):
        chain = get_technique_chain("Unrestricted file upload", "CWE")
        exts = {t.filename.split(".")[-1] for t in chain}
        assert "php" in exts
        assert "jsp" in exts

    def test_all_techniques_have_descriptions(self):
        """Every technique in every chain must have a description."""
        from prove_agent.techniques import _CHAIN_MAP
        for category, chain in _CHAIN_MAP.items():
            for tech in chain:
                assert tech.description, f"Missing description in {category}"

    def test_all_techniques_have_path_patterns(self):
        """Every technique must have a path pattern."""
        from prove_agent.techniques import _CHAIN_MAP
        for category, chain in _CHAIN_MAP.items():
            for tech in chain:
                assert tech.path_pattern, f"Missing path_pattern in {category}"
                assert tech.path_pattern.startswith("/"), (
                    f"Path must start with / in {category}: {tech.path_pattern}"
                )

    def test_all_techniques_have_methods(self):
        """Every technique must have a valid HTTP method."""
        from prove_agent.techniques import _CHAIN_MAP
        valid_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"}
        for category, chain in _CHAIN_MAP.items():
            for tech in chain:
                assert tech.method in valid_methods, (
                    f"Invalid method {tech.method} in {category}"
                )


class TestTechniqueIntegration:
    """Integration with build_fallback_plan."""

    def test_fallback_uses_technique_chain(self):
        from prove_agent.strategies.shared import build_fallback_plan
        plan = build_fallback_plan(
            {"title": "Cross-Site Scripting (XSS)", "category": "OWASP"},
            "/api/users\n/login",
            None,
        )
        # Should use technique chain, not site context
        assert "xss" in plan.description.lower() or "script" in plan.description.lower()

    def test_upload_technique_chain_preferred(self):
        from prove_agent.strategies.shared import build_fallback_plan
        plan = build_fallback_plan(
            {"title": "Unrestricted file upload", "category": "CWE-434"},
            "/api/data\n/login",
            None,
        )
        assert plan.is_multipart is True
        assert plan.filename != ""
        # Technique chain for uploads starts with /api/upload
        assert "/api/upload" in plan.url_path or "/upload" in plan.url_path
