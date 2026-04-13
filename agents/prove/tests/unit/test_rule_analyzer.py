"""Tests for deterministic rule-based response analysis."""

import pytest

from prove_agent.strategies.rule_analyzer import analyze_response


class TestSqlInjection:
    """SQL injection detection rules."""

    def test_mysql_error_detected(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body="You have an error in your SQL syntax; check the manual",
            plan_body="' OR 1=1 --",
            finding_category="OWASP",
            finding_title="SQL Injection in login form",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is True
        assert "SQL error" in result.evidence

    def test_postgres_error_detected(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body="PG::SyntaxError: unterminated quoted string",
            plan_body="' OR 1=1 --",
            finding_category="CWE",
            finding_title="SQL Injection via user input",
        )
        assert result is not None
        assert result.conclusive is True

    def test_sqlite_error_detected(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body="sqlite3.OperationalError: near \"DROP\": syntax error",
            plan_body="'; DROP TABLE users;--",
            finding_category="OWASP",
            finding_title="SQL Injection in search",
        )
        assert result is not None
        assert result.conclusive is True

    def test_500_with_injection_payload(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body="Internal Server Error",
            plan_body="' OR 1=1 --",
            finding_category="OWASP",
            finding_title="SQL Injection in login",
        )
        assert result is not None
        assert result.conclusive is True
        assert "500" in result.evidence

    def test_200_without_error_not_detected(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="Search results: none found",
            plan_body="' OR 1=1 --",
            finding_category="OWASP",
            finding_title="SQL Injection in search endpoint",
        )
        assert result is None

    def test_non_injection_finding_skips_sql_check(self):
        """SQL errors in response don't trigger when finding is not injection-related."""
        result = analyze_response(
            status_code=500,
            headers={"strict-transport-security": "max-age=31536000",
                     "x-frame-options": "DENY",
                     "x-content-type-options": "nosniff",
                     "content-security-policy": "default-src 'self'"},
            body="You have an error in your SQL syntax",
            plan_body="",
            finding_category="OWASP",
            finding_title="Missing rate limiting",
        )
        # SQL check only fires for injection-related findings
        assert result is None


class TestXssReflection:
    """XSS reflection detection rules."""

    def test_script_tag_reflected(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="<html>Search results for: <script>alert(1)</script></html>",
            plan_body="<script>alert(1)</script>",
            finding_category="OWASP",
            finding_title="Cross-Site Scripting (XSS)",
        )
        assert result is not None
        assert result.conclusive is True
        assert "XSS" in result.evidence

    def test_no_reflection(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="<html>Search results for: sanitized</html>",
            plan_body="<script>alert(1)</script>",
            finding_category="OWASP",
            finding_title="Cross-Site Scripting (XSS)",
        )
        assert result is None

    def test_no_plan_body(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="<html><script>app.init()</script></html>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Cross-Site Scripting (XSS)",
        )
        assert result is None


class TestPathTraversal:
    """Path traversal detection rules."""

    def test_etc_passwd_in_response(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            plan_body="../../etc/passwd",
            finding_category="CWE",
            finding_title="Path Traversal in file download",
        )
        assert result is not None
        assert result.conclusive is True
        assert "traversal" in result.evidence.lower()

    def test_windows_path_in_response(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="[boot loader]\ntimeout=30",
            plan_body="..\\..\\boot.ini",
            finding_category="CWE",
            finding_title="Path Traversal vulnerability",
        )
        assert result is not None
        assert result.conclusive is True


class TestInfoDisclosure:
    """Information disclosure detection rules."""

    def test_python_stack_trace(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body='Traceback (most recent call last):\n  File "/app/views.py", line 42',
            plan_body="",
            finding_category="OWASP",
            finding_title="Information Disclosure via error messages",
        )
        assert result is not None
        assert result.conclusive is True
        assert "disclosure" in result.evidence.lower()

    def test_django_debug(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body="DJANGO_SETTINGS_MODULE = myproject.settings",
            plan_body="",
            finding_category="OWASP",
            finding_title="Information Disclosure in debug mode",
        )
        assert result is not None
        assert result.conclusive is True

    def test_api_key_leak(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"config": {"api_key": "sk-1234567890abcdef"}}',
            plan_body="",
            finding_category="OWASP",
            finding_title="Hardcoded Credentials exposure",
        )
        assert result is not None
        assert result.conclusive is True

    def test_clean_response_no_match(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="Welcome to our app. Everything is working fine.",
            plan_body="",
            finding_category="OWASP",
            finding_title="Information Disclosure via verbose errors",
        )
        assert result is None


class TestSecurityHeaders:
    """Missing security header detection rules."""

    def test_missing_hsts(self):
        result = analyze_response(
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html></html>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Missing HSTS header",
        )
        assert result is not None
        assert result.conclusive is True
        assert "HSTS" in result.evidence

    def test_present_hsts_not_flagged(self):
        result = analyze_response(
            status_code=200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'",
            },
            body="<html></html>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Missing HSTS header",
        )
        assert result is None

    def test_missing_x_frame_options(self):
        result = analyze_response(
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html></html>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Missing X-Frame-Options — Clickjacking risk",
        )
        assert result is not None
        assert result.conclusive is True

    def test_generic_missing_headers(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="<html></html>",
            plan_body="",
            finding_category="SOC2",
            finding_title="Missing security headers on responses",
        )
        assert result is not None
        assert result.conclusive is True


class TestCookieSecurity:
    """Cookie security flag detection rules."""

    def test_insecure_cookie_no_flags(self):
        result = analyze_response(
            status_code=200,
            headers={"set-cookie": "session=abc123; Path=/"},
            body="",
            plan_body="",
            finding_category="OWASP",
            finding_title="Insecure session cookie configuration",
        )
        assert result is not None
        assert result.conclusive is True
        assert "Secure" in result.evidence

    def test_secure_cookie_not_flagged(self):
        result = analyze_response(
            status_code=200,
            headers={"set-cookie": "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"},
            body="",
            plan_body="",
            finding_category="OWASP",
            finding_title="Insecure session cookie",
        )
        assert result is None

    def test_no_cookie_no_match(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="",
            plan_body="",
            finding_category="OWASP",
            finding_title="Session cookie security",
        )
        assert result is None


class TestAuthBypass:
    """Authentication bypass detection rules."""

    def test_dashboard_without_auth(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="<html><h1>Dashboard</h1><p>Welcome admin</p></html>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Broken Authentication — unauthenticated access",
        )
        assert result is not None
        assert result.conclusive is True
        assert "without authentication" in result.evidence

    def test_401_means_protected(self):
        result = analyze_response(
            status_code=401,
            headers={},
            body="Unauthorized",
            plan_body="",
            finding_category="OWASP",
            finding_title="Broken Authentication bypass",
        )
        assert result is None

    def test_non_auth_finding_skips(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="<h1>Dashboard</h1>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Missing input validation",
        )
        assert result is None


class TestChaosServerError:
    """Server error detection for chaos/resilience findings."""

    def test_500_means_no_resilience(self):
        result = analyze_response(
            status_code=500,
            headers={},
            body="Internal Server Error",
            plan_body="",
            finding_category="chaos_engineering",
            finding_title="Missing circuit breaker pattern",
        )
        assert result is not None
        assert result.conclusive is True
        assert "resilience" in result.evidence.lower()

    def test_503_means_no_resilience(self):
        result = analyze_response(
            status_code=503,
            headers={},
            body="Service Unavailable",
            plan_body="",
            finding_category="chaos",
            finding_title="Missing retry pattern",
        )
        assert result is not None
        assert result.conclusive is True

    def test_200_no_chaos_match(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body="OK",
            plan_body="",
            finding_category="chaos_engineering",
            finding_title="Missing circuit breaker",
        )
        assert result is None

    def test_500_non_chaos_not_flagged(self):
        """500 from a non-chaos finding should NOT trigger chaos rule."""
        result = analyze_response(
            status_code=500,
            headers={},
            body="Internal Server Error",
            plan_body="",
            finding_category="OWASP",
            finding_title="Missing input validation",
        )
        assert result is None


class TestFileUpload:
    """File upload (CWE-434) detection rules."""

    def test_dangerous_file_accepted_with_filename_echo(self):
        result = analyze_response(
            status_code=201,
            headers={},
            body='{"file": "shell.php", "url": "/uploads/shell.php"}',
            plan_body="<?php echo 'test'; ?>",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.php",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is True
        assert "shell.php" in result.evidence

    def test_201_created_dangerous_extension(self):
        result = analyze_response(
            status_code=201,
            headers={},
            body='{"id": 42}',
            plan_body="<?php system($_GET['cmd']); ?>",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="payload.jsp",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is True
        assert "201" in result.evidence

    def test_200_success_pattern_detected(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"message": "file saved successfully", "path": "/uploads/test.php"}',
            plan_body="test content",
            finding_category="CWE",
            finding_title="Unrestricted file upload vulnerability",
            upload_filename="test.php",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is True

    def test_200_no_error_dangerous_file(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"status": "ok"}',
            plan_body="<?php echo 1; ?>",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.aspx",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is True
        assert "missing file type validation" in result.evidence

    def test_400_rejection_means_not_reproduced(self):
        result = analyze_response(
            status_code=400,
            headers={},
            body='{"error": "File type not allowed"}',
            plan_body="",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.php",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is False
        assert "validation is present" in result.evidence

    def test_415_unsupported_media_type(self):
        result = analyze_response(
            status_code=415,
            headers={},
            body="Unsupported Media Type",
            plan_body="",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.php",
        )
        assert result is not None
        assert result.conclusive is True
        assert result.reproduced is False

    def test_safe_extension_not_triggered(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"status": "ok"}',
            plan_body="image data",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="photo.jpg",
        )
        # .jpg is not a dangerous extension, so no rule fires
        assert result is None

    def test_no_filename_skips_check(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"status": "ok"}',
            plan_body="",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="",
        )
        assert result is None

    def test_200_with_error_in_body_not_flagged(self):
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"error": "Invalid file type", "status": "rejected"}',
            plan_body="<?php echo 1; ?>",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.php",
        )
        # Response contains error keywords — should NOT be flagged as reproduced
        assert result is None

    def test_graphql_error_200_not_false_positive(self):
        """GraphQL returns 200 with errors array — must NOT be treated as upload success."""
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"errors":[{"message":"Missing Authorization header","extensions":{"path":"$","code":"invalid-headers"}}]}',
            plan_body="<?php echo 'test'; ?>",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.php",
        )
        # "path":"$" in GraphQL error extensions must NOT match as upload success
        assert result is None

    def test_200_errors_array_not_flagged(self):
        """Server returning 200 with errors field = not a successful upload."""
        result = analyze_response(
            status_code=200,
            headers={},
            body='{"errors": ["file too large"], "path": "/tmp/upload"}',
            plan_body="data",
            finding_category="CWE",
            finding_title="Unrestricted file upload",
            upload_filename="shell.php",
        )
        assert result is None

    def test_non_upload_finding_skips(self):
        """File upload check only fires for upload-related findings."""
        result = analyze_response(
            status_code=201,
            headers={},
            body='{"file": "shell.php"}',
            plan_body="",
            finding_category="CWE",
            finding_title="SQL Injection in search",
            upload_filename="shell.php",
        )
        assert result is None


class TestNoMatch:
    """Cases where no rule should fire."""

    def test_normal_200_response(self):
        result = analyze_response(
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html><body>Hello World</body></html>",
            plan_body="",
            finding_category="OWASP",
            finding_title="Some generic finding",
        )
        assert result is None

    def test_404_response(self):
        result = analyze_response(
            status_code=404,
            headers={},
            body="Not Found",
            plan_body="",
            finding_category="CWE",
            finding_title="Some vulnerability",
        )
        assert result is None
