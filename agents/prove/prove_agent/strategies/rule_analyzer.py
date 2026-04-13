"""Deterministic rule-based response analysis — works without LLM.

When the LLM is too small or returns invalid JSON, these rules provide
concrete vulnerability detection by pattern-matching HTTP response data.
Each rule checks status codes, headers, and body content for known indicators.
"""

import re

from prove_agent.strategies.base import ExecutionResult


# --- SQL injection error patterns ---
_SQL_ERROR_PATTERNS = re.compile(
    r"(You have an error in your SQL syntax|"
    r"mysql_fetch|mysqli_|"
    r"pg_query|pg_exec|PG::SyntaxError|"
    r"SQLite3::SQLException|sqlite3\.OperationalError|"
    r"Unclosed quotation mark|"
    r"ORA-\d{5}|"
    r"SQLSTATE\[|"
    r"Microsoft OLE DB Provider|"
    r"Incorrect syntax near|"
    r"unterminated quoted string|"
    r"syntax error at or near)",
    re.IGNORECASE,
)

# --- XSS reflection patterns ---
_XSS_PAYLOADS = [
    "<script>", "javascript:", "onerror=", "onload=",
    "alert(", "<img src=", "<svg/onload",
]

# --- Information disclosure patterns ---
_INFO_DISCLOSURE_PATTERNS = re.compile(
    r"(Traceback \(most recent call last\)|"
    r"at \w+\.\w+\(.*:\d+\)|"  # Java/C# stack traces
    r"File \".*\", line \d+|"  # Python stack traces
    r"DJANGO_SETTINGS_MODULE|"
    r"DEBUG\s*=\s*True|"
    r"phpinfo\(\)|"
    r"X-Powered-By:|"
    r"AWS_SECRET_ACCESS_KEY|"
    r"PRIVATE KEY---|"
    r"password[\"']?\s*[:=]\s*['\"][^'\"]{3,}|"
    r"api[_-]?key[\"']?\s*[:=]\s*['\"][^'\"]{8,}|"
    r"secret[_-]?key[\"']?\s*[:=]\s*['\"][^'\"]{8,})",
    re.IGNORECASE,
)

# --- Path traversal indicators ---
_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(root:x:\d+:\d+|"
    r"\[boot loader\]|"  # Windows boot.ini
    r"<Directory |"  # Apache config
    r"/etc/passwd|/etc/shadow|"
    r"\\Windows\\System32)",
    re.IGNORECASE,
)

# --- Security headers that SHOULD be present ---
_REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": "Missing HSTS header",
    "x-frame-options": "Missing X-Frame-Options header",
    "x-content-type-options": "Missing X-Content-Type-Options header",
    "content-security-policy": "Missing Content-Security-Policy header",
}

# --- Cookie security flags ---
_INSECURE_COOKIE_RE = re.compile(
    r"Set-Cookie:.*(?!.*(?:Secure|HttpOnly|SameSite))",
    re.IGNORECASE,
)


def analyze_response(
    status_code: int,
    headers: dict[str, str],
    body: str,
    plan_body: str,
    finding_category: str,
    finding_title: str,
    upload_filename: str = "",
) -> ExecutionResult | None:
    """Apply deterministic rules to detect vulnerability indicators.

    Returns ExecutionResult if a rule fires, or None if no rule matched
    (in which case the caller should fall through to LLM analysis).
    """
    lower_body = body.lower()
    lower_title = finding_title.lower()

    # --- SQL Injection ---
    if _is_injection_related(lower_title, finding_category):
        result = _check_sql_injection(status_code, body, plan_body)
        if result:
            return result

    # --- XSS Reflection ---
    if "xss" in lower_title or "cross-site" in lower_title:
        result = _check_xss_reflection(body, plan_body)
        if result:
            return result

    # --- Path Traversal ---
    if "traversal" in lower_title or "path" in lower_title or "lfi" in lower_title:
        result = _check_path_traversal(body)
        if result:
            return result

    # --- Information Disclosure / Secrets ---
    if _is_disclosure_related(lower_title, finding_category):
        result = _check_info_disclosure(body)
        if result:
            return result

    # --- Missing Security Headers ---
    if _is_header_related(lower_title, finding_category):
        result = _check_security_headers(headers, lower_title)
        if result:
            return result

    # --- Cookie Security ---
    if "cookie" in lower_title or "session" in lower_title:
        result = _check_cookie_security(headers)
        if result:
            return result

    # --- Authentication Bypass ---
    if _is_auth_related(lower_title):
        result = _check_auth_bypass(status_code, body)
        if result:
            return result

    # --- File Upload (CWE-434) ---
    if _is_upload_related(lower_title, finding_category):
        result = _check_file_upload(status_code, body, upload_filename)
        if result:
            return result

    # --- Server Error (useful for chaos/resilience) ---
    if finding_category.lower() in ("chaos", "resilience", "chaos_engineering"):
        result = _check_server_error(status_code, headers)
        if result:
            return result

    return None


def _is_injection_related(title: str, category: str) -> bool:
    return any(kw in title for kw in ("injection", "sqli", "sql ")) or "injection" in category.lower()


def _is_disclosure_related(title: str, category: str) -> bool:
    return any(kw in title for kw in (
        "disclosure", "leak", "expos", "hardcod", "credential", "secret",
        "debug", "verbose", "stack trace", "error handling",
    ))


def _is_header_related(title: str, category: str) -> bool:
    return any(kw in title for kw in (
        "header", "hsts", "x-frame", "csp", "content-security",
        "x-content-type", "clickjack", "transport",
    ))


def _is_auth_related(title: str) -> bool:
    return any(kw in title for kw in (
        "auth", "login", "access control", "bypass", "unauthenticated",
        "unauthorized", "privilege", "csrf",
    ))


def _check_sql_injection(
    status_code: int, body: str, plan_body: str,
) -> ExecutionResult | None:
    match = _SQL_ERROR_PATTERNS.search(body)
    if match:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"SQL error in response: {match.group()[:100]}",
            status_code=status_code,
            response_snippet=body[:500],
        )
    # 500 with injection payload suggests server-side error from bad SQL
    if status_code == 500 and plan_body and ("'" in plan_body or '"' in plan_body or "--" in plan_body):
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"HTTP 500 triggered by SQL injection payload",
            status_code=status_code,
            response_snippet=body[:500],
        )
    return None


def _check_xss_reflection(body: str, plan_body: str) -> ExecutionResult | None:
    if not plan_body:
        return None
    for payload in _XSS_PAYLOADS:
        if payload in plan_body and payload in body:
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence=f"XSS payload reflected in response: {payload}",
                status_code=200,
                response_snippet=body[:500],
            )
    return None


def _check_path_traversal(body: str) -> ExecutionResult | None:
    match = _PATH_TRAVERSAL_PATTERNS.search(body)
    if match:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"Path traversal indicator in response: {match.group()[:100]}",
            status_code=200,
            response_snippet=body[:500],
        )
    return None


def _check_info_disclosure(body: str) -> ExecutionResult | None:
    match = _INFO_DISCLOSURE_PATTERNS.search(body)
    if match:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"Information disclosure: {match.group()[:100]}",
            status_code=200,
            response_snippet=body[:500],
        )
    return None


def _check_security_headers(
    headers: dict[str, str], title: str,
) -> ExecutionResult | None:
    missing = []
    for header, msg in _REQUIRED_SECURITY_HEADERS.items():
        if header not in headers:
            missing.append(msg)

    if not missing:
        return None

    # Check if the finding is about a specific header
    for header, msg in _REQUIRED_SECURITY_HEADERS.items():
        short = header.replace("-", "").replace("_", "")
        if short in title.replace("-", "").replace("_", "") and header not in headers:
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence=msg,
                status_code=200,
            )

    # Generic "missing security headers" finding
    if "header" in title and missing:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence="; ".join(missing),
            status_code=200,
        )
    return None


def _check_cookie_security(headers: dict[str, str]) -> ExecutionResult | None:
    cookie = headers.get("set-cookie", "")
    if not cookie:
        return None
    issues = []
    if "secure" not in cookie.lower():
        issues.append("missing Secure flag")
    if "httponly" not in cookie.lower():
        issues.append("missing HttpOnly flag")
    if "samesite" not in cookie.lower():
        issues.append("missing SameSite flag")
    if issues:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"Insecure cookie: {', '.join(issues)}",
            status_code=200,
        )
    return None


def _check_auth_bypass(status_code: int, body: str) -> ExecutionResult | None:
    # Got 200 on a protected resource without auth = bypass confirmed
    if status_code == 200 and any(
        kw in body.lower() for kw in ("dashboard", "admin", "settings", "profile", "account")
    ):
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"Protected content returned without authentication (HTTP {status_code})",
            status_code=status_code,
            response_snippet=body[:500],
        )
    return None


def _is_upload_related(title: str, category: str) -> bool:
    return any(kw in title for kw in (
        "upload", "file upload", "unrestricted", "cwe-434", "multipart",
        "file type", "file extension",
    )) or "434" in category


# Dangerous extensions that should be blocked by upload validation
_DANGEROUS_EXTENSIONS = frozenset({
    ".php", ".phtml", ".php5", ".php7",
    ".jsp", ".jspx", ".asp", ".aspx",
    ".exe", ".sh", ".bat", ".cmd",
    ".py", ".rb", ".pl", ".cgi",
    ".svg", ".html", ".htm", ".shtml",
})

# Patterns indicating a file was successfully stored/accessible
_UPLOAD_SUCCESS_PATTERNS = re.compile(
    r"(\"(?:url|path|file_?path|location|file_?name|key|download)\"[:\s]+\"|"
    r"uploaded\s+successfully|"
    r"file\s+(?:saved|stored|created)|"
    r"(?:upload|file)\s+(?:complete|accepted))",
    re.IGNORECASE,
)


def _is_error_response(lower_body: str) -> bool:
    """Detect error responses that should not be treated as upload success."""
    error_keywords = (
        '"errors"', '"error"', "invalid", "rejected", "not allowed",
        "forbidden", "unsupported", "denied", "fail", "unauthorized",
        "missing", "required",
    )
    return any(kw in lower_body for kw in error_keywords)


def _check_file_upload(
    status_code: int, body: str, upload_filename: str,
) -> ExecutionResult | None:
    """Detect successful unrestricted file upload (CWE-434).

    Checks if:
    1. Server accepted upload with dangerous extension (200/201)
    2. Filename is reflected in response (file was stored)
    3. Response contains file URL/path indicators

    Guards against false positives from error responses (e.g. GraphQL
    returning HTTP 200 with {"errors":[...]}).
    """
    if not upload_filename:
        return None

    # Extract extension from upload filename
    ext = ""
    dot_idx = upload_filename.rfind(".")
    if dot_idx >= 0:
        ext = upload_filename[dot_idx:].lower()

    lower_body = body.lower()

    # Early exit: if response contains error indicators, it's not a
    # successful upload regardless of status code.  This prevents false
    # positives from e.g. GraphQL {"errors":[{"extensions":{"path":"$"}}]}
    is_error = _is_error_response(lower_body)

    # Check 1: Server accepted a dangerous file with 200/201
    if status_code in (200, 201) and ext in _DANGEROUS_EXTENSIONS and not is_error:
        # Filename echoed in response = file was accepted
        base_name = upload_filename.lower()
        if base_name in lower_body:
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence=(
                    f"Server accepted upload of dangerous file '{upload_filename}' "
                    f"(HTTP {status_code}) — filename echoed in response"
                ),
                status_code=status_code,
                response_snippet=body[:500],
            )

        # Response has upload success patterns
        match = _UPLOAD_SUCCESS_PATTERNS.search(body)
        if match:
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence=(
                    f"Server accepted dangerous file '{upload_filename}' "
                    f"(HTTP {status_code}): {match.group()[:80]}"
                ),
                status_code=status_code,
                response_snippet=body[:500],
            )

        # 201 Created with dangerous extension = strong signal
        if status_code == 201:
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence=(
                    f"Server returned 201 Created for dangerous file "
                    f"'{upload_filename}' — no extension validation"
                ),
                status_code=status_code,
                response_snippet=body[:500],
            )

    # Check 2: Server returned 200 with no error for dangerous file
    # (weaker signal — only conclusive if response looks like success)
    if status_code == 200 and ext in _DANGEROUS_EXTENSIONS and not is_error:
        if len(body.strip()) > 0:
            return ExecutionResult(
                conclusive=True,
                reproduced=True,
                evidence=(
                    f"Server returned HTTP 200 for dangerous file '{upload_filename}' "
                    f"with no rejection — missing file type validation"
                ),
                status_code=status_code,
                response_snippet=body[:500],
            )

    # Check 3: Server explicitly rejected = not reproduced
    if status_code in (400, 403, 415, 422) and ext in _DANGEROUS_EXTENSIONS:
        return ExecutionResult(
            conclusive=True,
            reproduced=False,
            evidence=(
                f"Server rejected dangerous file '{upload_filename}' "
                f"with HTTP {status_code} — upload validation is present"
            ),
            status_code=status_code,
            response_snippet=body[:500],
        )

    return None


def _check_server_error(
    status_code: int, headers: dict[str, str],
) -> ExecutionResult | None:
    # 5xx means the server has no graceful error handling / circuit breaker
    if status_code >= 500:
        return ExecutionResult(
            conclusive=True,
            reproduced=True,
            evidence=f"Server error (HTTP {status_code}) — missing resilience pattern",
            status_code=status_code,
        )
    return None
