"""CWE-799 (missing rate limiting) detection, file-scoped (feature 0063).

This is the one OWASP-A04/A06 capability with no prior CWE-agent equivalent;
porting it here keeps OWASP coverage after the OWASP agent stops detecting.
Suppression is file-scoped (a limiter in the SAME file), not project-wide.
"""

from cwe_agent.skills.resource_check import check_resource_management


def _cwes(path) -> set[str]:
    return {f["category"] for f in check_resource_management(str(path))["findings"]}


def test_flags_unthrottled_auth_endpoint(tmp_path):
    (tmp_path / "auth.py").write_text(
        "def login(request):\n    return authenticate(request)\n"
    )
    assert "CWE-799" in _cwes(tmp_path)


def test_no_799_when_same_file_rate_limited(tmp_path):
    (tmp_path / "auth.py").write_text(
        "@rate_limit('5/min')\ndef login(request):\n    return authenticate(request)\n"
    )
    assert "CWE-799" not in _cwes(tmp_path)


def test_unrelated_file_limiter_does_not_suppress(tmp_path):
    # File-scoped: a limiter in ANOTHER file must not suppress this endpoint.
    (tmp_path / "other.py").write_text("limiter = RateLimiter()\n")
    (tmp_path / "auth.py").write_text(
        "def signup(request):\n    return create_user(request)\n"
    )
    assert "CWE-799" in _cwes(tmp_path)


def test_non_auth_function_not_flagged(tmp_path):
    (tmp_path / "util.py").write_text(
        "def format_date(d):\n    return str(d)\n"
    )
    assert "CWE-799" not in _cwes(tmp_path)
