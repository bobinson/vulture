"""shared.tools.cookie_attributes: the attribute predicates and the call context."""
from __future__ import annotations

import re
from collections.abc import Sequence

import pytest

from shared.tools.cookie_attributes import (
    SAFE_HTTPONLY,
    SAFE_SAMESITE,
    SAFE_SECURE,
    call_open,
    cookie_context,
)

_TRIGGER = re.compile(r"(?:SetCookie|set_cookie|\.cookie)\s*\(")


def _line_of(lines: Sequence[str], marker: str) -> int:
    return next(n for n, line in enumerate(lines, start=1) if marker in line)


def _context(lines: Sequence[str], marker: str) -> str:
    n = _line_of(lines, marker)
    return cookie_context(lines, n, call_open(_TRIGGER.search(lines[n - 1])))


@pytest.mark.parametrize("text", [
    "Secure: true", "secure=True", "c.Secure = https", "secure: req.secure",
    "secure: !isDev", "Set-Cookie: a=b; Secure", "__Host-session", "__Secure-id",
    "cookie.setSecure(true)", ".secure(true)", "'secure' => true", 'c["secure"] = True',
    "SESSION_COOKIE_SECURE = True",
])
def test_secure_set(text: str) -> None:
    assert SAFE_SECURE.search(text)


@pytest.mark.parametrize("text", [
    "Secure: false", "secure=False", "secure: null", "insecure: true",
    "HttpOnly: true, Secure: false, SameSite: http.SameSiteStrictMode",
    "cookie.setSecure(false)", "'secure' => false",
])
def test_secure_not_set(text: str) -> None:
    assert not SAFE_SECURE.search(text)


@pytest.mark.parametrize("text", [
    "SameSite: http.SameSiteStrictMode", "c.SameSite = http.SameSiteLaxMode",
    "SameSite = SameSiteMode.Strict", "sameSite: 'strict'", 'samesite="Lax"',
    "Set-Cookie: a=b; SameSite=Lax",
])
def test_samesite_strict_or_lax(text: str) -> None:
    assert SAFE_SAMESITE.search(text)


@pytest.mark.parametrize("text", [
    "SameSite: http.SameSiteNoneMode", "SameSite: http.SameSiteDefaultMode",
    "sameSite: 'none'", "SameSite=None; Secure",
])
def test_samesite_none_or_default_is_unsafe(text: str) -> None:
    assert not SAFE_SAMESITE.search(text)


@pytest.mark.parametrize("text", [
    "HttpOnly: true", "httponly=True", "httpOnly: true", "cookie.setHttpOnly(true)",
    ".httpOnly(true)", "'httponly' => true", "Set-Cookie: a=b; HttpOnly",
    "session.cookie_httponly = 1", "HttpOnly = true",
])
def test_httponly_set(text: str) -> None:
    assert SAFE_HTTPONLY.search(text)


@pytest.mark.parametrize("text", [
    "HttpOnly: false", "httponly=False", "cookie.setHttpOnly(false)", "Secure: true",
    "// HttpOnly is set by the proxy",
])
def test_httponly_not_set(text: str) -> None:
    assert not SAFE_HTTPONLY.search(text)


GO = """package s

func build(v string) *http.Cookie {
	return &http.Cookie{Name: "s", Value: v,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
}

func a() {}
func b() {}
func c() {}

func set(w http.ResponseWriter, v string) {
	http.SetCookie(w, build(v)) // site
}
""".splitlines()


def test_routine_of_the_same_file_is_read() -> None:
    text = _context(GO, "// site")
    assert "HttpOnly: true" in text and "SameSiteStrictMode" in text


def test_two_definitions_of_the_name_add_nothing() -> None:
    lines = [*GO, "func (x T) build(v string) *http.Cookie { return nil }"]
    assert "HttpOnly" not in _context(lines, "// site")


def test_without_the_call_position_only_the_window_is_read() -> None:
    assert "HttpOnly" not in cookie_context(GO, _line_of(GO, "// site"))


def test_a_variable_assigned_from_a_routine_is_read() -> None:
    lines = [*GO[:-3], "func set(w http.ResponseWriter, v string) {", "\tc := build(v)",
             "\thttp.SetCookie(w, c) // site", "}"]
    assert "HttpOnly: true" in _context(lines, "// site")


def test_the_enclosing_and_neighbouring_routines_are_not_read() -> None:
    lines = """func login(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{Name: "s", Value: tok}) // site
}

func prefs(v string) *http.Cookie {
	return &http.Cookie{Name: "p", HttpOnly: true}
}
""".splitlines()
    assert "HttpOnly" not in _context(lines, "// site")


def test_python_routine_ends_at_its_indent() -> None:
    lines = """def opts():
    return {"httponly": True}


def other():
    return {"secure": True}


def login(response, token):
    response.set_cookie("sid", token, **opts())  # site
""".splitlines()
    text = _context(lines, "# site")
    assert "httponly" in text and "secure" not in text


def test_arrow_routine_on_one_line_is_read() -> None:
    lines = [
        'const opts = (v) => ({ httpOnly: true, secure: true, sameSite: "lax" });',
        "", "", "", "",
        'function login(response, token) { response.cookie("sid", token, opts(token)); } // site',
    ]
    assert "httpOnly: true" in _context(lines, "// site")


def test_multi_line_call_is_read_to_its_closing_paren() -> None:
    lines = ['res.cookie("sid", token, { // site', "  a: 1,", "  b: 2,", "  c: 3,", "  httpOnly: true,", "});"]
    assert "httpOnly" in cookie_context(lines, 1)


def test_a_name_without_a_definition_adds_nothing() -> None:
    lines = ["http.SetCookie(w, imported.Build(v)) // site"]
    assert cookie_context(lines, 1) == lines[0]
