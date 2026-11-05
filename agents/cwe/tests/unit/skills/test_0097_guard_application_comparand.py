"""Feature 0097 re-audit: unit coverage for the comparand model (veto 5), the
CSRF vocabulary (veto 1) and the verifying conjunct (veto 6) of the
guard-application rule.

Veto 5: equality of a NON-identity attribute with a value the client cannot
know is a shared secret (authentication), not a bypass. A value the client
CAN know is a literal that is the WHOLE comparand, or an identifier
(optionally ``X.`` / ``X::`` qualified) bound in the same file only to
non-placeholder literals.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cwe_agent.skills._guard_application import (
    BARE_ELSE,
    FEATURE_GATE,
    GUARD_REDIRECT,
    PRINCIPAL_RETURN,
    VERIFIER,
    FileView,
    attr_vetoed,
    code_lines,
    is_client_knowable,
    raw_comparand,
)
from cwe_agent.skills.access_control_check import check_access_control
from shared.tools.file_scanner import clear_caches

SKIP = "cwe.access_control.guard_skip_by_request_attr"


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _view(text: str = "") -> FileView:
    lines = text.splitlines()
    return FileView(lines, code_lines(lines), lambda _code: False, ())


# --------------------------------------------------------------------------- #
# is_client_knowable: the truth table
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("comparand", ["'1'", '"true"', "1", "true", "None", "`x`"])
def test_a_whole_literal_is_client_knowable(comparand: str) -> None:
    assert is_client_knowable(comparand, _view())


@pytest.mark.parametrize(("comparand", "source"), [
    ("BYPASS", 'const BYPASS = "1"'),
    ("BYPASS", "const BYPASS = '1'; // dev"),
    ("BYPASS", 'BYPASS = "on"  # local'),
    ("bypassValue", 'var bypassValue string = "1"'),
    ("BYPASS", 'private const val BYPASS = "1"'),
    ("B", 'private static final String B = "1";'),
    ("Mode.Bypass", "enum Mode { Bypass = 'on' }"),
    ("self::BYPASS", "const BYPASS = '1';"),
    ("Flags.BYPASS", 'BYPASS = "1"'),
])
def test_an_identifier_bound_to_a_literal_is_client_knowable(comparand: str, source: str) -> None:
    assert is_client_knowable(comparand, _view(source))


@pytest.mark.parametrize("comparand", [
    "process.env.X", "this.token", "config('a')", "settings.X", "`${a}`", "`Bearer ${T}`",
    "'cron:' + SECRET", "s.cfg.Key", "UNBOUND_NAME",
])
def test_a_server_held_value_is_not_client_knowable(comparand: str) -> None:
    assert not is_client_knowable(comparand, _view())


@pytest.mark.parametrize(("comparand", "source"), [
    ("expected", "expected = settings.T"),
    ("internalToken", "let internalToken = ''\ninternalToken = process.env.T"),
    ("SERVICE_KEY", 'SERVICE_KEY = None\nSERVICE_KEY = app.config["K"]'),
    ("process.env.TOKEN", "const TOKEN = 'dev'"),
    ("this.token", "const token = 'x'"),
])
def test_a_binding_that_is_not_only_literal_is_server_held(comparand: str, source: str) -> None:
    assert not is_client_knowable(comparand, _view(source))


@pytest.mark.parametrize(("comparand", "source"), [
    # a field default read through an INSTANCE is loaded at runtime
    ("settings.internal_token", 'class Settings(BaseSettings):\n    internal_token: str = "change-me"'),
    ("cfg.service_key", '@dataclass\nclass Config:\n    service_key: str = "unset"'),
    ("config.internalKey", "class AppConfig {\n  internalKey = 'dev-key';\n}"),
    # a parameter default on a wrapped parameter list
    ("sharedKey", "export function internalOnly(\n  sharedKey = 'local-dev',\n  options = {},\n) {"),
    # an object member binds only QUALIFIED by its object, not as a bare name
    ("debug", "const MODES = { debug: 'on' };"),
    ("OTHER.debug", "const MODES = { debug: 'on' };"),
    # an imported name that falls back to a literal
    ("INTERNAL_TOKEN", 'try:\n    from local_settings import INTERNAL_TOKEN\n'
                       'except ImportError:\n    INTERNAL_TOKEN = "dev-only"'),
])
def test_a_runtime_loaded_default_is_server_held(comparand: str, source: str) -> None:
    assert not is_client_knowable(comparand, _view(source))


@pytest.mark.parametrize(("comparand", "source"), [
    ("BYPASS", "const BYPASS = 'on' as const;"),
    ("ON", "const ON = '1', OFF = '0';"),
    ("OFF", "const ON = '1', OFF = '0';"),
    ("FLAGS.BYPASS", "const FLAGS = Object.freeze({ BYPASS: 'yes' });"),
    ("MODES.debug", "const MODES = { debug: 'on' };"),
    ("Mode.Bypass", "enum Mode {\n  Bypass = 'on',\n  Other = 'off',\n}"),
    ("BYPASS", "app.use((req, res, next) => {\n  const BYPASS = '1';"),
    ("BYPASS", "const (\n\tBYPASS = \"1\"\n)"),
])
def test_common_literal_declaration_shapes_are_client_knowable(comparand: str, source: str) -> None:
    assert is_client_knowable(comparand, _view(source))


@pytest.mark.parametrize(("text", "knowable"), [
    ('if (Objects.equals(request.getHeader("X-Internal"), "true")) {', True),
    ('if (StringUtils.equals(request.getHeader("X-Internal"), "true")) {', True),
    ('if (Objects.equals(request.getHeader("X-Internal"), internalKey)) {', False),
    ('if (INTERNAL.equals(request.getHeader("X-Internal"))) {', False),
    ('if ("true".equals(request.getHeader("X-Internal"))) {', True),
])
def test_the_comparand_of_a_static_equals_is_its_other_argument(text: str, knowable: bool) -> None:
    m = re.search(r'request\.getHeader\("X-Internal', text)
    c = raw_comparand(text, m.start(), m.end()).strip()

    assert c
    assert is_client_knowable(c, _view()) is knowable


def test_raw_comparand_skips_a_default_argument() -> None:
    text = 'request.headers.get("X", "") == T'
    m = re.search(r'"X', text)

    assert raw_comparand(text, m.start(), m.end()) == "T"


# --------------------------------------------------------------------------- #
# veto 1: CSRF vocabulary
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", [
    "x-csrftoken", "csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token",
    "x-xsrf-token", "x-csrf-token", "csrftoken",
])
def test_csrf_names_are_vetoed(name: str) -> None:
    assert attr_vetoed("header", name)


def test_a_csrf_prefixed_mode_name_is_not_a_credential() -> None:
    assert not attr_vetoed("header", "x-csrf-mode")


@pytest.mark.parametrize("name", [
    "auth_token", "api_token", "x-api-token", "x-auth-token", "bearer-token",
    "signature", "x-signature", "x-hub-signature-256",
])
def test_token_and_signature_names_are_credentials(name: str) -> None:
    assert attr_vetoed("header", name)


# --------------------------------------------------------------------------- #
# feature / selection gates: a gate word in a name with no bypass word
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", [
    "beta_opt_in", "x-beta", "cf_clearance", "consent", "cookie_consent", "x-tenant-id", "tenant",
    "x-api-version", "api-version", "x-client-version",
])
def test_feature_and_selection_gate_names(name: str) -> None:
    assert FEATURE_GATE.match(name)


@pytest.mark.parametrize("name", [
    "x-admin-clearance", "skip_auth_variant", "x-internal-bypass-beta", "beta_admin_bypass",
    "debug", "x-internal",
])
def test_a_bypass_name_is_not_a_feature_gate(name: str) -> None:
    assert not FEATURE_GATE.match(name)


# --------------------------------------------------------------------------- #
# guard evidence and outcomes
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    "return res.redirect('/login');",
    "return redirect(url_for('auth.login'))",
    "return NextResponse.redirect(new URL('/signin', req.url))",
    'return res.redirect(302, "/auth/signin")',
])
def test_a_login_redirect_is_guard_evidence(text: str) -> None:
    assert GUARD_REDIRECT.search(text)


@pytest.mark.parametrize("text", [
    "return res.redirect(301, `https://${req.hostname}${req.originalUrl}`);\n}\nfunction auth(req, res, next) {",
    "return res.redirect(301, 'https://' + req.headers.host + req.url);\n}\nmodule.exports = { authenticate };",
    "return res.redirect(301, `https://${host}`); // auth",
])
def test_an_https_redirect_is_not_a_login_redirect(text: str) -> None:
    assert not GUARD_REDIRECT.search(text)


@pytest.mark.parametrize("text", ["} else {", "else:", "  else", "}else{"])
def test_bare_else(text: str) -> None:
    assert BARE_ELSE.match(text)


@pytest.mark.parametrize("text", ["} else if (x) {", "elsewhere()", "x"])
def test_not_a_bare_else(text: str) -> None:
    assert not BARE_ELSE.match(text)


@pytest.mark.parametrize("text", ["return AnonymousUser()", "return GuestUser()",
                                  "return models.AnonymousUser()"])
def test_an_anonymous_principal_grants_nothing(text: str) -> None:
    assert not PRINCIPAL_RETURN.search(text)


def test_a_returned_principal_constructor_is_a_grant() -> None:
    assert PRINCIPAL_RETURN.search("return User(id=claims['sub'])")


def test_a_constant_time_compare_is_a_verifier() -> None:
    assert VERIFIER.search("ActiveSupport::SecurityUtils.secure_compare(a, b)")


# --------------------------------------------------------------------------- #
# veto 6: a verifying call conjoined with the read
# --------------------------------------------------------------------------- #
def _rows(tmp_path: Path, name: str, text: str) -> list[tuple[str, int]]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    found = check_access_control(str(tmp_path))["findings"]
    return [(f["check_id"], f["line_start"]) for f in found if f.get("check_id") == SKIP]


def test_a_feature_flag_conjunct_does_not_verify(tmp_path: Path) -> None:
    text = (
        "function requireAuth(req, res, next) {\n"
        '  if (req.query.debug === "1" && isFeatureOn("debug")) return next();\n'
        "  if (!req.user) return res.status(401).end();\n"
        "  next();\n"
        "}\n"
    )
    assert _rows(tmp_path, "a.js", text) == [(SKIP, 2)]


def test_a_verifier_called_first_and_conjoined_vetoes(tmp_path: Path) -> None:
    text = (
        "def require_login(view):\n"
        "    def wrapped(request, *a, **k):\n"
        '        if check_service_jwt(request) and request.headers.get("X-Skip-Auth") == "1":\n'
        "            return view(request, *a, **k)\n"
        "        if not request.user.is_authenticated:\n"
        "            return HttpResponse(status=401)\n"
        "        return view(request, *a, **k)\n"
        "    return wrapped\n"
    )
    assert _rows(tmp_path, "a.py", text) == []
