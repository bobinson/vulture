"""Feature 0097 — an auth guard whose application is decided by a
client-controlled request attribute (unit coverage for ``access_control_check``).

The E2E contract (tests/e2e/test_0097_guard_application.py) pins the fixture
corpus. This file pins each predicate on its own: one test per veto family,
the outcome vocabulary, enclosing-scope scoping of guard evidence, the
route-matcher arm's bracket scoping, and the 807 -> 290 specialisation.

Every assertion filters by check_id, because other access_control rules fire
on the same files.

It also carries the still-valid cases of the retired framework-named skill
(``next_middleware_matcher``): the guarded ``auth-gate.ts`` / ``request-gate.ts``
middlewares stay positive (now CWE-807), and the plain-string, ``routes.ts`` and
no-config cases stay negative. Its single-line and has-cookie cases had NO guard
in the module; they are now negative, deliberately reversing that skill's
"recall by design": excluding requests from a middleware that enforces nothing
bypasses nothing, and every row here blocks the offline gate at ``high``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills._guard_application import (
    attr_vetoed,
    bracket_span,
    code_lines,
    mask_multiline,
)
from cwe_agent.skills.access_control_check import check_access_control
from shared.tools.file_scanner import clear_caches
from shared.tools.finding_collapse import collapse_line_stacks

SKIP = "cwe.access_control.guard_skip_by_request_attr"
SPOOF = "cwe.access_control.spoofable_identity_guard"
EXCLUDED = "cwe.access_control.guard_excluded_by_request_attr"
GUARD_IDS = {SKIP, SPOOF, EXCLUDED}


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _rows(tmp_path: Path, name: str, text: str) -> list[dict]:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    found = check_access_control(str(tmp_path))["findings"]
    return [f for f in found if f.get("check_id") in GUARD_IDS]


def _summary(rows: list[dict]) -> list[tuple[str, str, int]]:
    return [(r["check_id"], r["category"], r["line_start"]) for r in rows]


def _express(condition: str, tail: str = "  return res.status(401).end();\n") -> str:
    """An Express guard whose first branch is ``condition`` -> next()."""
    return (
        "module.exports = function guard(req, res, next) {\n"
        f"  if ({condition}) return next();\n"
        "  if (!req.session.user) return res.status(401).end();\n"
        f"{tail}"
        "};\n"
    )


# --------------------------------------------------------------------------- #
# Imperative arm: the positive baseline the vetoes are measured against
# --------------------------------------------------------------------------- #
def test_header_skip_before_guard_is_807(tmp_path):
    rows = _rows(tmp_path, "g.js", _express("req.headers['x-internal'] === '1'"))
    assert _summary(rows) == [(SKIP, "CWE-807", 2)]
    assert rows[0]["severity"] == "high"
    assert "x-internal" in rows[0]["description"]


def test_query_presence_skip_is_807(tmp_path):
    rows = _rows(tmp_path, "g.js", _express("req.query.debug"))
    assert _summary(rows) == [(SKIP, "CWE-807", 2)]


def test_one_hop_alias_is_followed(tmp_path):
    code = (
        "module.exports = function guard(req, res, next) {\n"
        "  const bypass = req.get('x-bypass');\n"
        "  if (bypass === 'yes') return next();\n"
        "  if (!req.session.user) return res.status(401).end();\n"
        "};\n"
    )
    assert _summary(_rows(tmp_path, "g.js", code)) == [(SKIP, "CWE-807", 3)]


# --------------------------------------------------------------------------- #
# The eight veto families — each turns the baseline silent
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("condition", [
    "req.headers.authorization",                 # credential
    "req.headers['x-api-key'] === KEY",          # credential
    "req.cookies.session",                       # credential
])
def test_veto_credential_attribute(tmp_path, condition):
    assert _rows(tmp_path, "g.js", _express(condition)) == []


@pytest.mark.parametrize("condition", [
    "req.headers['accept'] === 'text/html'",
    "req.query.format === 'csv'",                # FIX-3
    "req.query.page",                            # FIX-3
    "req.method === 'OPTIONS' || req.headers.origin",
])
def test_veto_neutral_attribute(tmp_path, condition):
    assert _rows(tmp_path, "g.js", _express(condition)) == []


def test_veto_gateway_identity_header(tmp_path):
    code = _express("req.headers['x-goog-authenticated-user-email']")
    assert _rows(tmp_path, "g.js", code) == []


def test_veto_privilege_cookie_owned_by_cookie_rule(tmp_path):
    assert _rows(tmp_path, "g.js", _express("req.cookies.isAdmin === 'true'")) == []


def test_non_privilege_cookie_is_this_rule(tmp_path):
    rows = _rows(tmp_path, "g.js", _express("req.cookies.beta === 'on'"))
    assert _summary(rows) == [(SKIP, "CWE-807", 2)]


def test_veto_role_string_owned_by_role_rule(tmp_path):
    code = (
        "module.exports = function guard(req, res, next) {\n"
        "  const role = req.headers['x-role'];\n"
        "  if (role === 'admin') return next();\n"
        "  return res.status(403).end();\n"
        "};\n"
    )
    assert _rows(tmp_path, "g.js", code) == []


@pytest.mark.parametrize("condition", [
    "req.headers['x-internal'] === process.env.INTERNAL_KEY",
    "req.headers['x-internal'] === config.internalKey",
    "req.headers['x-internal'] === internalSecret",
])
def test_veto_server_secret_comparand(tmp_path, condition):
    assert _rows(tmp_path, "g.js", _express(condition)) == []


def test_secret_comparand_does_not_excuse_an_identity_header(tmp_path):
    """A forged X-Forwarded-For matches a configured allowlist just as well."""
    code = _express("config.allowlist.includes(req.headers['x-forwarded-for'])")
    assert _summary(_rows(tmp_path, "g.js", code)) == [(SPOOF, "CWE-290", 2)]


def test_veto_verifier_on_the_line(tmp_path):
    code = _express("crypto.timingSafeEqual(Buffer.from(req.headers['x-sig']), expected)")
    assert _rows(tmp_path, "g.js", code) == []


@pytest.mark.parametrize("condition", [
    "!req.headers['x-internal']",
    "req.headers['x-internal'] === undefined",
])
def test_veto_negated_read(tmp_path, condition):
    assert _rows(tmp_path, "g.js", _express(condition)) == []


def test_go_non_empty_presence_still_fires(tmp_path):
    code = (
        "package mw\n"
        "\n"
        "func Guard(next http.Handler) http.Handler {\n"
        "\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
        '\t\tif r.Header.Get("X-Internal") != "" {\n'
        "\t\t\tnext.ServeHTTP(w, r)\n"
        "\t\t\treturn\n"
        "\t\t}\n"
        '\t\thttp.Error(w, "no", http.StatusUnauthorized)\n'
        "\t})\n"
        "}\n"
    )
    assert _summary(_rows(tmp_path, "g.go", code)) == [(SKIP, "CWE-807", 5)]


def test_veto_non_http_server_variable(tmp_path):
    code = (
        "<?php\n"
        "if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1') { return; }\n"
        "if (!current_user()) { http_response_code(403); exit; }\n"
    )
    assert _rows(tmp_path, "g.php", code) == []


# --------------------------------------------------------------------------- #
# Outcome vocabulary, FIX-1 .. FIX-4
# --------------------------------------------------------------------------- #
def test_no_outcome_no_row(tmp_path):
    """Reading a header to LOG it decides nothing."""
    code = (
        "module.exports = function guard(req, res, next) {\n"
        "  if (req.headers['x-trace']) {\n"
        "    log.info('trace', req.headers['x-trace']);\n"
        "  }\n"
        "  if (!req.session.user) return res.status(401).end();\n"
        "  return next();\n"
        "};\n"
    )
    assert _rows(tmp_path, "g.js", code) == []


def test_fix1_decorator_view_passthrough(tmp_path):
    code = (
        "from functools import wraps\n"
        "from flask import abort, request\n"
        "\n"
        "def internal_only(view):\n"
        "    @wraps(view)\n"
        "    def wrapper(*args, **kwargs):\n"
        "        if request.headers.get('X-Internal') == '1':\n"
        "            return view(*args, **kwargs)\n"
        "        abort(403)\n"
        "    return wrapper\n"
    )
    assert _summary(_rows(tmp_path, "d.py", code)) == [(SKIP, "CWE-807", 7)]


def test_fix2_named_guard_call_is_evidence(tmp_path):
    code = (
        "app.use(async (ctx, next) => {\n"
        "  if (ctx.query.debug === '1') return next();\n"
        "  await requireUser(ctx);\n"
        "  return next();\n"
        "});\n"
    )
    assert _summary(_rows(tmp_path, "k.js", code)) == [(SKIP, "CWE-807", 2)]


def test_fix4_inline_branch_body_is_the_line_only(tmp_path):
    """`if (x) log(x);` must not borrow the NEXT statement's `return next()`."""
    code = (
        "module.exports = function guard(req, res, next) {\n"
        "  if (req.headers['x-debug']) console.log('debug');\n"
        "  if (!req.session.user) return res.status(401).end();\n"
        "  return next();\n"
        "};\n"
    )
    assert _rows(tmp_path, "g.js", code) == []


def test_grant_flag_then_guard(tmp_path):
    code = (
        "<?php\n"
        "$authorized = false;\n"
        "if ($_GET['preview'] === 'yes') {\n"
        "    $authorized = true;\n"
        "}\n"
        "if (!$authorized && !current_user()) {\n"
        "    http_response_code(403);\n"
        "    exit('forbidden');\n"
        "}\n"
    )
    assert _summary(_rows(tmp_path, "g.php", code)) == [(SKIP, "CWE-807", 3)]


def test_grant_return_true_in_guard_function(tmp_path):
    code = (
        "export class InternalGuard {\n"
        "  canActivate(context) {\n"
        "    const req = context.switchToHttp().getRequest();\n"
        "    if (req.headers['x-internal-call'] === 'true') {\n"
        "      return true;\n"
        "    }\n"
        "    return this.jwt.check(req);\n"
        "  }\n"
        "}\n"
    )
    assert _summary(_rows(tmp_path, "g.ts", code)) == [(SKIP, "CWE-807", 4)]


# --------------------------------------------------------------------------- #
# Guard evidence is scoped to the ENCLOSING scope
# --------------------------------------------------------------------------- #
def test_guard_in_the_next_function_does_not_qualify_a_skip(tmp_path):
    code = (
        "function preview(req, res, next) {\n"
        "  if (req.query.preview === '1') {\n"
        "    return next();\n"
        "  }\n"
        "  res.render('page');\n"
        "}\n"
        "\n"
        "function admin(req, res) {\n"
        "  return res.status(403).end();\n"
        "}\n"
    )
    assert _rows(tmp_path, "g.js", code) == []


def test_indent_scope_ends_at_dedent(tmp_path):
    code = (
        "def preview(request, get_response):\n"
        "    if request.GET.get('preview') == '1':\n"
        "        return get_response(request)\n"
        "    return render(request, 'page.html')\n"
        "\n"
        "def admin(request):\n"
        "    raise PermissionDenied()\n"
    )
    assert _rows(tmp_path, "g.py", code) == []


# --------------------------------------------------------------------------- #
# 290 versus 807
# --------------------------------------------------------------------------- #
def test_identity_header_compared_is_290_and_replaces_807(tmp_path):
    rows = _rows(tmp_path, "g.js", _express("req.headers['x-real-ip'] === '10.0.0.1'"))
    assert _summary(rows) == [(SPOOF, "CWE-290", 2)]


def test_identity_header_presence_only_is_silent(tmp_path):
    assert _rows(tmp_path, "g.js", _express("req.headers['x-forwarded-for']")) == []


def test_server_observed_address_is_not_a_client_read(tmp_path):
    assert _rows(tmp_path, "g.js", _express("ALLOW.includes(req.ip)")) == []


# --------------------------------------------------------------------------- #
# Route-matcher (declarative) arm
# --------------------------------------------------------------------------- #
_GUARDED_PROXY = (
    "export function proxy(request) {\n"
    "  if (request.headers.get('x-action-secret') !== process.env.ACTION_SECRET) {\n"
    "    return new Response('no', { status: 403 });\n"
    "  }\n"
    "}\n"
)


def test_two_entry_missing_array_is_one_row(tmp_path):
    code = _GUARDED_PROXY + (
        "export const config = {\n"
        "  matcher: [{\n"
        "    source: '/api/(.*)',\n"
        "    missing: [\n"
        "      { type: 'header', key: 'next-router-prefetch' },\n"
        "      { type: 'header', key: 'purpose', value: 'prefetch' },\n"
        "    ],\n"
        "  }],\n"
        "};\n"
    )
    assert _summary(_rows(tmp_path, "proxy.ts", code)) == [(EXCLUDED, "CWE-807", 9)]


def test_two_matcher_entries_with_conditions_are_one_row_per_matcher(tmp_path):
    code = _GUARDED_PROXY + (
        "export const config = {\n"
        "  matcher: [\n"
        "    { source: '/a/(.*)', missing: [{ type: 'header', key: 'next-router-prefetch' }] },\n"
        "    { source: '/b/(.*)', has: [{ type: 'cookie', key: 'beta' }] },\n"
        "  ],\n"
        "};\n"
    )
    assert _summary(_rows(tmp_path, "proxy.ts", code)) == [(EXCLUDED, "CWE-807", 8)]


def test_trailing_comment_matcher_condition_is_silent(tmp_path):
    code = _GUARDED_PROXY + (
        "export const config = {\n"
        "  matcher: [{ source: '/api/(.*)' }], // missing: [{ type: 'header', key: 'x' }]\n"
        "};\n"
    )
    assert _rows(tmp_path, "proxy.ts", code) == []


def test_path_condition_type_is_not_a_client_attribute_exclusion(tmp_path):
    code = _GUARDED_PROXY + (
        "export const config = {\n"
        "  matcher: [{ source: '/api/(.*)', has: [{ type: 'host', value: 'example.com' }] }],\n"
        "};\n"
    )
    assert _rows(tmp_path, "proxy.ts", code) == []


def test_bracket_span_balances_on_code_not_strings():
    lines = [
        "export const config = {",
        "  matcher: [",
        "    { source: '/x]}', missing: [",
        "      { type: 'header', key: 'a' },",
        "    ] },",
        "  ],",
        "};",
    ]
    codes = code_lines(lines)
    assert bracket_span(codes, 1, 40) == 5
    assert bracket_span(codes, 2, 12) == 4


def test_bracket_span_is_capped():
    codes = code_lines(["matcher: ["] + ["  'x',"] * 100)
    assert bracket_span(codes, 0, 40) == 39


# --------------------------------------------------------------------------- #
# Code view: multi-line literals and block comments are not code
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("text", [
    'x = 1\n"""\nif request.headers.get("X"):\n"""\ny = 2',
    "a();\n/*\nif (req.headers['x']) return next();\n*/\nb();",
    "const t = `\nexample:\nif (req.headers['x']) return next();\n`;\nb();",
])
def test_code_view_blanks_lines_inside_multiline_literals(text):
    codes = code_lines(text.split("\n"))
    assert codes[2] == ""
    assert codes[0] and codes[-1]


def test_code_view_does_not_open_a_comment_inside_a_string():
    """A glob such as '/api/*' must not start a block comment."""
    lines = ["app.use('/api/*', auth);", "if (req.headers['x']) return next();", "x(); // */"]
    assert code_lines(lines)[1].startswith("if (req.headers[")


def test_mask_is_linear_on_unclosed_openers():
    """An opener that never closes must not be retried from every later offset."""
    import time
    for payload in ("`\\" * 100_000, '"\\' * 100_000, '"""\\' * 50_000, "/*" * 100_000):
        t0 = time.perf_counter()
        mask_multiline([payload])
        assert time.perf_counter() - t0 < 1.0, payload[:8]


# --------------------------------------------------------------------------- #
# Attribute vetoes are shared by the imperative and the declarative arms
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kind,name,vetoed", [
    ("header", "authorization", True),
    ("header", "x-requested-with", True),
    ("header", "access-control-request-method", True),
    ("header", "x-forwarded-user", True),
    ("cookie", "isadmin", True),
    ("header", "x-internal", False),
    ("cookie", "beta", False),
])
def test_attr_vetoed(kind, name, vetoed):
    assert attr_vetoed(kind, name) is vetoed


def test_feature_flag_conjunct_is_not_a_secret_comparand(tmp_path):
    """Veto 5 reads the comparand, not the whole line."""
    code = _express("req.query.debug === '1' && config.allowDebug")
    assert _summary(_rows(tmp_path, "g.js", code)) == [(SKIP, "CWE-807", 2)]


def test_secret_on_the_left_is_still_the_comparand(tmp_path):
    code = _express("process.env.INTERNAL_KEY === req.headers['x-internal']")
    assert _rows(tmp_path, "g.js", code) == []


# --------------------------------------------------------------------------- #
# Ported from the retired framework-named skill
# --------------------------------------------------------------------------- #
def test_ported_prefetch_header_missing_in_renamed_middleware(tmp_path):
    code = """
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export default function middleware(req: NextRequest) {
  // auth gate for every dashboard route
  if (!req.cookies.get('session')) {
    return NextResponse.redirect(new URL('/login', req.url))
  }
  return NextResponse.next()
}

export const config = {
  matcher: [
    {
      source: '/dashboard/:path*',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
      ],
    },
  ],
}
"""
    rows = _rows(tmp_path, "auth-gate.ts", code)
    assert _summary(rows) == [(EXCLUDED, "CWE-807", 17)]
    assert rows[0]["severity"] == "high"
    assert Path(rows[0]["file_path"]).name == "auth-gate.ts"


def test_ported_custom_named_handler(tmp_path):
    code = """
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

export function gate(request: NextRequest) {
  const userId = request.headers.get("x-user-id");
  if (!userId) return new NextResponse("Unauthorized", { status: 401 });
  return NextResponse.next();
}

export const config = {
  matcher: [
    {
      source: "/api/internal/(.*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
"""
    rows = _rows(tmp_path, "web/request-gate.ts", code)
    assert _summary(rows) == [(EXCLUDED, "CWE-807", 15)]
    assert Path(rows[0]["file_path"]).name == "request-gate.ts"


def test_ported_single_line_matcher_without_a_guard_is_now_silent(tmp_path):
    """Reversed on purpose: the middleware enforces nothing, so excluding
    prefetches from it bypasses nothing."""
    code = (
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) { return NextResponse.next() }\n"
        "export const config = { matcher: [{ source: '/((?!_next).*)', "
        "missing: [{ type: 'header', key: 'next-router-prefetch' }] }] }\n"
    )
    assert _rows(tmp_path, "middleware.ts", code) == []


def test_ported_single_line_matcher_with_a_guard_fires(tmp_path):
    code = (
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) {\n"
        "  if (!req.cookies.get('session')) return NextResponse.redirect(new URL('/login', req.url))\n"
        "  return NextResponse.next()\n"
        "}\n"
        "export const config = { matcher: [{ source: '/((?!_next).*)', "
        "missing: [{ type: 'header', key: 'next-router-prefetch' }] }] }\n"
    )
    assert _summary(_rows(tmp_path, "middleware.ts", code)) == [(EXCLUDED, "CWE-807", 6)]


def test_ported_has_cookie_without_a_guard_is_now_silent(tmp_path):
    code = (
        "import { NextResponse } from 'next/server'\n"
        "export default function middleware(req) { return NextResponse.next() }\n"
        "export const config = {\n"
        "  matcher: [{ source: '/admin/:path*', has: [{ type: 'cookie', key: 'preview' }] }],\n"
        "}\n"
    )
    assert _rows(tmp_path, "middleware.js", code) == []


def test_ported_plain_string_matcher_not_flagged(tmp_path):
    code = (
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) { return NextResponse.next() }\n"
        "export const config = { matcher: ['/dashboard/:path*', '/admin/:path*'] }\n"
    )
    assert _rows(tmp_path, "middleware.ts", code) == []


def test_ported_unrelated_object_not_flagged(tmp_path):
    code = (
        "export const routes = {\n"
        "  matcher: [{ source: '/x', missing: [{ type: 'header', key: 'a' }] }],\n"
        "}\n"
        "// no guard anywhere in this module\n"
    )
    assert _rows(tmp_path, "routes.ts", code) == []


def test_ported_middleware_without_config_not_flagged(tmp_path):
    code = (
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) { return NextResponse.next() }\n"
    )
    assert _rows(tmp_path, "middleware.ts", code) == []


# --------------------------------------------------------------------------- #
# Declarative arm (other frameworks): the declaration must key on the request
# --------------------------------------------------------------------------- #
def test_rails_skip_on_a_path_condition_is_silent(tmp_path):
    code = (
        "class ApiController < ApplicationController\n"
        "  before_action :authenticate_user!\n"
        "  skip_before_action :authenticate_user!, if: -> { request.path == '/health' }\n"
        "end\n"
    )
    assert _rows(tmp_path, "c.rb", code) == []


def test_rails_skip_on_a_header_fires(tmp_path):
    code = (
        "class ApiController < ApplicationController\n"
        "  before_action :authenticate_user!\n"
        "  skip_before_action :authenticate_user!, if: -> { request.headers['X-Internal'].present? }\n"
        "end\n"
    )
    assert _summary(_rows(tmp_path, "c.rb", code)) == [(EXCLUDED, "CWE-807", 3)]


# --------------------------------------------------------------------------- #
# Collapse: a residual same-line 807 row folds into the CWE-784 cookie row
# --------------------------------------------------------------------------- #
def test_same_line_807_folds_into_784():
    base = {"file_path": "a.js", "line_start": 2, "line_end": 2, "severity": "high",
            "title": "t", "description": "d"}
    cookie = {**base, "check_id": "cwe.web_security.cookie_security_decision",
              "category": "CWE-784"}
    guard = {**base, "check_id": SKIP, "category": "CWE-807"}

    kept, collapsed = collapse_line_stacks([guard, cookie])

    assert collapsed == 1
    assert [f["category"] for f in kept] == ["CWE-784"]
    assert kept[0].get("collapsed_from")
