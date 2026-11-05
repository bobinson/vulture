"""E2E business-logic contract, part two: the guard-application rule across the
idioms real middleware is written in (feature 0097).

``test_0097_guard_application.py`` fixes the weakness class and its three arms.
This file fixes their REACH and their PRECISION:

  * reach: a deny written in any common idiom (``res.statusCode = 401``,
    ``writeHead``, ``createError``, Fastify ``reply.code``, FastAPI
    ``HTTPException`` / ``HTTP_401_*``, Go ``WriteHeader``, Fiber
    ``SendStatus``, Koa ``ctx.throw``, a PHP status line, a Flask ``, 401``
    tuple) is guard evidence; a skip written as ``next(); return;``, an
    if/else ``next()`` or Fiber's ``return c.Next()`` is a skip; a grant flag
    set on the request object is a grant; a spoofed identity compared by
    prefix or by map lookup is CWE-290; Fiber, Echo ``KeyAuthWithConfig``,
    ``web.ignoring()``, the Kotlin DSL, next-auth ``withAuth`` and a rewrite
    to the login page are all instances of the arms;
  * precision: a mere READ of the user's identity is not a guard (only a deny
    is, or an identity test whose own body turns the request away); a
    framework hook that only shares a line window with an auth guard (a
    Logger ``Skipper``, a Spring entry point or CSRF matcher, a Rails CSRF
    skip) is not that guard's exclusion; a verified webhook signature and a
    CORS preflight are not bypasses; code inside a block comment, a docstring
    or a template literal is not code.

Every positive is exactly ONE ``high`` row; every negative lives in
``fixtures/guard_application/neg`` and is asserted silent by the part-one
file as well. These tests are the business contract. Do NOT weaken them.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from cwe_agent.offline import scan_files
from cwe_agent.skills.access_control_check import check_access_control
from shared.tools.file_scanner import clear_caches

FIXTURES = Path(__file__).parent / "fixtures" / "guard_application"

SKIP = "cwe.access_control.guard_skip_by_request_attr"
SPOOF = "cwe.access_control.spoofable_identity_guard"
EXCLUDED = "cwe.access_control.guard_excluded_by_request_attr"
GUARD_IDS = {SKIP, SPOOF, EXCLUDED}

# fixture -> (check_id, category, line_start). Exactly ONE guard row each.
POSITIVES: dict[str, tuple[str, str, int]] = {
    # deny idioms after an imperative skip
    "q01_node_res_statuscode.js": (SKIP, "CWE-807", 2),
    "q02_node_writehead.js": (SKIP, "CWE-807", 2),
    "q03_express_create_error.js": (SKIP, "CWE-807", 2),
    "q04_fastify_reply_code.js": (SKIP, "CWE-807", 3),
    "q05_fastapi_httpexception.py": (SKIP, "CWE-807", 8),
    "q06_fastapi_http_401_constant.py": (SKIP, "CWE-807", 9),
    "q07_go_writeheader.go": (SKIP, "CWE-807", 7),
    "q08_fiber_sendstatus.go": (SKIP, "CWE-807", 4),
    "q09_php_status_line.php": (SKIP, "CWE-807", 2),
    "q10_koa_ctx_throw.js": (SKIP, "CWE-807", 2),
    "q38_flask_tuple_401.py": (SKIP, "CWE-807", 8),
    "q37_negated_identity_soft_deny.js": (SKIP, "CWE-807", 2),
    # spoofed identity compared by prefix / map membership
    "q11_flask_xff_prefix.py": (SPOOF, "CWE-290", 8),
    "q12_go_xff_hasprefix.go": (SPOOF, "CWE-290", 10),
    "q13_go_realip_map_lookup.go": (SPOOF, "CWE-290", 9),
    # skip and grant idioms
    "q14_express_next_then_return.js": (SKIP, "CWE-807", 2),
    "q15_express_if_else_next.js": (SKIP, "CWE-807", 2),
    "q16_fiber_return_next.go": (SKIP, "CWE-807", 4),
    "q17_request_flag_grant.js": (SKIP, "CWE-807", 2),
    "q18_flask_g_flag_grant.py": (SKIP, "CWE-807", 8),
    # accessors
    "q19_fiber_header_get.go": (SKIP, "CWE-807", 4),
    "q29_optional_chain_header.ts": (SKIP, "CWE-807", 2),
    "q30_servlet_named_request.java": (SKIP, "CWE-807", 4),
    "q33_hono_header.ts": (SKIP, "CWE-807", 4),
    "q34_go_header_index.go": (SKIP, "CWE-807", 7),
    "q35_symfony_headers_get.php": (SKIP, "CWE-807", 6),
    # a feature flag that ENABLES the bypass is not a server-secret comparand
    "q32_flag_conjunct_config.js": (SKIP, "CWE-807", 2),
    # declarative exclusions
    "q20_fiber_keyauth_next.go": (EXCLUDED, "CWE-807", 7),
    "q21_fiber_jwtware_filter.go": (EXCLUDED, "CWE-807", 8),
    "q22_echo_keyauth_skipper.go": (EXCLUDED, "CWE-807", 7),
    "q23_spring_web_ignoring.java": (EXCLUDED, "CWE-807", 6),
    "q24_spring_kotlin_dsl.kt": (EXCLUDED, "CWE-807", 5),
    "q25_unless_custom_function.js": (EXCLUDED, "CWE-807", 4),
    "q31_rails_cookie_skip.rb": (EXCLUDED, "CWE-807", 2),
    "q36_rails_get_header.rb": (EXCLUDED, "CWE-807", 2),
    # route matchers whose module guard is a wrapper, a re-export or a rewrite
    "q26_next_auth_with_auth.ts": (EXCLUDED, "CWE-807", 9),
    "q27_next_auth_reexport.ts": (EXCLUDED, "CWE-807", 5),
    "q28_next_rewrite_to_login.ts": (EXCLUDED, "CWE-807", 15),
}

# The precision negatives added with this file (all live in neg/).
PRECISION_NEGATIVES = (
    "n23_dnt_analytics.js",
    "n24_django_locale.py",
    "n25_laravel_setlocale.php",
    "n26_rails_csrf_skip_api.rb",
    "n27_spring_entry_point.java",
    "n28_spring_csrf_ignore.java",
    "n29_echo_logger_skipper.go",
    "n30_shopify_hmac_helper.js",
    "n31_stripe_construct_event.js",
    "n32_cors_preflight_header.ts",
    "n33_fastapi_timing.py",
    "n34_go_logging.go",
    "n35_gin_feature_flags.go",
    "n36_ab_variant.js",
    "n37_docstring_example.py",
    "n38_block_comment_unprefixed.js",
    "n39_template_literal_example.js",
    "n40_tracing_sampler.js",
    "n41_flask_metrics_hook.py",
    "n42_echo_gzip_skipper.go",
    "n43_csrf_origin_check.js",
)


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _stage(tmp_path: Path, name: str, sub: str) -> Path:
    dst = tmp_path / "src" / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / sub / name, dst)
    return dst


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    dst = tmp_path / "src" / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")
    return dst


def _guard_rows(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("check_id") in GUARD_IDS]


def _skill_rows(tmp_path: Path) -> list[dict]:
    clear_caches()  # several tests rewrite one file between scans
    return check_access_control(str(tmp_path / "src"))["findings"]


def test_every_fixture_is_in_the_contract() -> None:
    staged = {p.name for p in (FIXTURES / "pos_idioms").iterdir()}
    assert staged == set(POSITIVES)
    assert set(PRECISION_NEGATIVES) <= {p.name for p in (FIXTURES / "neg").iterdir()}


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_idiom_positive_fires_exactly_once(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "pos_idioms")
    check_id, category, line = POSITIVES[name]

    rows = _guard_rows(_skill_rows(tmp_path))
    offline = _guard_rows(scan_files([str(f)], root=str(tmp_path)))

    expected = [(check_id, category, "high", line)]
    assert [(r["check_id"], r["category"], r["severity"], r["line_start"]) for r in rows] == expected
    assert [(r["check_id"], r["category"], r["severity"], r["line_start"]) for r in offline] == expected


@pytest.mark.parametrize("name", PRECISION_NEGATIVES)
def test_precision_negative_is_silent(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert _guard_rows(_skill_rows(tmp_path)) == []
    assert _guard_rows(scan_files([str(f)], root=str(tmp_path))) == []


def test_identity_read_alone_is_not_guard_evidence(tmp_path: Path) -> None:
    """The same skip earns a row once the identity test turns the request away."""
    base = (
        "function mw(req, res, next) {\n"
        "  if (req.headers['x-quiet'] === '1') {\n"
        "    return next();\n"
        "  }\n"
        "{tail}"
        "  next();\n"
        "}\n"
    )
    _write(tmp_path, "read.js", base.replace("{tail}", "  log(currentUser(req));\n"))
    assert _guard_rows(_skill_rows(tmp_path)) == []

    _write(tmp_path, "read.js", base.replace(
        "{tail}", "  if (!currentUser(req)) return res.status(401).end();\n"))
    assert [r["line_start"] for r in _guard_rows(_skill_rows(tmp_path))] == [2]


def test_skipper_is_owned_by_its_own_config_literal(tmp_path: Path) -> None:
    """A Skipper inside the JWT config is the JWT's exclusion; the same Skipper
    in a sibling Logger config two lines below a JWT `Use` is not."""
    jwt = (
        "package main\n"
        "func wire(e *echo.Echo) {\n"
        "\te.Use(middleware.JWTWithConfig(middleware.JWTConfig{\n"
        "\t\tSkipper: func(c echo.Context) bool {\n"
        "\t\t\treturn c.QueryParam(\"debug\") == \"1\"\n"
        "\t\t},\n"
        "\t}))\n"
        "}\n"
    )
    _write(tmp_path, "a.go", jwt)
    assert [r["line_start"] for r in _guard_rows(_skill_rows(tmp_path))] == [4]

    sibling = jwt.replace(
        "\te.Use(middleware.JWTWithConfig(middleware.JWTConfig{\n",
        "\te.Use(middleware.JWT(key))\n\te.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{\n",
    )
    _write(tmp_path, "a.go", sibling)
    assert _guard_rows(_skill_rows(tmp_path)) == []


def test_spring_header_matcher_must_feed_the_permit_rule(tmp_path: Path) -> None:
    """`requestMatchers(<header matcher>).permitAll()` is an exclusion; a header
    matcher that feeds an entry point, with a path permitAll on the next line,
    is not."""
    permitted = (
        "class C {\n"
        "  SecurityFilterChain chain(HttpSecurity http) throws Exception {\n"
        "    http.authorizeHttpRequests(a -> a\n"
        "        .requestMatchers(new RequestHeaderRequestMatcher(\"X-Internal\"))\n"
        "        .permitAll()\n"
        "        .anyRequest().authenticated());\n"
        "    return http.build();\n"
        "  }\n"
        "}\n"
    )
    _write(tmp_path, "S.java", permitted)
    assert [r["line_start"] for r in _guard_rows(_skill_rows(tmp_path))] == [4]

    entry_point = permitted.replace(
        ".requestMatchers(new RequestHeaderRequestMatcher(\"X-Internal\"))",
        ".exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(ep, "
        "new RequestHeaderRequestMatcher(\"X-Internal\")))\n"
        "        .requestMatchers(\"/health\")",
    )
    _write(tmp_path, "S.java", entry_point)
    assert _guard_rows(_skill_rows(tmp_path)) == []


def test_route_matcher_arm_is_linear_in_file_size(tmp_path: Path) -> None:
    """Thousands of matcher entries in one file must not pin the audit worker:
    guard evidence is computed once per file, not once per matcher."""
    entry = "export const c{i} = {{ matcher: [{{ source: '/x', has: [{{ type: 'header', key: 'x-a' }}] }}] }};\n"
    text = "".join(entry.format(i=i) for i in range(2000)) + "if (!ok) return res.status(401).end();\n"
    _write(tmp_path, "gen.ts", text)

    t0 = time.perf_counter()
    rows = _guard_rows(_skill_rows(tmp_path))
    elapsed = time.perf_counter() - t0

    assert len(rows) == 2000
    assert elapsed < 5.0, f"{elapsed:.1f}s for 2000 matchers"
