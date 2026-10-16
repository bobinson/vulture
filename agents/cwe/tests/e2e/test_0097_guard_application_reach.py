"""E2E business-logic contract, part three: the REACH and the PRECISION of the
guard-application rule after its re-audit (feature 0097).

Part one (``test_0097_guard_application.py``) fixes the weakness class and its
three arms; part two (``..._idioms.py``) fixes the idioms. This file fixes what
the re-audit found each arm still got wrong.

Precision (negatives, all in ``fixtures/guard_application/neg``, so the part-one
glob asserts them silent as well):

  * a client value compared for EQUALITY with a value the client cannot know
    (an env-loaded constant, a config call, a settings alias, a ``this.`` /
    struct field, a destructured config import, Rails credentials) is a shared
    secret, i.e. authentication, not a bypass. Only a literal that IS the whole
    comparand, or an identifier bound in the same file only to such literals,
    is a value the client can know;
  * a hand-rolled CSRF double-submit check is not a guard decision;
  * a sole 403 gate on an attribute NAMED as a feature or challenge gate
    (beta, opt-in, consent, captcha clearance) is not an auth guard unless an
    independent guard follows;
  * a verifying call (verb + credential name) conjoined with the read
    authenticates the branch.

Reach (positives in ``fixtures/guard_application/pos_reaudit``): Rails
``before_action ..., unless:/if:``, a Spring ``preHandle`` that returns true,
ASP.NET ``_next(context)``, an Auth.js re-export as the module guard, Go and
Express identity accessors (``r.UserAgent()``, ``r.Host``, ``req.hostname``),
Echo ``ErrUnauthorized``, Koa ``ctx.cookies.get``, Flask ``"X" in
request.headers``, a FastAPI dependency returning a principal, and the
``export const config = { matcher }`` shorthand. The kept-recall positives pin
that none of the precision rules eats a real bypass.

Every positive is exactly ONE ``high`` row through the skill AND through the
offline runner. These tests are the business contract. Do NOT weaken them.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from cwe_agent.offline import main, scan_files
from cwe_agent.skills.access_control_check import check_access_control
from shared.tools.file_scanner import clear_caches

FIXTURES = Path(__file__).parent / "fixtures" / "guard_application"
SKILLS_MD = Path(__file__).resolve().parents[2] / "cwe_agent" / "skills" / "SKILLS.md"

SKIP = "cwe.access_control.guard_skip_by_request_attr"
SPOOF = "cwe.access_control.spoofable_identity_guard"
EXCLUDED = "cwe.access_control.guard_excluded_by_request_attr"
GUARD_IDS = {SKIP, SPOOF, EXCLUDED}

# fixture -> (check_id, category, line_start). Exactly ONE guard row each.
POSITIVES: dict[str, tuple[str, str, int]] = {
    # reach: framework hooks and outcomes the rule did not see
    "r01_rails_before_action_unless.rb": (EXCLUDED, "CWE-807", 2),
    "r02_rails_before_action_if_param.rb": (EXCLUDED, "CWE-807", 2),
    "r03_spring_prehandle.java": (SKIP, "CWE-807", 3),
    "r04_aspnet_underscore_next.cs": (SKIP, "CWE-807", 2),
    "r05_aspnet_next_invoke.cs": (SKIP, "CWE-807", 2),
    "r06_authjs_reexport_matcher.ts": (EXCLUDED, "CWE-807", 2),
    "r10_echo_err_unauthorized.go": (SKIP, "CWE-807", 3),
    "r13_fastapi_dependency_principal.py": (SKIP, "CWE-807", 8),
    "r42_nextauth_import_default_export.ts": (EXCLUDED, "CWE-807", 4),
    # reach: accessors
    "r07_go_useragent_prefix.go": (SPOOF, "CWE-290", 3),
    "r08_go_host_equals.go": (SPOOF, "CWE-290", 3),
    "r09_express_hostname.js": (SPOOF, "CWE-290", 2),
    "r11_koa_ctx_cookie.js": (SKIP, "CWE-807", 2),
    "r12_flask_name_in_headers.py": (SKIP, "CWE-807", 9),
    "r40_flask_get_not_in_prod.py": (SKIP, "CWE-807", 9),
    "r41_flask_args_not_in.py": (SKIP, "CWE-807", 11),
    # reach: the route-matcher shorthand `config = { matcher }`
    "r14_next_matcher_shorthand.ts": (EXCLUDED, "CWE-807", 7),
    "r43_next_matcher_comma_shorthand.ts": (EXCLUDED, "CWE-807", 3),
    # kept recall: a comparand the client CAN know is still a bypass
    "r15_identifier_bound_to_literal.js": (SKIP, "CWE-807", 3),
    "r21_js_const_trailing_comment.js": (SKIP, "CWE-807", 3),
    "r22_py_const_trailing_comment.py": (SKIP, "CWE-807", 6),
    "r23_go_var_typed.go": (SKIP, "CWE-807", 5),
    "r24_kotlin_const_val.kt": (SKIP, "CWE-807", 4),
    "r25_ts_enum_member.ts": (SKIP, "CWE-807", 3),
    "r26_php_class_const.php": (SKIP, "CWE-807", 5),
    "r27_py_class_const.py": (SKIP, "CWE-807", 8),
    "r44_py_typed_final.py": (SKIP, "CWE-807", 8),
    # kept recall: a conjunct that does not verify, or a negated verifier
    "r16_membership_in_literal_set.py": (SKIP, "CWE-807", 10),
    "r32_conj_auth_bypass_enabled.js": (SKIP, "CWE-807", 2),
    "r33_conj_validate_body.js": (SKIP, "CWE-807", 2),
    "r34_py_tokenizer_ready.py": (SKIP, "CWE-807", 8),
    "r35_py_is_auth_disabled.py": (SKIP, "CWE-807", 8),
    "r36_negated_is_authenticated_conj.js": (SKIP, "CWE-807", 2),
    "r37_py_not_has_auth_token.py": (SKIP, "CWE-807", 8),
    "r38_py_not_check_jwt_first.py": (SKIP, "CWE-807", 8),
    "r39_js_neg_check_jwt_first.js": (SKIP, "CWE-807", 2),
    # kept recall: a sole gate that is NOT named as a feature gate, or one
    # that answers 401 (authentication) rather than 403
    "r17_header_sole_gate_401.js": (SKIP, "CWE-807", 2),
    "r18_beta_cookie_sole_gate_401.js": (SKIP, "CWE-807", 2),
    "r28_cookie_skip_auth_403.js": (SKIP, "CWE-807", 2),
    "r29_flask_cookie_internal_access_403.py": (SKIP, "CWE-807", 6),
    "r30_cookie_debug_unindented_nested_deny.js": (SKIP, "CWE-807", 2),
    "r31_cookie_bypass_login_sendstatus_403.js": (SKIP, "CWE-807", 2),
    # second re-audit. Kept recall: the comparand of a static two-argument
    # equals is its OTHER argument, not the receiver type
    "r45_java_objects_equals_literal.java": (SKIP, "CWE-807", 4),
    "r46_java_stringutils_equals_literal.java": (SKIP, "CWE-807", 4),
    "r47_java_objects_equals_const.java": (SKIP, "CWE-807", 5),
    # kept recall: an alias of a comparison with a literal
    "r48_alias_bool_literal.js": (SKIP, "CWE-807", 3),
    # kept recall: same-file literal constants in common declaration shapes
    "r49_ts_as_const.ts": (SKIP, "CWE-807", 3),
    "r50_js_multi_declarator.js": (SKIP, "CWE-807", 3),
    "r51_js_object_freeze_member.js": (SKIP, "CWE-807", 3),
    "r52_js_object_literal_member.js": (SKIP, "CWE-807", 3),
    # reach: a config object wrapped across lines still binds `matcher`
    "r53_next_matcher_shorthand_multiline.ts": (EXCLUDED, "CWE-807", 4),
    "r54_next_config_multiline_with_auth.ts": (EXCLUDED, "CWE-807", 5),
    # reach: ASP.NET `next(context)` and the `StatusCodes.Status401*` constant
    "r55_aspnet_next_context.cs": (SKIP, "CWE-807", 3),
    "r56_aspnet_status_constant.cs": (SKIP, "CWE-807", 3),
    "r57_aspnet_next_invoke_status_constant.cs": (SKIP, "CWE-807", 4),
    # reach: a Rails filter declaration wrapped onto a continuation line
    "r58_rails_before_action_wrapped.rb": (EXCLUDED, "CWE-807", 2),
    # reach: Flask `return None`, `req.query?.x`, Koa `ctx.request.headers`,
    # and a grant flag on `res.locals`
    "r59_flask_return_none.py": (SKIP, "CWE-807", 9),
    "r60_ts_optional_chain_query.ts": (SKIP, "CWE-807", 2),
    "r61_koa_ctx_request_header.js": (SKIP, "CWE-807", 2),
    "r62_res_locals_grant.js": (SKIP, "CWE-807", 2),
    # kept recall: the feature-gate word must be the HEAD of the name
    "r63_header_admin_clearance_403.js": (SKIP, "CWE-807", 2),
    "r64_cookie_skip_auth_variant_403.js": (SKIP, "CWE-807", 2),
    "r65_internal_bypass_beta_403.js": (SKIP, "CWE-807", 2),
    # kept recall: a negated verifier, with `await` or extra whitespace
    "r66_js_negated_await_verify.js": (SKIP, "CWE-807", 2),
    "r67_py_not_await_verify.py": (SKIP, "CWE-807", 7),
    "r68_py_not_double_space_verify.py": (SKIP, "CWE-807", 7),
    # kept recall: a twin declaration that is not an auth guard is no pair
    "r69_rails_unless_with_nonauth_twin.rb": (EXCLUDED, "CWE-807", 2),
    # kept recall: a Referer is a CSRF signal when it only answers 403, but a
    # Referer that skips a 401 guard is still a spoofable identity
    "r70_go_referer_before_401.go": (SPOOF, "CWE-290", 5),
    # kept recall: a Go `const (...)` group is a declaration, not a call
    "r71_go_const_block.go": (SKIP, "CWE-807", 9),
    # kept recall: gate vocabulary inside a bypass name is not a gate
    "r72_cookie_beta_admin_bypass_403.js": (SKIP, "CWE-807", 2),
    # kept recall: a constant inside a callback's BODY is not a parameter
    "r73_express_callback_local_const.js": (SKIP, "CWE-807", 3),
}

# The negatives added with this file (all live in neg/).
REAUDIT_NEGATIVES = (
    # shared secret: the comparand is a value the client cannot know
    "n44_shared_secret_env_const.js",
    "n45_laravel_config_call.php",
    "n46_go_package_var.go",
    "n47_spring_value_field.java",
    "n48_django_settings_alias.py",
    "n49_nest_this_field.ts",
    "n50_fastapi_module_const.py",
    "n51_go_struct_field.go",
    "n52_destructured_config_import.js",
    "n53_rails_credentials_skip.rb",
    "n54_flask_heartbeat_const.py",
    "n55_flask_default_arg_const.py",
    "n56_java_header_equals_field.java",
    "n69_concat_literal_head_secret.js",
    "n70_let_placeholder_then_env.js",
    "n71_py_none_then_init_app.py",
    "n72_template_bearer_env.js",
    "n73_shadow_param_literal_default.js",
    "n74_env_qualified_vs_same_name_literal.js",
    "n75_this_field_vs_same_name_local.ts",
    # CSRF double-submit
    "n57_flask_csrf_double_submit.py",
    "n58_express_csrf_body_session.js",
    # feature / challenge gates answering 403
    "n59_beta_cookie_403.js",
    "n60_captcha_cookie_403.js",
    "n61_beta_cookie_else_403.js",
    "n79_header_beta_opt_in_403.js",
    # a verifying conjunct
    "n62_verified_conjunct.py",
    # the new reach must not over-reach
    "n63_prehandle_logging.java",
    "n64_return_user_no_deny.py",
    "n65_go_host_routing.go",
    "n66_reexport_unrelated_module.ts",
    "n67_rails_before_action_format.rb",
    "n68_flask_not_in_headers.py",
    "n76_fastapi_version_dispatch_user.py",
    "n77_flask_user_store_lookup.py",
    "n78_rails_params_controller.rb",
    "n80_rails_params_action.rb",
    "n81_const_matcher_other_lib.ts",
    # second re-audit. A field or parameter DEFAULT read through an instance
    # (`settings.x`, `cfg.x`, `config.x`) or a parameter is loaded at runtime;
    # an imported name is not a same-file literal
    "n82_pydantic_settings_field_default.py",
    "n83_dataclass_default_via_instance.py",
    "n84_py_dataclass_default_from_env.py",
    "n85_ts_class_field_via_instance.ts",
    "n86_factory_multiline_param_default.js",
    "n87_py_try_import_fallback.py",
    # a Rails pair that chooses between two authentication methods, and
    # token / signature credentials
    "n88_rails_token_auth_pair.rb",
    "n89_rails_signature_pair_header.rb",
    "n90_rails_signed_url_pair.rb",
    "n91_rails_partner_key_pair.rb",
    # a Referer check is a CSRF defence, like Origin
    "n92_go_referer_csrf.go",
    "n93_flask_referrer_csrf.py",
    # an HTTPS / canonical-host redirect is not a login redirect, and a word
    # containing `auth` on a later line is not its target
    "n94_express_https_redirect_then_auth.js",
    "n95_proto_redirect_then_auth_export.js",
    # a constant-time compare in a Rails hook is a shared secret
    "n96_rails_secure_compare_unless.rb",
    "n97_rails_skip_secure_compare.rb",
    # a tenant / API-version selection answering 403 is not an auth guard
    "n98_spring_prehandle_tenant.java",
    "n99_spring_prehandle_api_version.java",
    # an anonymous principal grants nothing
    "n100_fastapi_anonymous_user.py",
    # a static equals against a field, and an alias of a shared-secret compare
    "n101_java_objects_equals_field.java",
    "n102_alias_bool_env.js",
    "n103_py_alias_env.py",
    # a consent cookie gate answering 403 (the gate word need not be the head)
    "n104_koa_cookie_consent_403.js",
)


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _stage(tmp_path: Path, name: str, sub: str) -> Path:
    """Copy one fixture into its own tree (fixtures live under tests/, which
    the scanner skips as test code)."""
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
    return check_access_control(str(tmp_path / "src"))["findings"]


def _gate(tmp_path: Path, f: Path) -> int:
    return main(["--root", str(tmp_path), "--severity", "high", str(f)])


def test_every_fixture_is_in_the_contract() -> None:
    staged = {p.name for p in (FIXTURES / "pos_reaudit").iterdir()}
    assert staged == set(POSITIVES)
    assert set(REAUDIT_NEGATIVES) <= {p.name for p in (FIXTURES / "neg").iterdir()}


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_reaudit_positive_fires_exactly_once(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "pos_reaudit")
    check_id, category, line = POSITIVES[name]

    rows = _guard_rows(_skill_rows(tmp_path))
    offline = _guard_rows(scan_files([str(f)], root=str(tmp_path)))

    expected = [(check_id, category, "high", line)]
    assert [(r["check_id"], r["category"], r["severity"], r["line_start"]) for r in rows] == expected
    assert [(r["check_id"], r["category"], r["severity"], r["line_start"]) for r in offline] == expected
    assert offline[0]["file_path"] == str(f)


@pytest.mark.parametrize("name", REAUDIT_NEGATIVES)
def test_reaudit_negative_is_silent(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert _guard_rows(_skill_rows(tmp_path)) == []
    assert _guard_rows(scan_files([str(f)], root=str(tmp_path))) == []


# --------------------------------------------------------------------------- #
# The offline gate: a shared secret and a feature gate no longer block a commit
# --------------------------------------------------------------------------- #
def test_shared_secret_header_does_not_block_the_offline_gate(tmp_path: Path) -> None:
    """A header compared with an env-loaded constant is authentication."""
    f = _stage(tmp_path, "n44_shared_secret_env_const.js", "neg")

    assert _gate(tmp_path, f) == 0


def test_beta_cookie_gate_does_not_block_the_offline_gate(tmp_path: Path) -> None:
    f = _stage(tmp_path, "n59_beta_cookie_403.js", "neg")

    assert _gate(tmp_path, f) == 0


def test_bypass_cookie_answering_403_still_blocks_the_offline_gate(tmp_path: Path) -> None:
    """A real bypass cookie is not a feature gate: its 403 still counts."""
    f = _stage(tmp_path, "r28_cookie_skip_auth_403.js", "pos_reaudit")

    assert _gate(tmp_path, f) == 1


# --------------------------------------------------------------------------- #
# Row detail and overlap
# --------------------------------------------------------------------------- #
def test_returned_principal_is_reported_as_satisfied(tmp_path: Path) -> None:
    """A dependency that hands back a principal built from a header does not
    skip the guard, it SATISFIES it."""
    _stage(tmp_path, "r13_fastapi_dependency_principal.py", "pos_reaudit")

    rows = _guard_rows(_skill_rows(tmp_path))

    assert len(rows) == 1
    assert "SATISFIED" in rows[0]["description"]


def test_privilege_cookie_in_koa_stays_one_cookie_rule_row(tmp_path: Path) -> None:
    """Reading Koa's `ctx.cookies.get` must not stack an 807 row on the
    privilege cookie the cookie rule (CWE-784) already owns."""
    text = (
        "app.use(async (ctx, next) => {\n"
        "  if (ctx.cookies.get('admin') === '1') {\n"
        "    return next();\n"
        "  }\n"
        "  if (!ctx.state.user) ctx.throw(401);\n"
        "  await next();\n"
        "});\n"
    )
    f = _write(tmp_path, "app.js", text)

    findings = scan_files([str(f)], root=str(tmp_path))

    assert [x["category"] for x in findings
            if x.get("check_id") == "cwe.web_security.cookie_security_decision"] == ["CWE-784"]
    assert _guard_rows(findings) == []


def test_cross_module_config_is_a_documented_limit(tmp_path: Path) -> None:
    """A matcher re-exported from another module cannot be seen from one file:
    no row, and the limit is written down."""
    text = (
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) {\n"
        "  const t = req.cookies.get('session')\n"
        "  if (!t) return NextResponse.redirect(new URL('/login', req.url))\n"
        "  return NextResponse.next()\n"
        "}\n"
        "export { config } from './mw/config'\n"
    )
    _write(tmp_path, "middleware.ts", text)

    assert _guard_rows(_skill_rows(tmp_path)) == []
    assert "export { config } from" in SKILLS_MD.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Second re-audit: the offline gate, cost, and the documented limits
# --------------------------------------------------------------------------- #
def test_settings_field_default_does_not_block_the_offline_gate(tmp_path: Path) -> None:
    """A pydantic settings field default is not what the client is compared to."""
    f = _stage(tmp_path, "n82_pydantic_settings_field_default.py", "neg")

    assert _gate(tmp_path, f) == 0


def test_rails_token_auth_pair_does_not_block_the_offline_gate(tmp_path: Path) -> None:
    f = _stage(tmp_path, "n88_rails_token_auth_pair.rb", "neg")

    assert _gate(tmp_path, f) == 0


def test_referer_csrf_check_does_not_block_the_offline_gate(tmp_path: Path) -> None:
    f = _stage(tmp_path, "n92_go_referer_csrf.go", "neg")

    assert _gate(tmp_path, f) == 0


def test_static_equals_against_a_literal_still_blocks_the_offline_gate(tmp_path: Path) -> None:
    f = _stage(tmp_path, "r45_java_objects_equals_literal.java", "pos_reaudit")

    assert _gate(tmp_path, f) == 1


def test_matcher_shorthand_arm_is_linear_in_file_size(tmp_path: Path) -> None:
    """Whether a file binds `matcher` into its config is a per-file fact: a
    file of many `const matcher` lines must not rescan the file per line."""
    line = "const matcher = [{ missing: [{ type: 'header', key: 'x' }] }];\n"
    text = line * (500_000 // len(line)) + "export default withAuth;\n"
    _write(tmp_path, "gen.js", text)

    t0 = time.perf_counter()
    _skill_rows(tmp_path)
    elapsed = time.perf_counter() - t0

    assert elapsed < 5.0, f"{elapsed:.1f}s for a 500KB file of matcher lines"


def test_unreached_shapes_are_documented_limits(tmp_path: Path) -> None:
    """A ternary skip and a Spring lambda request matcher are not reached:
    no row, and the limits are written down."""
    _write(tmp_path, "t.js", (
        "function guard(req, res, next) {\n"
        "  return req.headers['x-skip-auth'] === '1' ? next() : res.status(401).end();\n"
        "}\n"
    ))
    _write(tmp_path, "S.java", (
        "http.authorizeHttpRequests(a -> a\n"
        "    .requestMatchers(request -> \"true\".equals(request.getHeader(\"X-Internal\"))).permitAll()\n"
        "    .anyRequest().authenticated());\n"
    ))

    assert _guard_rows(_skill_rows(tmp_path)) == []
    doc = SKILLS_MD.read_text(encoding="utf-8")
    assert "ternary" in doc
    assert "lambda request matcher" in doc
