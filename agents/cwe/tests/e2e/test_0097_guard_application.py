"""E2E business-logic contract: an auth guard whose application is decided by a
client-controlled request attribute (feature 0097).

The weakness class is framework-neutral. A protection mechanism exists, but
whether it RUNS, is SKIPPED, or is SATISFIED depends on a header, query
parameter, body field or cookie that the client sets:

  * imperative: inside the guard, a branch reads such an attribute and
    returns ``next()`` (or grants access) before the guard's own check;
  * declarative: the framework's own exclusion hook for the guard is keyed on
    such an attribute (a route matcher's ``has`` / ``missing`` condition, a
    Rails ``skip_before_action ... if:``, a Spring header matcher feeding
    ``permitAll()``, an ``.unless({ custom })``, an Echo ``Skipper``).

CWE-807 (Reliance on Untrusted Inputs in a Security Decision) is the row; when
the attribute is a client-asserted source identity (X-Forwarded-For, Host,
Referer, User-Agent, ...) and the guard compares it, CWE-290 (Authentication
Bypass by Spoofing) REPLACES the 807 row at that site.

The motivating shape is a proxy/middleware that enforces a secret header but
whose route matcher excludes every request carrying ``next-router-prefetch``:
the client sets that header and the guard never runs. A Next.js matcher is
only ONE instance of the declarative arm; nothing here is keyed on a framework
import, a filename or a file suffix.

Every row is ``high`` and blocks the offline pre-commit gate, so every row
needs three co-occurring signals; the negatives below are the shapes a single
signal would condemn.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cwe_agent.offline import main, scan_files
from cwe_agent.skills.access_control_check import check_access_control
from shared.tools.file_scanner import clear_caches

from .test_0098_offline_skills import VULNERABLE_PROXY

FIXTURES = Path(__file__).parent / "fixtures" / "guard_application"

SKIP = "cwe.access_control.guard_skip_by_request_attr"
SPOOF = "cwe.access_control.spoofable_identity_guard"
EXCLUDED = "cwe.access_control.guard_excluded_by_request_attr"
GUARD_IDS = {SKIP, SPOOF, EXCLUDED, "cwe.next_middleware_matcher.bypass"}

# fixture -> (check_id, category, line_start). Exactly ONE guard row each.
POSITIVES: dict[str, tuple[str, str, int]] = {
    "p01_next_matcher_prefetch.ts": (EXCLUDED, "CWE-807", 16),
    "p02_next_matcher_has_cookie.ts": (EXCLUDED, "CWE-807", 10),
    "p03_express_internal_header.js": (SKIP, "CWE-807", 4),
    "p04_express_debug_query.js": (SKIP, "CWE-807", 2),
    "p05_flask_before_request.py": (SKIP, "CWE-807", 8),
    "p06_django_middleware.py": (SKIP, "CWE-807", 9),
    "p07_go_nethttp.go": (SKIP, "CWE-807", 7),
    "p08_gin_query.go": (SKIP, "CWE-807", 11),
    "p09_servlet_user_agent.java": (SPOOF, "CWE-290", 11),
    "p10_php_forwarded_ip.php": (SPOOF, "CWE-290", 4),
    "p11_laravel_header.php": (SKIP, "CWE-807", 11),
    "p12_nest_guard.ts": (SKIP, "CWE-807", 10),
    "p13_express_xff_allowlist.ts": (SPOOF, "CWE-290", 7),
    "p14_rails_skip.rb": (EXCLUDED, "CWE-807", 3),
    "p15_spring_header_matcher.java": (EXCLUDED, "CWE-807", 12),
    "p16_aspnet_handler.cs": (SKIP, "CWE-807", 13),
    "p17_express_unless_custom.js": (EXCLUDED, "CWE-807", 5),
    "p18_echo_skipper.go": (EXCLUDED, "CWE-807", 11),
    "p19_flask_decorator_xff.py": (SPOOF, "CWE-290", 12),
    "p20_koa_debug_query.js": (SKIP, "CWE-807", 2),
    "p21_next_body_prefetch.ts": (SKIP, "CWE-807", 6),
    # Same shape as the root cause of CVE-2025-29927 (a framework that trusted
    # its internal `x-middleware-subrequest` marker header from the client).
    # That CVE itself is a Next.js bug fixed by upgrading Next.js; this row is
    # about application code that repeats the pattern.
    "p22_express_subrequest_marker.js": (SKIP, "CWE-807", 4),
}

NEGATIVES = sorted(p.name for p in (FIXTURES / "neg").iterdir())


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


# --------------------------------------------------------------------------- #
# (a) every positive: exactly one row, right id / CWE / severity / line
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_positive_fires_exactly_once_through_the_skill(tmp_path: Path, name: str) -> None:
    _stage(tmp_path, name, "pos")
    check_id, category, line = POSITIVES[name]

    rows = _guard_rows(_skill_rows(tmp_path))

    assert len(rows) == 1, rows
    assert rows[0]["check_id"] == check_id
    assert rows[0]["category"] == category
    assert rows[0]["severity"] == "high"
    assert rows[0]["line_start"] == line


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_positive_fires_exactly_once_through_the_offline_runner(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "pos")
    check_id, category, line = POSITIVES[name]

    rows = _guard_rows(scan_files([str(f)], root=str(tmp_path)))

    assert [(r["check_id"], r["category"], r["line_start"]) for r in rows] == [
        (check_id, category, line)
    ]
    assert rows[0]["file_path"] == str(f)


# --------------------------------------------------------------------------- #
# (b) every negative: no guard row at all
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", NEGATIVES)
def test_negative_is_silent(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert _guard_rows(_skill_rows(tmp_path)) == []
    assert _guard_rows(scan_files([str(f)], root=str(tmp_path))) == []


# --------------------------------------------------------------------------- #
# The motivating shape, and the four shapes the retired skill condemned
# --------------------------------------------------------------------------- #
def _matcher_span(text: str) -> tuple[int, int]:
    """1-based first and last line of the `matcher:` value (test oracle)."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines, 1) if "matcher:" in ln)
    end = next(i for i, ln in enumerate(lines, 1) if i > start and ln == "  ],")
    return start, end


def test_motivating_proxy_fires_once_inside_the_matcher(tmp_path: Path) -> None:
    """(e) The 0098 contract fixture: one CWE-807 row, anchored on the
    prefetch condition INSIDE the matcher, not on the guard or line 1."""
    _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    rows = _guard_rows(_skill_rows(tmp_path))

    assert len(rows) == 1, rows
    row = rows[0]
    assert (row["check_id"], row["category"], row["severity"]) == (EXCLUDED, "CWE-807", "high")
    start, end = _matcher_span(VULNERABLE_PROXY)
    assert start < row["line_start"] <= end
    assert "missing:" in VULNERABLE_PROXY.splitlines()[row["line_start"] - 1]


def test_motivating_proxy_blocks_the_offline_gate(tmp_path: Path) -> None:
    """(f) The offline CLI exits 1 on the motivating shape at --severity high."""
    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    assert main(["--root", str(tmp_path), "--severity", "high", str(f)]) == 1


def test_anchor_is_the_matcher_condition_not_the_first_has_key(tmp_path: Path) -> None:
    """An unrelated `has:` earlier in the module must not steal the anchor."""
    text = (
        'import { NextResponse, type NextRequest } from "next/server";\n'
        "const flags = { has: [1], missing: [] };\n"
        "\n"
        "export function proxy(request: NextRequest) {\n"
        '  if (request.headers.get("x-action-secret") !== process.env.ACTION_SECRET) {\n'
        '    return new NextResponse("no", { status: 403 });\n'
        "  }\n"
        "  return NextResponse.next();\n"
        "}\n"
        "\n"
        "export const config = {\n"
        "  matcher: [\n"
        '    { source: "/api/(.*)",\n'
        '      missing: [{ type: "header", key: "next-router-prefetch" }] },\n'
        "  ],\n"
        "};\n"
    )
    _write(tmp_path, "proxy.ts", text)

    rows = _guard_rows(_skill_rows(tmp_path))

    assert [(r["check_id"], r["line_start"]) for r in rows] == [(EXCLUDED, 14)]


def test_quoted_keys_are_the_same_matcher(tmp_path: Path) -> None:
    """A matcher written with quoted keys (JSON style) is the same exclusion."""
    text = (
        "export function proxy(req) {\n"
        "  if (!req.cookies.get('session')) {\n"
        "    return Response.redirect(new URL('/login', req.url));\n"
        "  }\n"
        "}\n"
        "export const config = {\n"
        '  "matcher": [\n'
        '    { "source": "/app/(.*)",\n'
        '      "missing": [{ "type": "header", "key": "next-router-prefetch" }] },\n'
        "  ],\n"
        "};\n"
    )
    _write(tmp_path, "gate.js", text)

    rows = _guard_rows(_skill_rows(tmp_path))

    assert [(r["check_id"], r["category"], r["line_start"]) for r in rows] == [
        (EXCLUDED, "CWE-807", 9)
    ]


def test_config_exported_by_name_is_detected(tmp_path: Path) -> None:
    """`const config = {...}; export { config }` is the same declaration;
    detection does not depend on how (or whether) the config is exported."""
    text = (
        "import { NextResponse } from 'next/server'\n"
        "import { getToken } from 'next-auth/jwt'\n"
        "async function gate(req) {\n"
        "  const token = await getToken({ req })\n"
        "  if (!token) return NextResponse.redirect(new URL('/login', req.url))\n"
        "  return NextResponse.next()\n"
        "}\n"
        "const config = {\n"
        "  matcher: [{ source: '/admin/:path*', has: [{ type: 'query', key: 'preview' }] }],\n"
        "}\n"
        "export { gate as middleware, config }\n"
    )
    _write(tmp_path, "edge.ts", text)

    rows = _guard_rows(_skill_rows(tmp_path))

    assert [(r["check_id"], r["line_start"]) for r in rows] == [(EXCLUDED, 9)]


def test_i18n_middleware_with_prefetch_exclusion_is_silent(tmp_path: Path) -> None:
    """Excluding prefetches from a locale-redirect middleware bypasses nothing."""
    text = (
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(request) {\n"
        "  const locale = request.headers.get('accept-language')?.split(',')[0] || 'en'\n"
        "  if (request.nextUrl.pathname.startsWith(`/${locale}`)) return NextResponse.next()\n"
        "  return NextResponse.redirect(new URL(`/${locale}${request.nextUrl.pathname}`, request.url))\n"
        "}\n"
        "export const config = {\n"
        "  matcher: [{ source: '/((?!_next).*)', missing: [{ type: 'header', key: 'next-router-prefetch' }] }],\n"
        "}\n"
    )
    f = _write(tmp_path, "middleware.ts", text)

    assert _guard_rows(_skill_rows(tmp_path)) == []
    assert main(["--root", str(tmp_path), "--severity", "high", str(f)]) == 0


# --------------------------------------------------------------------------- #
# (c) overlap: neighbouring rules still own their shapes, nothing doubles up
# --------------------------------------------------------------------------- #
def test_privilege_cookie_stays_with_the_cookie_rule(tmp_path: Path) -> None:
    """CWE-784 owns a privilege cookie; no 807 row is stacked on it."""
    f = _stage(tmp_path, "n13_priv_cookie_784.js", "neg")

    findings = scan_files([str(f)], root=str(tmp_path))

    assert [x["category"] for x in findings
            if x.get("check_id") == "cwe.web_security.cookie_security_decision"] == ["CWE-784"]
    assert _guard_rows(findings) == []


def test_rate_limit_key_stays_with_the_resource_rule(tmp_path: Path) -> None:
    f = _stage(tmp_path, "n17_ratelimit_xff.js", "neg")

    findings = scan_files([str(f)], root=str(tmp_path))

    assert [x["category"] for x in findings
            if x.get("check_id") == "cwe.resource.spoofable_rate_limit_key"] == ["CWE-807"]
    assert _guard_rows(findings) == []


def test_role_string_from_a_header_stays_with_the_role_rule(tmp_path: Path) -> None:
    """A privileged role literal compared to a header read is CWE-863's row."""
    text = (
        "module.exports = function adminOnly(req, res, next) {\n"
        "  const role = req.headers['x-user-role'];\n"
        "  if (role === 'admin') return next();\n"
        "  return res.status(403).send('forbidden');\n"
        "};\n"
    )
    f = _write(tmp_path, "admin.js", text)

    findings = scan_files([str(f)], root=str(tmp_path))

    assert [(x["category"], x["line_start"]) for x in findings
            if x.get("check_id") == "cwe.access_control.role_string_cmp"] == [("CWE-863", 3)]
    assert _guard_rows(findings) == []


def test_trust_proxy_stays_with_the_configuration_rule(tmp_path: Path) -> None:
    """A server-derived address behind `trust proxy` is CWE-348's finding."""
    text = (
        "const express = require('express');\n"
        "const app = express();\n"
        "app.set('trust proxy', true);\n"
        "app.use((req, res, next) => {\n"
        "  if (ALLOWED.includes(req.ip)) return next();\n"
        "  return res.status(403).end();\n"
        "});\n"
    )
    f = _write(tmp_path, "server.js", text)

    findings = scan_files([str(f)], root=str(tmp_path))

    assert [x["category"] for x in findings
            if x.get("check_id") == "cwe.configuration.trust_proxy"] == ["CWE-348"]
    assert _guard_rows(findings) == []


# --------------------------------------------------------------------------- #
# (d) the framework-named skill is retired into access_control
# --------------------------------------------------------------------------- #
def test_framework_named_skill_is_retired() -> None:
    from cwe_agent.config import AGENT_INFO, ALL_CATEGORIES
    from cwe_agent.skills import SKILL_MAP

    assert "next_middleware_matcher" not in SKILL_MAP
    assert "next_middleware_matcher" not in ALL_CATEGORIES
    assert "next_middleware_matcher_check" not in AGENT_INFO["skills"]
    assert "access_control" in SKILL_MAP
    assert "access_control" in ALL_CATEGORIES


def test_no_row_uses_the_framework_named_check_id(tmp_path: Path) -> None:
    for name in POSITIVES:
        _stage(tmp_path, name, "pos")

    ids = {f["check_id"] for f in _skill_rows(tmp_path)}

    assert "cwe.next_middleware_matcher.bypass" not in ids
    assert {SKIP, SPOOF, EXCLUDED} <= ids
