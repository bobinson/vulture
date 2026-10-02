"""Feature 0097 — the Next.js middleware matcher-bypass skill.

Context: a Next.js middleware module gates auth for every matched route. When
its ``export const config.matcher`` uses the ADVANCED object form with a
``missing`` or ``has`` condition, a client that controls the referenced request
attribute (a header such as ``next-router-prefetch``, a cookie, or a query
param) can shape a request that the matcher EXCLUDES — the middleware never
runs and the auth gate is skipped. This is the CVE-2025-29927 class:
authentication bypass using an alternate path or channel (CWE-288).

The weakness is file-content, not filename: middleware is often wired from a
module not named ``middleware.ts``. Every test therefore scans a REAL tree
through the public entry point and keys on content, so a renamed middleware is
still caught and a plain string matcher is never flagged.

Detection favours RECALL by design: a downstream LLM-verify gate adjudicates
precision, so a legitimate ``missing``/``has`` in middleware is allowed to fire
and be filtered later, but a non-middleware object is not flagged at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.next_middleware_matcher_check import check_next_middleware_matcher
from shared.tools.file_scanner import clear_caches


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(root: Path) -> list[dict]:
    return check_next_middleware_matcher(str(root))["findings"]


def _ids(findings: list[dict]) -> list[str]:
    return sorted(str(f["check_id"]) for f in findings)


# --------------------------------------------------------------------------- #
# Positive — prefetch-header exclusion, multi-line, non-standard filename
# --------------------------------------------------------------------------- #
def test_prefetch_header_missing_in_renamed_middleware(tmp_path):
    _write(
        tmp_path,
        "auth-gate.ts",
        """
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
""",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f["category"] == "CWE-288"
    assert f["severity"] == "high"
    assert Path(f["file_path"]).name == "auth-gate.ts"
    assert f["line_start"] > 0


# --------------------------------------------------------------------------- #
# Positive — handler with a custom name (not `middleware`) in a non-standard
# file. The detector must NOT require the conventional handler name; the
# `config` export is the module marker.
# --------------------------------------------------------------------------- #
def test_custom_named_handler(tmp_path):
    _write(
        tmp_path,
        "web/request-gate.ts",
        """
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
""",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f["category"] == "CWE-288"
    assert f["severity"] == "high"
    assert Path(f["file_path"]).name == "request-gate.ts"


# --------------------------------------------------------------------------- #
# Positive — single-line object form
# --------------------------------------------------------------------------- #
def test_single_line_missing_header(tmp_path):
    _write(
        tmp_path,
        "middleware.ts",
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) { return NextResponse.next() }\n"
        "export const config = { matcher: [{ source: '/((?!_next).*)', "
        "missing: [{ type: 'header', key: 'next-router-prefetch' }] }] }\n",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1, findings
    assert findings[0]["category"] == "CWE-288"


# --------------------------------------------------------------------------- #
# Positive — `has` form is the same bypass (run only when header present)
# --------------------------------------------------------------------------- #
def test_has_condition_also_flagged(tmp_path):
    _write(
        tmp_path,
        "middleware.js",
        "import { NextResponse } from 'next/server'\n"
        "export default function middleware(req) { return NextResponse.next() }\n"
        "export const config = {\n"
        "  matcher: [{ source: '/admin/:path*', has: [{ type: 'cookie', key: 'preview' }] }],\n"
        "}\n",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1, findings
    assert findings[0]["category"] == "CWE-288"


# --------------------------------------------------------------------------- #
# Negative — plain string matcher is the safe, normal form
# --------------------------------------------------------------------------- #
def test_plain_string_matcher_not_flagged(tmp_path):
    _write(
        tmp_path,
        "middleware.ts",
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) { return NextResponse.next() }\n"
        "export const config = { matcher: ['/dashboard/:path*', '/admin/:path*'] }\n",
    )
    assert _run(tmp_path) == []


# --------------------------------------------------------------------------- #
# Negative — a non-middleware module that merely has `missing:`/`has:` keys
# --------------------------------------------------------------------------- #
def test_unrelated_object_not_flagged(tmp_path):
    _write(
        tmp_path,
        "routes.ts",
        "export const routes = {\n"
        "  matcher: [{ source: '/x', missing: [{ type: 'header', key: 'a' }] }],\n"
        "}\n"
        "// no next/server import, no middleware export -- not a middleware module\n",
    )
    assert _run(tmp_path) == []


# --------------------------------------------------------------------------- #
# Negative — middleware with no config at all
# --------------------------------------------------------------------------- #
def test_middleware_without_config_not_flagged(tmp_path):
    _write(
        tmp_path,
        "middleware.ts",
        "import { NextResponse } from 'next/server'\n"
        "export function middleware(req) { return NextResponse.next() }\n",
    )
    assert _run(tmp_path) == []
