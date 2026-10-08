"""Next.js middleware matcher-bypass detection skill (CWE-288).

A Next.js middleware module gates auth for every route its ``export const
config.matcher`` selects. The ADVANCED object form of ``matcher`` admits
``missing`` and ``has`` conditions keyed on a request attribute — a header, a
cookie, or a query param — all of which the CLIENT controls. A request shaped
to violate a ``missing`` (or satisfy an inverse ``has``) is EXCLUDED from the
matcher, so the middleware never runs and its auth gate is skipped. This is the
CVE-2025-29927 class: authentication bypass using an alternate path or channel.

Detection is content-based, not filename-based: middleware is often wired from
a module that is not named ``middleware.ts``, so keying on the filename would
miss it. A module counts as
Next.js middleware only when it imports from ``next/server`` AND exports a
middleware entry; a plain object that merely spells ``matcher``/``missing`` is
not flagged. The skill is deterministic and LLM-free, so it fires on every scan
(stop hook, CI) regardless of ``VULTURE_LLM_TIER3``; a downstream LLM-verify
gate adjudicates precision, so detection is tuned for recall.
"""

import re
from pathlib import Path

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

# A module is Next.js middleware when it both imports from next/server and
# declares the middleware `config` export. The handler function is NOT required
# to be named `middleware`: Next.js lets the file's middleware handler carry any
# name while the wiring lives in a sibling re-export.
# `export const config = { matcher }` is the reliable module marker.
_NEXT_SERVER_IMPORT = re.compile(r"""['"]next/server['"]""")
_CONFIG_EXPORT = re.compile(
    r"export\s+(?:const\s+config\b|\{[^}]*\bconfig\b[^}]*\})",
)

# `matcher:` must be declared (the advanced object form lives under it), and a
# `missing`/`has` condition is the bypass itself. Both are required: a matcher
# with no missing/has is the safe path-only form.
_MATCHER_KEY = re.compile(r"\bmatcher\s*:")
_MISSING_OR_HAS = re.compile(r"\b(?:missing|has)\s*:")

_JS_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}

_FIELDS = {
    "category": "CWE-288",
    "check_id": "cwe.next_middleware_matcher.bypass",
    "title": "Next.js middleware matcher allows authentication bypass",
    "description": (
        "Next.js middleware config.matcher uses a missing/has condition at line "
        "{line}; a client controlling the referenced header, cookie, or query can "
        "shape a request the matcher excludes, skipping the middleware and its "
        "auth gate"
    ),
    "recommendation": (
        "Do not gate authentication with matcher missing/has conditions. Match "
        "routes by path only and enforce auth inside the middleware body; also "
        "ensure the x-middleware-subrequest header is not trusted (CVE-2025-29927)"
    ),
}


def check_next_middleware_matcher(source_path: str) -> dict:
    """Flag Next.js middleware whose matcher admits an auth-bypass path.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of matcher-bypass issues.
    """
    findings: list[dict] = []
    for file_path in scan_code_files(source_path):
        if _skip_file(file_path):
            continue
        _analyze_file(file_path, findings)
    return {"findings": findings}


def _skip_file(path: Path) -> bool:
    """Generated/test files and non-JS/TS sources carry no Next middleware."""
    if is_generated_file(path) or is_test_file(path):
        return True
    return path.suffix.lower() not in _JS_SUFFIXES


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    lines = read_file_lines(file_path)
    if lines is None:
        return
    if not _is_next_middleware("\n".join(lines)):
        return
    line_num = _matcher_bypass_line(lines)
    if line_num is None:
        return
    _emit(findings, file_path, line_num, lines)


def _is_next_middleware(text: str) -> bool:
    """next/server import AND a `config` export mark a middleware module."""
    return bool(_NEXT_SERVER_IMPORT.search(text) and _CONFIG_EXPORT.search(text))


def _matcher_bypass_line(lines: tuple[str, ...]) -> int | None:
    """1-indexed line of the first missing/has condition, if a matcher exists."""
    if not any(_MATCHER_KEY.search(line) for line in lines):
        return None
    for idx, line in enumerate(lines):
        if _MISSING_OR_HAS.search(line):
            return idx + 1
    return None


def _emit(
    findings: list[dict], file_path: Path, line_num: int, lines: tuple[str, ...]
) -> None:
    finding = {
        **_FIELDS,
        "severity": "high",
        "description": _FIELDS["description"].format(line=line_num),
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "code_snippet": extract_snippet(lines, line_num),
    }
    findings.append(enrich_finding(finding, "288"))


check_next_middleware_matcher_tool = function_tool(check_next_middleware_matcher)
