"""E2E business-logic contract for the offline skills runner (feature 0098).

The offline runner is what a developer's pre-commit hook (lefthook) and a CI job
call to scan a set of changed files with the CWE skills WITHOUT a running backend
or any LLM. It must:

  1. Flag a security issue introduced in a changed file (the Next.js middleware
     matcher bypass class, CVE-2025-29927) and exit non-zero so the commit is
     blocked.
  2. Pass cleanly (exit 0) when the changed files carry no issue at or above the
     gate severity.
  3. Report the ORIGINAL file path the developer staged, never an internal temp
     path, so the finding is actionable.
  4. Gate on a configurable minimum severity (default: high), so a lower-severity
     finding does not block a commit when the gate is set to high.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

from pathlib import Path

# Contract: a standalone module, importable without starting any agent/server.
from cwe_agent.offline import main, scan_files

# A Next.js middleware whose config.matcher carries a `missing` prefetch
# condition — the CVE-2025-29927 matcher-bypass shape.
VULNERABLE_PROXY = """\
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function proxy(request: NextRequest) {
  const secret = request.headers.get("x-action-secret");
  if (secret !== process.env.ACTION_SECRET) {
    return new NextResponse("no", { status: 403 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: [
    {
      source: "/api/actions/(.*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
"""

CLEAN_FILE = "export const add = (a: number, b: number): number => a + b;\n"


def _write(root: Path, rel: str, text: str) -> str:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return str(p)


def test_flags_introduced_matcher_bypass(tmp_path: Path) -> None:
    """A staged proxy.ts with a matcher bypass is reported as a high finding."""
    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    findings = scan_files([f], root=str(tmp_path))

    hits = [x for x in findings if x.get("check_id") == "cwe.next_middleware_matcher.bypass"]
    assert hits, "offline runner must flag the matcher bypass"
    assert hits[0]["severity"] == "high"


def test_reports_original_path_not_temp(tmp_path: Path) -> None:
    """The finding cites the developer's real path, not an internal temp copy."""
    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    findings = scan_files([f], root=str(tmp_path))
    hits = [x for x in findings if x.get("check_id") == "cwe.next_middleware_matcher.bypass"]

    assert hits[0]["file_path"] == f


def test_clean_file_has_no_high_findings(tmp_path: Path) -> None:
    """A trivial, safe file produces nothing at the gate severity."""
    f = _write(tmp_path, "frontend/util.ts", CLEAN_FILE)

    findings = scan_files([f], root=str(tmp_path))
    highs = [x for x in findings if x.get("severity") in ("high", "critical")]

    assert highs == []


def test_main_blocks_on_vulnerable_file(tmp_path: Path) -> None:
    """main() exits non-zero (blocks the commit) when a high finding is present."""
    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    code = main(["--root", str(tmp_path), "--severity", "high", f])

    assert code != 0


def test_main_passes_on_clean_file(tmp_path: Path) -> None:
    """main() exits 0 (allows the commit) when no finding meets the gate."""
    f = _write(tmp_path, "frontend/util.ts", CLEAN_FILE)

    code = main(["--root", str(tmp_path), "--severity", "high", f])

    assert code == 0


def test_severity_gate_ignores_below_threshold(tmp_path: Path) -> None:
    """A finding below the gate severity does not block the commit.

    The matcher bypass is `high`; gating at `critical` must let it through
    (exit 0) while still having detected it — proving the gate is a severity
    filter, not a detector toggle.
    """
    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    # Detected regardless of gate:
    assert any(
        x.get("check_id") == "cwe.next_middleware_matcher.bypass"
        for x in scan_files([f], root=str(tmp_path))
    )
    # But a `critical` gate does not block a `high` finding:
    assert main(["--root", str(tmp_path), "--severity", "critical", f]) == 0


# --- Additional contract coverage: output format, path modes, robustness ------


def test_json_format_emits_findings_and_blocking(tmp_path, capsys) -> None:
    """--format json prints a parseable object with findings + blocking lists."""
    import json as _json

    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)
    main(["--root", str(tmp_path), "--severity", "high", "--format", "json", f])

    out = _json.loads(capsys.readouterr().out)
    assert "findings" in out and "blocking" in out
    assert any(
        x.get("check_id") == "cwe.next_middleware_matcher.bypass"
        for x in out["blocking"]
    )


def test_root_none_falls_back_to_basename(tmp_path) -> None:
    """With no root, the file is still scanned (copied under its basename)."""
    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)

    findings = scan_files([f], root=None)

    assert any(
        x.get("check_id") == "cwe.next_middleware_matcher.bypass" for x in findings
    )


def test_missing_file_is_skipped_not_fatal(tmp_path) -> None:
    """A path that does not exist is ignored rather than crashing the gate."""
    assert scan_files([str(tmp_path / "does_not_exist.ts")], root=str(tmp_path)) == []


def test_one_failing_skill_does_not_sink_the_gate(tmp_path, monkeypatch) -> None:
    """If a single skill raises, the rest still run and the gate still reports."""
    from cwe_agent import offline

    def _boom(_root):
        raise RuntimeError("skill blew up")

    patched = dict(offline.SKILL_MAP)
    patched["_boom"] = _boom
    monkeypatch.setattr(offline, "SKILL_MAP", patched)

    f = _write(tmp_path, "frontend/proxy.ts", VULNERABLE_PROXY)
    findings = offline.scan_files([f], root=str(tmp_path))

    assert any(
        x.get("check_id") == "cwe.next_middleware_matcher.bypass" for x in findings
    )


def test_extract_normalises_list_and_unknown() -> None:
    """A skill may return {'findings': [...]}, a bare list, or neither."""
    from cwe_agent.offline import _extract

    assert _extract({"findings": [{"a": 1}]}) == [{"a": 1}]
    assert _extract([{"b": 2}]) == [{"b": 2}]
    assert _extract(None) == []


def test_file_outside_root_uses_basename(tmp_path) -> None:
    """A staged file that is not under --root still scans (basename fallback)."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    f = _write(outside, "proxy.ts", VULNERABLE_PROXY)
    other_root = tmp_path / "repo"
    other_root.mkdir()

    findings = scan_files([f], root=str(other_root))

    assert any(
        x.get("check_id") == "cwe.next_middleware_matcher.bypass" for x in findings
    )
