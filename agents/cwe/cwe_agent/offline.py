"""Offline CWE skills runner (feature 0098).

Runs the deterministic CWE skills over a set of files with NO backend and NO
LLM, so a developer's pre-commit hook (lefthook) or a CI job can gate on new
security issues in the files a change touches. It reuses ``SKILL_MAP`` — the
exact skill set the agent runs — so the hook and the full audit cannot drift.

The skills walk a directory, not a file list, so the runner copies the given
files into a temporary tree that preserves each file's path relative to the
repo root, runs the skills over that tree, then rewrites each finding's
``file_path`` back to the developer's real path.

CLI::

    python -m cwe_agent.offline [--root DIR] [--severity high] [--format text|json] FILE...

Exit code is non-zero when any finding is at or above ``--severity`` (default
``high``), which is what blocks a commit.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from cwe_agent.skills import SKILL_MAP

# Order used by the severity gate. Anything unknown sorts to the floor so it
# never blocks on its own.
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_DEFAULT_GATE = "high"


def _materialize(files: list[str], root: str | None) -> tuple[Path, dict[str, str]]:
    """Copy ``files`` into a temp tree preserving paths relative to ``root``.

    Returns the temp root and a mapping of copied-path -> original-path.
    """
    tmp = Path(tempfile.mkdtemp(prefix="vulture-offline-"))
    root_p = Path(root).resolve() if root else None
    mapping: dict[str, str] = {}
    for raw in files:
        src = Path(raw).resolve()
        if not src.is_file():
            continue
        rel = _relative_to(src, root_p)
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        mapping[str(dst)] = str(src)
    return tmp, mapping


def _relative_to(src: Path, root: Path | None) -> Path:
    """Path of ``src`` under ``root``; its basename when ``root`` doesn't apply."""
    if root is None:
        return Path(src.name)
    try:
        return src.relative_to(root)
    except ValueError:
        return Path(src.name)


def _extract(result: object) -> list[dict]:
    """Normalise a skill's return (``{"findings": [...]}`` or a bare list)."""
    if isinstance(result, dict):
        return result.get("findings", [])
    if isinstance(result, list):
        return result
    return []


def _run_skills(root: str) -> list[dict]:
    """Run every CWE skill over ``root`` and collect their findings."""
    findings: list[dict] = []
    for fn in SKILL_MAP.values():
        # One skill raising must not sink the whole gate; skip and continue.
        try:
            findings.extend(_extract(fn(root)))
        except Exception:
            continue
    return findings


def scan_files(files: list[str], root: str | None = None) -> list[dict]:
    """Scan ``files`` with the CWE skills; findings cite the original paths."""
    tmp, mapping = _materialize(files, root)
    try:
        findings = _run_skills(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for finding in findings:
        original = mapping.get(finding.get("file_path", ""))
        if original is not None:
            finding["file_path"] = original
    return findings


def _at_or_above(findings: list[dict], severity: str) -> list[dict]:
    floor = _SEVERITY_ORDER.get(severity, _SEVERITY_ORDER[_DEFAULT_GATE])
    return [
        f
        for f in findings
        if _SEVERITY_ORDER.get(f.get("severity", "info"), 0) >= floor
    ]


def _report(findings: list[dict], blocking: list[dict], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps({"findings": findings, "blocking": blocking}, indent=2))
        return
    for f in blocking:
        print(
            f"{f.get('severity', '?').upper():8} "
            f"{f.get('file_path')}:{f.get('line_start')}  "
            f"{f.get('title')}  [{f.get('check_id')}]"
        )
    print(
        f"\n{len(blocking)} blocking finding(s) at or above gate severity."
        if blocking
        else "No blocking findings."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulture-offline-skills",
        description="Run CWE skills on files offline (no backend, no LLM).",
    )
    parser.add_argument("files", nargs="+", help="Files to scan (e.g. staged files).")
    parser.add_argument("--root", default=None, help="Repo root for relative paths.")
    parser.add_argument(
        "--severity", default=_DEFAULT_GATE, help="Minimum severity that blocks."
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)

    findings = scan_files(args.files, root=args.root)
    blocking = _at_or_above(findings, args.severity)
    _report(findings, blocking, args.format)
    return 1 if blocking else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
