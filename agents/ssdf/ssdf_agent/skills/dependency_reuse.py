"""PW.4 - Dependency reuse audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe
from shared.tools.snippet import extract_snippet

_LOCK_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.sum", "poetry.lock", "Pipfile.lock",
    "Cargo.lock", "Gemfile.lock", "composer.lock",
}

_UNPINNED_PATTERNS = [
    (re.compile(r'"[^"]+"\s*:\s*"\s*\*\s*"'), "package.json"),
    (re.compile(r'"[^"]+"\s*:\s*"\s*latest\s*"'), "package.json"),
]


def check_dependency_reuse(source_path: str) -> dict:
    """Check for secure dependency management (PW.4).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _find_lock_file(root):
        findings.append({
            "severity": "high",
            "check_id": "ssdf.pw4.no_lock_file",
            "category": "PW-produce-well-secured-software",
            "title": "No dependency lock file found",
            "description": "No dependency lock file found to ensure reproducible builds",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Commit dependency lock files (package-lock.json, go.sum, poetry.lock, etc.)",
        })

    _check_unpinned_deps(root, findings)

    return {"findings": findings}


def _find_lock_file(root: Path) -> bool:
    """Check for any dependency lock file."""
    for name in _LOCK_FILES:
        if (root / name).exists():
            return True
    return False


def _check_unpinned_deps(root: Path, findings: list[dict]) -> None:
    """Check for wildcard or 'latest' dependencies."""
    pkg_json = root / "package.json"
    if not pkg_json.exists():
        return
    content = read_file_safe(pkg_json)
    if content is None:
        return
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for pattern, _ in _UNPINNED_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "severity": "medium",
                    "check_id": "ssdf.pw4.unpinned_dependencies",
                    "category": "PW-produce-well-secured-software",
                    "title": "Unpinned dependency version detected",
                    "description": f"Wildcard or 'latest' dependency version at line {i}",
                    "file_path": str(pkg_json),
                    "line_start": i,
                    "line_end": i,
                    "recommendation": "Pin dependency versions to specific semver ranges",
                    "code_snippet": extract_snippet(lines, i),
                })
                break


check_dependency_reuse_tool = function_tool(check_dependency_reuse)
