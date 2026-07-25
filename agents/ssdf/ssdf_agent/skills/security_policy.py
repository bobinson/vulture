"""PO.1 - Security policy audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

_POLICY_FILES = {
    "security.md", "security.txt", "security.rst",
    "security-policy.md", "security-policy.txt",
}

_GITHUB_SECURITY = ".github/security.md"

_POLICY_REFS = re.compile(
    r"security\s+policy|vulnerability\s+disclosure|responsible\s+disclosure|bug\s+bounty",
    re.IGNORECASE,
)


def check_security_policy(source_path: str) -> dict:
    """Check for security policy documents (PO.1).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    # Check for dedicated security policy files
    has_policy = _find_policy_file(root)

    # Check for security policy references in README/CONTRIBUTING
    if not has_policy:
        has_policy = _find_policy_reference(root)

    if not has_policy:
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.po1.missing_security_policy",
            "category": "PO-prepare-organization",
            "title": "No security policy document found",
            "description": "No SECURITY.md or security policy documentation found in the repository",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a SECURITY.md with vulnerability disclosure and reporting procedures",
        })

    return {"findings": findings}


def _find_policy_file(root: Path) -> bool:
    """Check for dedicated security policy files."""
    for item in root.iterdir():
        if item.is_file() and item.name.lower() in _POLICY_FILES:
            return True
    github_sec = root / _GITHUB_SECURITY
    return github_sec.exists()


def _find_policy_reference(root: Path) -> bool:
    """Check for security policy references in README/CONTRIBUTING."""
    for name in ("README.md", "README.rst", "README.txt", "CONTRIBUTING.md"):
        path = root / name
        if not path.exists():
            continue
        content = read_file_safe(path)
        if content and _POLICY_REFS.search(content):
            return True
    return False


check_security_policy_tool = function_tool(check_security_policy)
