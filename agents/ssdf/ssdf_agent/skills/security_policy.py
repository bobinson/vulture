"""PO.1 - Security policy audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import present, tree_files
from ssdf_agent.skills._ci_utils import present_contents

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
            "category": "PO",
            "practice": "PO-prepare-organization",
            "title": "No security policy document found",
            "description": "No SECURITY.md or security policy documentation found in the repository",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Create a SECURITY.md with vulnerability disclosure and reporting procedures",
        })

    return {"findings": findings}


def _find_policy_file(root: Path) -> bool:
    """Check for dedicated security policy files."""
    if any(item.name.lower() in _POLICY_FILES for item in tree_files(root, depth=1)):
        return True
    return present(root, _GITHUB_SECURITY)


def _find_policy_reference(root: Path) -> bool:
    """Check for security policy references in README/CONTRIBUTING."""
    docs = present_contents(root, ("README.md", "README.rst", "README.txt", "CONTRIBUTING.md"))
    return any(_POLICY_REFS.search(content) for content in docs)


check_security_policy_tool = function_tool(check_security_policy)
