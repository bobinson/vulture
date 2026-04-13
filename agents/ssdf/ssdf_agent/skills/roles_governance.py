"""PO.2 - Roles and governance audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)

_GOVERNANCE_FILES = {
    "codeowners", "maintainers.md", "maintainers", "maintainers.txt",
    "owners", "owners.md",
}

_GITHUB_CODEOWNERS = ".github/codeowners"

_RBAC_PATTERNS = [
    re.compile(r"role.?based|rbac|permissions?\s*=|access.?control.?list", re.IGNORECASE),
    re.compile(r"@admin|@owner|@maintainer|@reviewer", re.IGNORECASE),
]


def check_roles_governance(source_path: str) -> dict:
    """Check for roles and governance definitions (PO.2).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    has_codeowners = _find_governance_file(root)
    if not has_codeowners:
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.po2.missing_codeowners",
            "category": "PO-prepare-organization",
            "title": "No CODEOWNERS or maintainers file found",
            "description": "No CODEOWNERS or MAINTAINERS file defining code ownership and review responsibilities",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a CODEOWNERS file to define code review responsibilities",
        })

    return {"findings": findings}


def _find_governance_file(root: Path) -> bool:
    """Check for governance files."""
    for item in root.iterdir():
        if item.is_file() and item.name.lower() in _GOVERNANCE_FILES:
            return True
    github_co = root / _GITHUB_CODEOWNERS
    return github_co.exists()


check_roles_governance_tool = function_tool(check_roles_governance)
