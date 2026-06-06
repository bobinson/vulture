"""PO.4 - Security criteria audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from ssdf_agent.skills._ci_utils import gather_ci_content

_QUALITY_GATE_PATTERNS = re.compile(
    r"required_status_checks|branch_protection|status.?check|if:\s*failure\(\)|quality.?gate",
    re.IGNORECASE,
)

_MERGE_POLICY_FILES = {
    "pull_request_template.md",
    "pull_request_template.txt",
}


def check_security_criteria(source_path: str) -> dict:
    """Check for security criteria and quality gates (PO.4).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []
    ci_content = gather_ci_content(root)

    if not _QUALITY_GATE_PATTERNS.search(ci_content):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.po4.no_quality_gates",
            "category": "PO-prepare-organization",
            "title": "No security quality gates in CI/CD",
            "description": "No required status checks or quality gates found in CI configuration",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Configure required status checks and branch protection rules",
        })

    if not _find_merge_policy(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.po4.no_merge_policy",
            "category": "PO-prepare-organization",
            "title": "No PR template or merge policy found",
            "description": "No pull request template defining review checklists and merge criteria",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a PULL_REQUEST_TEMPLATE.md with security review checklist",
        })

    return {"findings": findings}


def _find_merge_policy(root: Path) -> bool:
    """Check for PR template or merge policy files."""
    github_dir = root / ".github"
    if github_dir.is_dir():
        for item in github_dir.iterdir():
            if item.name.lower() in _MERGE_POLICY_FILES:
                return True
    for item in root.iterdir():
        if item.is_file() and item.name.lower() in _MERGE_POLICY_FILES:
            return True
    return False


check_security_criteria_tool = function_tool(check_security_criteria)
