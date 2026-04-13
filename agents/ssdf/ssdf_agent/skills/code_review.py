"""PW.7 - Code review audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe
from ssdf_agent.skills._ci_utils import gather_ci_content

_PR_TEMPLATE_NAMES = {
    "pull_request_template.md", "pull_request_template.txt",
    "merge_request_template.md",
}

_REVIEW_REQUIRED_PATTERNS = re.compile(
    r"required_reviewers|required.?approving.?reviews|reviewers|approve|codeowners",
    re.IGNORECASE,
)


def check_code_review(source_path: str) -> dict:
    """Check for code review processes (PW.7).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _find_pr_template(root):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.pw7.no_pr_template",
            "category": "PW-produce-well-secured-software",
            "title": "No PR/MR template found",
            "description": "No pull request template with review checklist found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a PULL_REQUEST_TEMPLATE.md with security review checklist",
        })

    ci_content = _gather_review_content(root)
    if not _REVIEW_REQUIRED_PATTERNS.search(ci_content):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.pw7.no_required_reviews",
            "category": "PW-produce-well-secured-software",
            "title": "No required review configuration found",
            "description": "No required reviewer or approval configuration found in CI or branch rules",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Configure required reviewers and approval rules for code changes",
        })

    return {"findings": findings}


def _find_pr_template(root: Path) -> bool:
    """Check for PR template files."""
    github_dir = root / ".github"
    if github_dir.is_dir():
        for item in github_dir.iterdir():
            if item.name.lower() in _PR_TEMPLATE_NAMES:
                return True
    for item in root.iterdir():
        if item.is_file() and item.name.lower() in _PR_TEMPLATE_NAMES:
            return True
    return False


def _gather_review_content(root: Path) -> str:
    """Gather CI content + CODEOWNERS for review policy detection."""
    base = gather_ci_content(root)
    extras: list[str] = []
    for codeowners in (root / "CODEOWNERS", root / ".github" / "CODEOWNERS"):
        if codeowners.exists():
            extras.append("codeowners required_reviewers")
    if extras:
        return base + "\n" + "\n".join(extras)
    return base


check_code_review_tool = function_tool(check_code_review)
