"""RV.2 - Vulnerability remediation audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import read_file_safe, tree_files
from ssdf_agent.skills._ci_utils import present_contents

_SECURITY_ISSUE_TEMPLATE_NAMES = {
    "bug_report.md", "bug_report.yml",
    "security_vulnerability.md", "security_vulnerability.yml",
    "security-report.md",
}

_PATCHING_SLA_PATTERNS = re.compile(
    r"sla|response.?time|remediation.?timeline|patch.?within|fix.?within|days?\s+to\s+fix",
    re.IGNORECASE,
)

_AUTO_MERGE_PATTERNS = re.compile(
    r"auto.?merge|mergify|dependabot.*auto|renovate.*auto",
    re.IGNORECASE,
)


def check_vuln_remediation(source_path: str) -> dict:
    """Check for vulnerability remediation processes (RV.2).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _find_security_issue_template(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.rv2.no_security_issue_template",
            "category": "RV",
            "practice": "RV-respond-to-vulnerabilities",
            "title": "No security issue template found",
            "description": "No dedicated security bug/vulnerability issue template found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Create a security vulnerability issue template in .github/ISSUE_TEMPLATE/",
        })

    security_docs = _gather_security_docs(root)
    if not _PATCHING_SLA_PATTERNS.search(security_docs):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.rv2.no_patching_sla",
            "category": "RV",
            "practice": "RV-respond-to-vulnerabilities",
            "title": "No patching SLA or remediation timeline defined",
            "description": "No vulnerability patching SLA or remediation timeline found in security docs",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Define remediation timelines (e.g., critical: 24h, high: 7d) in security policy",
        })

    return {"findings": findings}


def _find_security_issue_template(root: Path) -> bool:
    """Check for security issue templates."""
    return any(
        item.name.lower() in _SECURITY_ISSUE_TEMPLATE_NAMES
        or "security" in (read_file_safe(item) or "").lower()
        for item in tree_files(root, under=".github/ISSUE_TEMPLATE", depth=1)
    )


def _gather_security_docs(root: Path) -> str:
    """Gather security documentation content."""
    parts = present_contents(root, ("SECURITY.md", "SECURITY.txt", "security-policy.md"))
    parts += [
        content for item in tree_files(root, under="docs", globs=("*security*",))
        if (content := read_file_safe(item))
    ]
    return "\n".join(parts)


check_vuln_remediation_tool = function_tool(check_vuln_remediation)
