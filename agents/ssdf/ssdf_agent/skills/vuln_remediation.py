"""RV.2 - Vulnerability remediation audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

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
            "category": "RV-respond-to-vulnerabilities",
            "title": "No security issue template found",
            "description": "No dedicated security bug/vulnerability issue template found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a security vulnerability issue template in .github/ISSUE_TEMPLATE/",
        })

    security_docs = _gather_security_docs(root)
    if not _PATCHING_SLA_PATTERNS.search(security_docs):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.rv2.no_patching_sla",
            "category": "RV-respond-to-vulnerabilities",
            "title": "No patching SLA or remediation timeline defined",
            "description": "No vulnerability patching SLA or remediation timeline found in security docs",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Define remediation timelines (e.g., critical: 24h, high: 7d) in security policy",
        })

    return {"findings": findings}


def _find_security_issue_template(root: Path) -> bool:
    """Check for security issue templates."""
    issue_dir = root / ".github" / "ISSUE_TEMPLATE"
    if issue_dir.is_dir():
        for item in issue_dir.iterdir():
            if item.name.lower() in _SECURITY_ISSUE_TEMPLATE_NAMES:
                return True
            content = read_file_safe(item)
            if content and "security" in content.lower():
                return True
    return False


def _gather_security_docs(root: Path) -> str:
    """Gather security documentation content."""
    parts: list[str] = []
    for name in ("SECURITY.md", "SECURITY.txt", "security-policy.md"):
        p = root / name
        if p.exists():
            content = read_file_safe(p)
            if content:
                parts.append(content)
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        for item in docs_dir.rglob("*security*"):
            if item.is_file():
                content = read_file_safe(item)
                if content:
                    parts.append(content)
    return "\n".join(parts)


check_vuln_remediation_tool = function_tool(check_vuln_remediation)
