"""RV.3 - Root cause analysis audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

_POSTMORTEM_NAMES = {
    "postmortem", "post-mortem", "post_mortem",
    "incident-report", "incident_report",
    "rca", "root-cause",
}

_RCA_PATTERNS = re.compile(
    r"post.?mortem|root.?cause|incident.?review|blameless|five.?whys|5.?whys|retrospective",
    re.IGNORECASE,
)


def check_root_cause_analysis(source_path: str) -> dict:
    """Check for root cause analysis processes (RV.3).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    has_postmortem = _find_postmortem_template(root)
    has_rca = _find_rca_docs(root)

    if not has_postmortem:
        findings.append({
            "severity": "low",
            "check_id": "ssdf.rv3.no_postmortem_template",
            "category": "RV-respond-to-vulnerabilities",
            "title": "No post-mortem/incident template found",
            "description": "No post-mortem or incident report template found in the repository",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a post-mortem template for structured incident analysis",
        })

    if not has_rca:
        findings.append({
            "severity": "low",
            "check_id": "ssdf.rv3.no_rca_process",
            "category": "RV-respond-to-vulnerabilities",
            "title": "No root cause analysis process documented",
            "description": "No RCA or blameless post-mortem process documentation found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Document a root cause analysis process (e.g., blameless post-mortems, five whys)",
        })

    return {"findings": findings}


def _find_postmortem_template(root: Path) -> bool:
    """Check for post-mortem templates."""
    # Use targeted globs instead of rglob("*")
    for pattern_name in _POSTMORTEM_NAMES:
        for item in root.rglob(f"*{pattern_name}*"):
            if item.is_file():
                return True
    return False


def _find_rca_docs(root: Path) -> bool:
    """Check for RCA documentation."""
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        # Search only text docs, not binaries/images
        for ext in ("*.md", "*.rst", "*.txt", "*.adoc"):
            for item in docs_dir.rglob(ext):
                content = read_file_safe(item)
                if content and _RCA_PATTERNS.search(content):
                    return True
    # Check contributing guide
    for name in ("CONTRIBUTING.md", "CONTRIBUTING.rst"):
        p = root / name
        if p.exists():
            content = read_file_safe(p)
            if content and _RCA_PATTERNS.search(content):
                return True
    return False


check_root_cause_analysis_tool = function_tool(check_root_cause_analysis)
