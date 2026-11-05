"""RV.3 - Root cause analysis audit skill for SSDF."""

import re
from itertools import chain
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import read_file_safe, tree_files
from ssdf_agent.skills._ci_utils import present_contents

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
            "category": "RV",
            "practice": "RV-respond-to-vulnerabilities",
            "title": "No post-mortem/incident template found",
            "description": "No post-mortem or incident report template found in the repository",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Create a post-mortem template for structured incident analysis",
        })

    if not has_rca:
        findings.append({
            "severity": "low",
            "check_id": "ssdf.rv3.no_rca_process",
            "category": "RV",
            "practice": "RV-respond-to-vulnerabilities",
            "title": "No root cause analysis process documented",
            "description": "No RCA or blameless post-mortem process documentation found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Document a root cause analysis process (e.g., blameless post-mortems, five whys)",
        })

    return {"findings": findings}


def _find_postmortem_template(root: Path) -> bool:
    """Check for post-mortem templates."""
    globs = tuple(f"*{name}*" for name in _POSTMORTEM_NAMES)
    return any(True for _ in tree_files(root, globs=globs))


def _find_rca_docs(root: Path) -> bool:
    """Check for RCA documentation: text docs under ``docs/`` (not
    binaries/images), then the contributing guide."""
    docs = (
        read_file_safe(item) or ""
        for item in tree_files(root, under="docs", globs=("*.md", "*.rst", "*.txt", "*.adoc"))
    )
    guides = present_contents(root, ("CONTRIBUTING.md", "CONTRIBUTING.rst"))
    return any(_RCA_PATTERNS.search(content) for content in chain(docs, guides))


check_root_cause_analysis_tool = function_tool(check_root_cause_analysis)
