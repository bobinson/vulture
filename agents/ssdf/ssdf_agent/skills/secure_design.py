"""PW.1 + PW.2 - Secure design audit skill for SSDF."""

import re
from collections.abc import Iterator
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import present, read_file_safe, tree_files

_THREAT_MODEL_NAMES = {
    "threat-model.md", "threat_model.md", "threatmodel.md",
    "threat-model.txt", "threat_model.txt",
}

_DESIGN_DOC_NAMES = {
    "design.md", "architecture.md", "design.txt", "architecture.txt",
}

_DESIGN_REVIEW_PATTERNS = re.compile(
    r"design.?review|security.?review|threat.?model|architecture.?review",
    re.IGNORECASE,
)


def check_secure_design(source_path: str) -> dict:
    """Check for secure design practices (PW.1 + PW.2).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _find_threat_model(root):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.pw1.no_threat_model",
            "category": "PW",
            "practice": "PW-produce-well-secured-software",
            "title": "No threat model documentation found",
            "description": "No threat model document found in the repository",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Create a threat model document using STRIDE or similar methodology",
        })

    if not _find_design_review(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.pw2.no_design_review",
            "category": "PW",
            "practice": "PW-produce-well-secured-software",
            "title": "No design review evidence found",
            "description": "No design review or architecture review documentation found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Document design review processes in PR templates or dedicated docs",
        })

    return {"findings": findings}


def _find_threat_model(root: Path) -> bool:
    """Check for threat model documents, or a ``docs/security`` directory."""
    if any(True for _ in tree_files(root, names=_THREAT_MODEL_NAMES)):
        return True
    return present(root, "docs/security")


def _find_design_review(root: Path) -> bool:
    """Check for design review evidence."""
    if any(True for _ in tree_files(root, names=_DESIGN_DOC_NAMES)):
        return True
    # Check PR template for design review checklist
    return any(_DESIGN_REVIEW_PATTERNS.search(content) for content in _pr_templates(root))


def _pr_templates(root: Path) -> Iterator[str]:
    """The contents of the PR templates directly in ``.github``."""
    for item in tree_files(root, under=".github", depth=1):
        if "pull_request_template" in item.name.lower():
            yield read_file_safe(item) or ""


check_secure_design_tool = function_tool(check_secure_design)
