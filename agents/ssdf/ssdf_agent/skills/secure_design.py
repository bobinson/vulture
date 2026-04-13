"""PW.1 + PW.2 - Secure design audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

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
            "category": "PW-produce-well-secured-software",
            "title": "No threat model documentation found",
            "description": "No threat model document found in the repository",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Create a threat model document using STRIDE or similar methodology",
        })

    if not _find_design_review(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.pw2.no_design_review",
            "category": "PW-produce-well-secured-software",
            "title": "No design review evidence found",
            "description": "No design review or architecture review documentation found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Document design review processes in PR templates or dedicated docs",
        })

    return {"findings": findings}


def _find_threat_model(root: Path) -> bool:
    """Check for threat model documents."""
    for name in _THREAT_MODEL_NAMES:
        if any(True for _ in root.rglob(name)):
            return True
    docs_security = root / "docs" / "security"
    if docs_security.is_dir():
        return True
    return False


def _find_design_review(root: Path) -> bool:
    """Check for design review evidence."""
    for name in _DESIGN_DOC_NAMES:
        for match in root.rglob(name):
            if match.is_file():
                return True
    # Check PR template for design review checklist
    github_dir = root / ".github"
    if github_dir.is_dir():
        for item in github_dir.iterdir():
            if "pull_request_template" in item.name.lower():
                content = read_file_safe(item)
                if content and _DESIGN_REVIEW_PATTERNS.search(content):
                    return True
    return False


check_secure_design_tool = function_tool(check_secure_design)
