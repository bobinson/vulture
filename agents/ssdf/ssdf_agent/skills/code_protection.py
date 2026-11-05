"""PS.1 - Code protection audit skill for SSDF."""

from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import present
from ssdf_agent.skills._ci_utils import present_contents

_PRE_COMMIT_FILES = {
    ".pre-commit-config.yaml", ".pre-commit-config.yml",
}

_HUSKY_DIR = ".husky"

_SIGNING_INDICATORS = {"commit.gpgsign", "gpg.format", "tag.gpgsign"}


def check_code_protection(source_path: str) -> dict:
    """Check for code protection measures (PS.1).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _has_pre_commit_hooks(root):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.ps1.no_pre_commit_hooks",
            "category": "PS",
            "practice": "PS-protect-software",
            "title": "No pre-commit hooks configured",
            "description": "No pre-commit hook configuration (pre-commit, husky, lint-staged) found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Set up pre-commit hooks for linting and security checks before commit",
        })

    if not _has_commit_signing(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.ps1.no_commit_signing",
            "category": "PS",
            "practice": "PS-protect-software",
            "title": "No commit signing configuration found",
            "description": "No GPG/SSH commit signing configuration detected",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Configure commit signing to ensure code authenticity",
        })

    return {"findings": findings}


def _has_pre_commit_hooks(root: Path) -> bool:
    """Check for pre-commit hook configurations."""
    if any(present(root, name) for name in (*_PRE_COMMIT_FILES, _HUSKY_DIR)):
        return True
    # Check for lint-staged in package.json
    return any("lint-staged" in content for content in present_contents(root, ("package.json",)))


def _has_commit_signing(root: Path) -> bool:
    """Check for commit signing configuration."""
    gitconfig = present_contents(root, (".gitconfig",))
    return any(indicator in content for content in gitconfig for indicator in _SIGNING_INDICATORS)


check_code_protection_tool = function_tool(check_code_protection)
