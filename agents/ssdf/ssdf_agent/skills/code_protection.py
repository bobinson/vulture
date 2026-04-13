"""PS.1 - Code protection audit skill for SSDF."""

from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

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
            "category": "PS-protect-software",
            "title": "No pre-commit hooks configured",
            "description": "No pre-commit hook configuration (pre-commit, husky, lint-staged) found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Set up pre-commit hooks for linting and security checks before commit",
        })

    if not _has_commit_signing(root):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.ps1.no_commit_signing",
            "category": "PS-protect-software",
            "title": "No commit signing configuration found",
            "description": "No GPG/SSH commit signing configuration detected",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Configure commit signing to ensure code authenticity",
        })

    return {"findings": findings}


def _has_pre_commit_hooks(root: Path) -> bool:
    """Check for pre-commit hook configurations."""
    for name in _PRE_COMMIT_FILES:
        if (root / name).exists():
            return True
    if (root / _HUSKY_DIR).is_dir():
        return True
    # Check for lint-staged in package.json
    pkg_json = root / "package.json"
    if pkg_json.exists():
        content = read_file_safe(pkg_json)
        if content and "lint-staged" in content:
            return True
    return False


def _has_commit_signing(root: Path) -> bool:
    """Check for commit signing configuration."""
    gitconfig = root / ".gitconfig"
    if gitconfig.exists():
        content = read_file_safe(gitconfig)
        if content:
            for indicator in _SIGNING_INDICATORS:
                if indicator in content:
                    return True
    return False


check_code_protection_tool = function_tool(check_code_protection)
