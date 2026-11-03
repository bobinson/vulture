"""PW.5 - Secure coding practices audit skill for SSDF."""

from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import tree_files
from ssdf_agent.skills._ci_utils import present_contents

_LINTER_FILES = {
    ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.yml", ".eslintrc.yaml",
    "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs",
    "ruff.toml",
    ".golangci.yml", ".golangci.yaml",
    ".rubocop.yml", "clippy.toml",
    ".pylintrc", "pylintrc",
    "biome.json", "biome.jsonc",
}

# pyproject.toml only counts as linter config if it has a linter section
_PYPROJECT_LINTER_SECTIONS = {"[tool.ruff]", "[tool.pylint]", "[tool.flake8]", "[tool.mypy]"}

_FORMATTER_FILES = {
    ".prettierrc", ".prettierrc.js", ".prettierrc.json", ".prettierrc.yml",
    "prettier.config.js", "prettier.config.mjs",
    "rustfmt.toml", ".editorconfig",
    ".clang-format",
}

_CODING_STANDARDS_FILES = {
    "contributing.md", "contributing.rst", "contributing.txt",
    "style-guide.md", "coding-standards.md",
}


def check_secure_coding(source_path: str) -> dict:
    """Check for secure coding practices and tooling (PW.5).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    if not _find_linter(root):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.pw5.no_linter_config",
            "category": "PW",
            "practice": "PW-produce-well-secured-software",
            "title": "No linter configuration found",
            "description": "No code linter configuration (eslint, ruff, golangci-lint, rubocop) found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Configure a linter appropriate for your language(s) to enforce coding standards",
        })

    return {"findings": findings}


def _find_linter(root: Path) -> bool:
    """Check for linter configuration files."""
    if any(item.name.lower() in _LINTER_FILES for item in tree_files(root, depth=1)):
        return True
    return _pyproject_configures_linter(root)


def _pyproject_configures_linter(root: Path) -> bool:
    """A linter section in pyproject.toml (the file alone would be a false positive)."""
    pyproject = present_contents(root, ("pyproject.toml",))
    return any(section in content for content in pyproject for section in _PYPROJECT_LINTER_SECTIONS)


check_secure_coding_tool = function_tool(check_secure_coding)
