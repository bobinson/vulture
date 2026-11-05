"""Shared CI content gathering for SSDF skills (DRY extraction).

Every SSDF look at the repository goes through the audit walker
(``tree_files`` / ``present``), never a walk of its own: evidence counts only
where the audit itself reads. A design document under ``.venv`` or a workflow
in a ``.vultureignore``d directory is not the project's.
"""

from collections.abc import Iterable, Iterator
from itertools import chain
from pathlib import Path

from shared.tools.file_scanner import present, read_file_safe, tree_files


def present_contents(root: Path, names: Iterable[str]) -> list[str]:
    """The non-empty contents of each fixed root-relative location in ``names``
    that the walk reaches, in order."""
    return [
        content for name in names
        if present(root, name) and (content := read_file_safe(root / name))
    ]


def workflow_files(root: Path) -> Iterator[Path]:
    """The GitHub Actions workflow files directly in ``.github/workflows``."""
    return (
        f for f in tree_files(root, under=".github/workflows", depth=1)
        if f.suffix in (".yml", ".yaml")
    )


def github_or_root_files(root: Path) -> Iterator[Path]:
    """The files directly in ``.github`` and then directly in the root, where
    repository policy files (PR templates, dependabot, CODEOWNERS) live."""
    return chain(tree_files(root, under=".github", depth=1), tree_files(root, depth=1))


def gather_ci_content(root: Path) -> str:
    """Gather CI content from GitHub Actions, GitLab CI, CircleCI, Jenkins.

    Args:
        root: Repository root path.

    Returns:
        Concatenated CI configuration content.
    """
    parts = [content for f in workflow_files(root) if (content := read_file_safe(f))]
    parts += present_contents(root, (
        ".gitlab-ci.yml", ".gitlab-ci.yaml",          # GitLab CI
        ".circleci/config.yml",                        # CircleCI
        "Jenkinsfile", "jenkins.groovy",               # Jenkins
        "Makefile", "pyproject.toml", "package.json",  # Build/config files
    ))
    return "\n".join(parts)
