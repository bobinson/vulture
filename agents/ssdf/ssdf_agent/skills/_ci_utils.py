"""Shared CI content gathering for SSDF skills (DRY extraction)."""

from pathlib import Path

from shared.tools.file_scanner import read_file_safe


def gather_ci_content(root: Path) -> str:
    """Gather CI content from GitHub Actions, GitLab CI, CircleCI, Jenkins.

    Args:
        root: Repository root path.

    Returns:
        Concatenated CI configuration content.
    """
    parts: list[str] = []
    # GitHub Actions
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for f in workflows.iterdir():
            if f.suffix in (".yml", ".yaml"):
                content = read_file_safe(f)
                if content:
                    parts.append(content)
    # GitLab CI
    for name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        p = root / name
        if p.exists():
            content = read_file_safe(p)
            if content:
                parts.append(content)
    # CircleCI
    circleci = root / ".circleci" / "config.yml"
    if circleci.exists():
        content = read_file_safe(circleci)
        if content:
            parts.append(content)
    # Jenkins
    for name in ("Jenkinsfile", "jenkins.groovy"):
        p = root / name
        if p.exists():
            content = read_file_safe(p)
            if content:
                parts.append(content)
    # Build/config files
    for name in ("Makefile", "pyproject.toml", "package.json"):
        p = root / name
        if p.exists():
            content = read_file_safe(p)
            if content:
                parts.append(content)
    return "\n".join(parts)
