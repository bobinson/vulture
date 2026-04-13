"""PS.3 - Archive protection audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe
from ssdf_agent.skills._ci_utils import gather_ci_content

_RELEASE_PATTERNS = re.compile(
    r"create-release|gh\s+release|actions/upload-release-asset|goreleaser|semantic-release",
    re.IGNORECASE,
)

_RETENTION_PATTERNS = re.compile(
    r"retention.?days|artifact.?retention|backup|archive",
    re.IGNORECASE,
)


def check_archive_protection(source_path: str) -> dict:
    """Check for release archival and protection (PS.3).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []
    ci_content = _gather_release_content(root)

    if not _RELEASE_PATTERNS.search(ci_content):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.ps3.no_release_archive",
            "category": "PS-protect-software",
            "title": "No automated release archival process",
            "description": "No automated release workflow (GitHub releases, goreleaser, semantic-release) found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Configure automated release archival via GitHub releases or goreleaser",
        })

    return {"findings": findings}


def _gather_release_content(root: Path) -> str:
    """Gather CI + release-specific content."""
    base = gather_ci_content(root)
    extras: list[str] = []
    for name in (".releaserc", ".releaserc.json", ".goreleaser.yml", ".goreleaser.yaml"):
        p = root / name
        if p.exists():
            content = read_file_safe(p)
            if content:
                extras.append(content)
    if extras:
        return base + "\n" + "\n".join(extras)
    return base


check_archive_protection_tool = function_tool(check_archive_protection)
