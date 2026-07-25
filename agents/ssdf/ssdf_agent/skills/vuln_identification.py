"""RV.1 - Vulnerability identification audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

_VULN_SCAN_PATTERNS = re.compile(
    r"dependabot|renovate|snyk|trivy|grype|anchore|clair|scout",
    re.IGNORECASE,
)

_CONTAINER_SCAN_PATTERNS = re.compile(
    r"trivy|grype|anchore|clair|docker\s+scout|container.?scan",
    re.IGNORECASE,
)


def check_vuln_identification(source_path: str) -> dict:
    """Check for vulnerability identification processes (RV.1).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []
    ci_content = _gather_ci_and_config(root)

    if not _VULN_SCAN_PATTERNS.search(ci_content):
        findings.append({
            "severity": "high",
            "check_id": "ssdf.rv1.no_vuln_scanning",
            "category": "RV-respond-to-vulnerabilities",
            "title": "No vulnerability scanning configured",
            "description": "No dependency or vulnerability scanning tool (Dependabot, Trivy, Snyk, Grype) found",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Enable Dependabot or integrate Trivy/Snyk for vulnerability scanning",
        })

    dockerfiles = list(root.rglob("Dockerfile*"))
    if dockerfiles and not _CONTAINER_SCAN_PATTERNS.search(ci_content):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.rv1.no_container_scanning",
            "category": "RV-respond-to-vulnerabilities",
            "title": "No container image scanning configured",
            "description": "Dockerfiles found but no container scanning tool in CI",
            "file_path": source_path,
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Add container image scanning (Trivy, Grype, Docker Scout) to CI",
        })

    return {"findings": findings}


def _gather_ci_and_config(root: Path) -> str:
    """Gather CI and config content."""
    parts: list[str] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for f in workflows.iterdir():
            if f.suffix in (".yml", ".yaml"):
                content = read_file_safe(f)
                if content:
                    parts.append(content)
    github_dir = root / ".github"
    if github_dir.is_dir():
        for item in github_dir.iterdir():
            if item.name.lower() in ("dependabot.yml", "dependabot.yaml"):
                parts.append("dependabot")
    for name in ("renovate.json", "renovate.json5", ".snyk"):
        if (root / name).exists():
            parts.append(name)
    return "\n".join(parts)


check_vuln_identification_tool = function_tool(check_vuln_identification)
