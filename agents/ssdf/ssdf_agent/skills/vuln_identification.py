"""RV.1 - Vulnerability identification audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import present, read_file_safe, tree_files
from ssdf_agent.skills._ci_utils import workflow_files

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
            "category": "RV",
            "practice": "RV-respond-to-vulnerabilities",
            "title": "No vulnerability scanning configured",
            "description": "No dependency or vulnerability scanning tool (Dependabot, Trivy, Snyk, Grype) found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Enable Dependabot or integrate Trivy/Snyk for vulnerability scanning",
        })

    if _has_dockerfile(root) and not _CONTAINER_SCAN_PATTERNS.search(ci_content):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.rv1.no_container_scanning",
            "category": "RV",
            "practice": "RV-respond-to-vulnerabilities",
            "title": "No container image scanning configured",
            "description": "Dockerfiles found but no container scanning tool in CI",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Add container image scanning (Trivy, Grype, Docker Scout) to CI",
        })

    return {"findings": findings}


def _gather_ci_and_config(root: Path) -> str:
    """Gather CI and config content."""
    parts = [content for f in workflow_files(root) if (content := read_file_safe(f))]
    return "\n".join(parts + _sca_markers(root))


def _sca_markers(root: Path) -> list[str]:
    """``dependabot`` when ``.github`` configures it, and each SCA config
    file at the root."""
    markers = ["dependabot"] if _has_dependabot(root) else []
    return markers + [name for name in ("renovate.json", "renovate.json5", ".snyk")
                      if present(root, name)]


def _has_dockerfile(root: Path) -> bool:
    return next(tree_files(root, globs=("Dockerfile*",)), None) is not None


def _has_dependabot(root: Path) -> bool:
    github = tree_files(root, under=".github", depth=1)
    return any(item.name.lower() in ("dependabot.yml", "dependabot.yaml") for item in github)


check_vuln_identification_tool = function_tool(check_vuln_identification)
