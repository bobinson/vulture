"""PO.3 - Security toolchain audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from ssdf_agent.skills._ci_utils import gather_ci_content, github_or_root_files

_SAST_PATTERNS = re.compile(
    r"semgrep|snyk\s+test|codeql|sonarqube|sonar-scanner|bandit|gosec|brakeman|spotbugs",
    re.IGNORECASE,
)

_DAST_PATTERNS = re.compile(
    r"zap|zaproxy|burp|nikto|nuclei|dast|dynamic.?analysis",
    re.IGNORECASE,
)

_SCA_FILES = {"dependabot.yml", "dependabot.yaml", "renovate.json", "renovate.json5", ".snyk"}

_CI_GLOBS = [".github/workflows", ".gitlab-ci.yml", ".circleci", "Jenkinsfile"]


def check_toolchain(source_path: str) -> dict:
    """Check for security toolchain configuration (PO.3).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    ci_content = gather_ci_content(root)

    if not _SAST_PATTERNS.search(ci_content):
        findings.append({
            "severity": "high",
            "check_id": "ssdf.po3.no_sast_tool",
            "category": "PO",
            "practice": "PO-prepare-organization",
            "title": "No SAST tool configured in CI/CD",
            "description": "No static analysis security tool (semgrep, codeql, snyk, bandit, gosec) found in CI configuration",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Add a SAST tool to your CI pipeline (e.g., semgrep, CodeQL, Snyk Code)",
        })

    if not _DAST_PATTERNS.search(ci_content):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.po3.no_dast_tool",
            "category": "PO",
            "practice": "PO-prepare-organization",
            "title": "No DAST tool configured in CI/CD",
            "description": "No dynamic analysis tool (ZAP, nuclei, nikto) found in CI configuration",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Add a DAST tool to your CI pipeline (e.g., OWASP ZAP, nuclei)",
        })

    if not _find_sca_config(root):
        findings.append({
            "severity": "high",
            "check_id": "ssdf.po3.no_sca_tool",
            "category": "PO",
            "practice": "PO-prepare-organization",
            "title": "No SCA/dependency scanning configured",
            "description": "No dependency scanning tool (Dependabot, Renovate, Snyk) configuration found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Enable Dependabot or Renovate for automated dependency updates",
        })

    return {"findings": findings}


def _find_sca_config(root: Path) -> bool:
    """Check for SCA tool configuration files."""
    return any(item.name.lower() in _SCA_FILES for item in github_or_root_files(root))


check_toolchain_tool = function_tool(check_toolchain)
