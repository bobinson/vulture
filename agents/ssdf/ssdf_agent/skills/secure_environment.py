"""PO.5 - Secure environment audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import (
    is_generated_file,
    is_test_file,
    read_file_safe,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

_SECRETS_MGMT_PATTERNS = re.compile(
    r"vault|hashicorp|aws.?secrets|sops|sealed.?secrets|secret.?manager|kms",
    re.IGNORECASE,
)

_PRIVILEGED_PATTERN = re.compile(r"privileged:\s*true", re.IGNORECASE)
_ROOT_USER_PATTERN = re.compile(r"^\s*USER\s+root\s*$", re.MULTILINE | re.IGNORECASE)
_USER_DIRECTIVE = re.compile(r"^\s*USER\s+\S+", re.MULTILINE | re.IGNORECASE)


def check_secure_environment(source_path: str) -> dict:
    """Check for secure environment configuration (PO.5).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    _check_secrets_management(root, findings)
    _check_container_security(root, findings)

    return {"findings": findings}


def _check_secrets_management(root: Path, findings: list[dict]) -> None:
    """Check for secrets management tooling."""
    has_secrets_mgmt = False
    for file_path in scan_code_files(str(root)):
        if is_generated_file(file_path) or is_test_file(file_path):
            continue
        content = read_file_safe(file_path)
        if content and _SECRETS_MGMT_PATTERNS.search(content):
            has_secrets_mgmt = True
            break

    if not has_secrets_mgmt:
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.po5.no_secrets_management",
            "category": "PO-prepare-organization",
            "title": "No secrets management solution detected",
            "description": "No secrets management tool (Vault, AWS Secrets Manager, SOPS) references found",
            "file_path": str(root),
            "line_start": 1,
            "line_end": 1,
            "recommendation": "Integrate a secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager)",
        })


def _check_container_security(root: Path, findings: list[dict]) -> None:
    """Check Dockerfiles and compose files for security issues."""
    for file_path in root.rglob("Dockerfile*"):
        if is_test_file(file_path):
            continue
        content = read_file_safe(file_path)
        if content is None:
            continue
        lines = content.splitlines()
        if _ROOT_USER_PATTERN.search(content):
            for i, line in enumerate(lines, 1):
                if re.match(r"^\s*USER\s+root\s*$", line, re.IGNORECASE):
                    findings.append({
                        "severity": "high",
                        "check_id": "ssdf.po5.root_user_container",
                        "category": "PO-prepare-organization",
                        "title": "Container runs as root user",
                        "description": f"Dockerfile {file_path.name} runs as root",
                        "file_path": str(file_path),
                        "line_start": i,
                        "line_end": i,
                        "recommendation": "Add a non-root USER directive in the Dockerfile",
                        "code_snippet": extract_snippet(lines, i),
                    })
                    break

    for file_path in root.rglob("docker-compose*.yml"):
        content = read_file_safe(file_path)
        if content is None:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if _PRIVILEGED_PATTERN.search(line):
                findings.append({
                    "severity": "high",
                    "check_id": "ssdf.po5.privileged_container",
                    "category": "PO-prepare-organization",
                    "title": "Privileged container detected",
                    "description": f"Container in {file_path.name} runs in privileged mode",
                    "file_path": str(file_path),
                    "line_start": i,
                    "line_end": i,
                    "recommendation": "Remove privileged: true and use specific capabilities instead",
                    "code_snippet": extract_snippet(lines, i),
                })


check_secure_environment_tool = function_tool(check_secure_environment)
