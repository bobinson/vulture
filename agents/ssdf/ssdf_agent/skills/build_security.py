"""PW.6 - Build security audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.tools.file_scanner import read_file_safe

_SECURITY_FLAGS = re.compile(
    r"-fstack-protector|-D_FORTIFY_SOURCE|CGO_ENABLED=0|-fPIE|-pie|RELRO|stack-clash-protection",
    re.IGNORECASE,
)

_MINIMAL_IMAGE_PATTERNS = re.compile(
    r"slim|alpine|distroless|scratch|busybox",
    re.IGNORECASE,
)


def check_build_security(source_path: str) -> dict:
    """Check for build process security (PW.6).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []

    _check_dockerfiles(root, findings)

    return {"findings": findings}


def _check_dockerfiles(root: Path, findings: list[dict]) -> None:
    """Check Dockerfiles for build security practices."""
    dockerfiles = list(root.rglob("Dockerfile*"))
    if not dockerfiles:
        return

    for dockerfile in dockerfiles:
        content = read_file_safe(dockerfile)
        if content is None:
            continue
        if not _MINIMAL_IMAGE_PATTERNS.search(content):
            findings.append({
                "severity": "low",
                "check_id": "ssdf.pw6.no_minimal_base_image",
                "category": "PW-produce-well-secured-software",
                "title": "Non-minimal base image in Dockerfile",
                "description": f"Dockerfile {dockerfile.name} does not use a minimal base image",
                "file_path": str(dockerfile),
                "line_start": 1,
                "line_end": 1,
                "recommendation": "Use minimal base images (slim, alpine, distroless) to reduce attack surface",
            })


check_build_security_tool = function_tool(check_build_security)
