"""PS.2 - Release integrity audit skill for SSDF."""

import re
from pathlib import Path

from agents import function_tool

from shared.models.finding import REPO_ROOT_PATH
from shared.tools.file_scanner import read_file_safe
from ssdf_agent.skills._ci_utils import present_contents, workflow_files

_SIGNING_PATTERNS = re.compile(
    r"cosign|sigstore|gpg\s+--sign|gpg\s+--detach-sign|signcode|authenticode",
    re.IGNORECASE,
)

_CHECKSUM_PATTERNS = re.compile(
    r"sha256sum|shasum|md5sum|checksums?\.txt|digest|integrity",
    re.IGNORECASE,
)

_PROVENANCE_PATTERNS = re.compile(
    r"slsa|provenance|in-toto|attestation|supply.?chain",
    re.IGNORECASE,
)


def check_release_integrity(source_path: str) -> dict:
    """Check for release integrity mechanisms (PS.2).

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    root = Path(source_path)
    findings: list[dict] = []
    ci_content = _gather_release_content(root)

    if not _SIGNING_PATTERNS.search(ci_content):
        findings.append({
            "severity": "medium",
            "check_id": "ssdf.ps2.no_release_signing",
            "category": "PS",
            "practice": "PS-protect-software",
            "title": "No release signing configured",
            "description": "No code/artifact signing mechanism (cosign, GPG, sigstore) found in release workflow",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Sign releases using cosign/sigstore or GPG for integrity verification",
        })

    if not _CHECKSUM_PATTERNS.search(ci_content):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.ps2.no_checksums",
            "category": "PS",
            "practice": "PS-protect-software",
            "title": "No checksum generation in build/release",
            "description": "No checksum generation (SHA256) found in build or release processes",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Generate and publish SHA256 checksums for all release artifacts",
        })

    if not _PROVENANCE_PATTERNS.search(ci_content):
        findings.append({
            "severity": "low",
            "check_id": "ssdf.ps2.no_provenance",
            "category": "PS",
            "practice": "PS-protect-software",
            "title": "No supply chain provenance generation",
            "description": "No SLSA provenance or in-toto attestation generation found",
            "file_path": REPO_ROOT_PATH,
            "line_start": 0,
            "line_end": 0,
            "recommendation": "Generate SLSA provenance for build artifacts to ensure supply chain integrity",
        })

    return {"findings": findings}


def _gather_release_content(root: Path) -> str:
    """Gather release and CI content."""
    parts = [content for f in workflow_files(root) if (content := read_file_safe(f))]
    parts += present_contents(root, ("Makefile", "Taskfile.yml", "justfile", "Rakefile"))
    return "\n".join(parts)


check_release_integrity_tool = function_tool(check_release_integrity)
