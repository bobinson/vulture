"""PS - Protect the Software."""

from ssdf_agent.skills.code_protection import check_code_protection
from ssdf_agent.skills.release_integrity import check_release_integrity
from ssdf_agent.skills.archive_protection import check_archive_protection


def audit_ps(source_path: str) -> dict:
    """Audit PS (Protect the Software).

    Covers code protection, release integrity, and archive protection.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []

    checks = (
        check_code_protection,
        check_release_integrity,
        check_archive_protection,
    )
    for check_fn in checks:
        result = check_fn(source_path)
        findings.extend(result.get("findings", []))

    return {"findings": findings}
