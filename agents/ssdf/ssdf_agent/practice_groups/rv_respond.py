"""RV - Respond to Vulnerabilities."""

from ssdf_agent.skills.vuln_identification import check_vuln_identification
from ssdf_agent.skills.vuln_remediation import check_vuln_remediation
from ssdf_agent.skills.root_cause_analysis import check_root_cause_analysis


def audit_rv(source_path: str) -> dict:
    """Audit RV (Respond to Vulnerabilities).

    Covers vulnerability identification, remediation, and root cause analysis.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []

    checks = (
        check_vuln_identification,
        check_vuln_remediation,
        check_root_cause_analysis,
    )
    for check_fn in checks:
        result = check_fn(source_path)
        findings.extend(result.get("findings", []))

    return {"findings": findings}
