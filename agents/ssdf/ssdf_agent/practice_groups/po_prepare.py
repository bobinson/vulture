"""PO - Prepare the Organization."""

from ssdf_agent.skills.security_policy import check_security_policy
from ssdf_agent.skills.roles_governance import check_roles_governance
from ssdf_agent.skills.toolchain_check import check_toolchain
from ssdf_agent.skills.security_criteria import check_security_criteria
from ssdf_agent.skills.secure_environment import check_secure_environment


def audit_po(source_path: str) -> dict:
    """Audit PO (Prepare the Organization).

    Covers security policy, roles, toolchain, criteria, and environment.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []

    checks = (
        check_security_policy,
        check_roles_governance,
        check_toolchain,
        check_security_criteria,
        check_secure_environment,
    )
    for check_fn in checks:
        result = check_fn(source_path)
        findings.extend(result.get("findings", []))

    return {"findings": findings}
