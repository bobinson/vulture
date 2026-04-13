"""PW - Produce Well-Secured Software."""

from ssdf_agent.skills.secure_design import check_secure_design
from ssdf_agent.skills.dependency_reuse import check_dependency_reuse
from ssdf_agent.skills.secure_coding import check_secure_coding
from ssdf_agent.skills.build_security import check_build_security
from ssdf_agent.skills.code_review import check_code_review
from ssdf_agent.skills.security_testing import check_security_testing
from ssdf_agent.skills.secure_defaults import check_secure_defaults


def audit_pw(source_path: str) -> dict:
    """Audit PW (Produce Well-Secured Software).

    Covers secure design, dependency reuse, secure coding, build security,
    code review, security testing, and secure defaults.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list.
    """
    findings: list[dict] = []

    checks = (
        check_secure_design,
        check_dependency_reuse,
        check_secure_coding,
        check_build_security,
        check_code_review,
        check_security_testing,
        check_secure_defaults,
    )
    for check_fn in checks:
        result = check_fn(source_path)
        findings.extend(result.get("findings", []))

    return {"findings": findings}
