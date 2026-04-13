"""NIST SSDF v1.1 compliance audit skills."""

from ssdf_agent.skills.security_policy import check_security_policy, check_security_policy_tool
from ssdf_agent.skills.roles_governance import check_roles_governance, check_roles_governance_tool
from ssdf_agent.skills.toolchain_check import check_toolchain, check_toolchain_tool
from ssdf_agent.skills.security_criteria import check_security_criteria, check_security_criteria_tool
from ssdf_agent.skills.secure_environment import check_secure_environment, check_secure_environment_tool
from ssdf_agent.skills.code_protection import check_code_protection, check_code_protection_tool
from ssdf_agent.skills.release_integrity import check_release_integrity, check_release_integrity_tool
from ssdf_agent.skills.archive_protection import check_archive_protection, check_archive_protection_tool
from ssdf_agent.skills.secure_design import check_secure_design, check_secure_design_tool
from ssdf_agent.skills.dependency_reuse import check_dependency_reuse, check_dependency_reuse_tool
from ssdf_agent.skills.secure_coding import check_secure_coding, check_secure_coding_tool
from ssdf_agent.skills.build_security import check_build_security, check_build_security_tool
from ssdf_agent.skills.code_review import check_code_review, check_code_review_tool
from ssdf_agent.skills.security_testing import check_security_testing, check_security_testing_tool
from ssdf_agent.skills.secure_defaults import check_secure_defaults, check_secure_defaults_tool
from ssdf_agent.skills.vuln_identification import check_vuln_identification, check_vuln_identification_tool
from ssdf_agent.skills.vuln_remediation import check_vuln_remediation, check_vuln_remediation_tool
from ssdf_agent.skills.root_cause_analysis import check_root_cause_analysis, check_root_cause_analysis_tool

SKILL_TOOLS = [
    check_security_policy_tool,
    check_roles_governance_tool,
    check_toolchain_tool,
    check_security_criteria_tool,
    check_secure_environment_tool,
    check_code_protection_tool,
    check_release_integrity_tool,
    check_archive_protection_tool,
    check_secure_design_tool,
    check_dependency_reuse_tool,
    check_secure_coding_tool,
    check_build_security_tool,
    check_code_review_tool,
    check_security_testing_tool,
    check_secure_defaults_tool,
    check_vuln_identification_tool,
    check_vuln_remediation_tool,
    check_root_cause_analysis_tool,
]

SKILL_MAP = {
    "security_policy": check_security_policy,
    "roles_governance": check_roles_governance,
    "toolchain": check_toolchain,
    "security_criteria": check_security_criteria,
    "secure_environment": check_secure_environment,
    "code_protection": check_code_protection,
    "release_integrity": check_release_integrity,
    "archive_protection": check_archive_protection,
    "secure_design": check_secure_design,
    "dependency_reuse": check_dependency_reuse,
    "secure_coding": check_secure_coding,
    "build_security": check_build_security,
    "code_review": check_code_review,
    "security_testing": check_security_testing,
    "secure_defaults": check_secure_defaults,
    "vuln_identification": check_vuln_identification,
    "vuln_remediation": check_vuln_remediation,
    "root_cause_analysis": check_root_cause_analysis,
}

__all__ = [
    "SKILL_TOOLS", "SKILL_MAP",
    "check_security_policy", "check_security_policy_tool",
    "check_roles_governance", "check_roles_governance_tool",
    "check_toolchain", "check_toolchain_tool",
    "check_security_criteria", "check_security_criteria_tool",
    "check_secure_environment", "check_secure_environment_tool",
    "check_code_protection", "check_code_protection_tool",
    "check_release_integrity", "check_release_integrity_tool",
    "check_archive_protection", "check_archive_protection_tool",
    "check_secure_design", "check_secure_design_tool",
    "check_dependency_reuse", "check_dependency_reuse_tool",
    "check_secure_coding", "check_secure_coding_tool",
    "check_build_security", "check_build_security_tool",
    "check_code_review", "check_code_review_tool",
    "check_security_testing", "check_security_testing_tool",
    "check_secure_defaults", "check_secure_defaults_tool",
    "check_vuln_identification", "check_vuln_identification_tool",
    "check_vuln_remediation", "check_vuln_remediation_tool",
    "check_root_cause_analysis", "check_root_cause_analysis_tool",
]
