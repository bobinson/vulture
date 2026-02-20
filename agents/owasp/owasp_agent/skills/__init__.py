"""OWASP security audit skills."""

from owasp_agent.skills.injection_check import check_injection, check_injection_tool
from owasp_agent.skills.auth_check import check_authentication, check_authentication_tool
from owasp_agent.skills.crypto_check import check_cryptography, check_cryptography_tool
from owasp_agent.skills.access_control import check_access_control, check_access_control_tool
from owasp_agent.skills.security_misconfig import check_security_misconfig, check_security_misconfig_tool
from owasp_agent.skills.insecure_design import check_insecure_design, check_insecure_design_tool
from owasp_agent.skills.vulnerable_components import check_vulnerable_components, check_vulnerable_components_tool
from owasp_agent.skills.data_integrity import check_data_integrity, check_data_integrity_tool
from owasp_agent.skills.logging_check import check_logging, check_logging_tool
from owasp_agent.skills.ssrf_check import check_ssrf, check_ssrf_tool

SKILL_TOOLS = [
    check_injection_tool,
    check_authentication_tool,
    check_cryptography_tool,
    check_access_control_tool,
    check_security_misconfig_tool,
    check_insecure_design_tool,
    check_vulnerable_components_tool,
    check_data_integrity_tool,
    check_logging_tool,
    check_ssrf_tool,
]

SKILL_MAP = {
    "injection": check_injection,
    "auth_failure": check_authentication,
    "crypto_failure": check_cryptography,
    "access_control": check_access_control,
    "security_misconfig": check_security_misconfig,
    "insecure_design": check_insecure_design,
    "vulnerable_components": check_vulnerable_components,
    "data_integrity": check_data_integrity,
    "logging_failure": check_logging,
    "ssrf": check_ssrf,
}

__all__ = [
    "check_injection", "check_injection_tool",
    "check_authentication", "check_authentication_tool",
    "check_cryptography", "check_cryptography_tool",
    "check_access_control", "check_access_control_tool",
    "check_security_misconfig", "check_security_misconfig_tool",
    "check_insecure_design", "check_insecure_design_tool",
    "check_vulnerable_components", "check_vulnerable_components_tool",
    "check_data_integrity", "check_data_integrity_tool",
    "check_logging", "check_logging_tool",
    "check_ssrf", "check_ssrf_tool",
    "SKILL_TOOLS", "SKILL_MAP",
]
