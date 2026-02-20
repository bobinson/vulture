"""CWE weakness audit skills."""

from cwe_agent.skills.injection_check import check_injection, check_injection_tool
from cwe_agent.skills.buffer_check import check_buffer_handling, check_buffer_handling_tool
from cwe_agent.skills.auth_check import check_authentication, check_authentication_tool
from cwe_agent.skills.crypto_check import check_cryptography, check_cryptography_tool
from cwe_agent.skills.input_validation_check import check_input_validation, check_input_validation_tool
from cwe_agent.skills.resource_check import check_resource_management, check_resource_management_tool
from cwe_agent.skills.info_exposure_check import check_information_exposure, check_information_exposure_tool
from cwe_agent.skills.access_control_check import check_access_control, check_access_control_tool
from cwe_agent.skills.error_handling_check import check_error_handling, check_error_handling_tool
from cwe_agent.skills.concurrency_check import check_concurrency, check_concurrency_tool

SKILL_TOOLS = [
    check_injection_tool,
    check_buffer_handling_tool,
    check_authentication_tool,
    check_cryptography_tool,
    check_input_validation_tool,
    check_resource_management_tool,
    check_information_exposure_tool,
    check_access_control_tool,
    check_error_handling_tool,
    check_concurrency_tool,
]

SKILL_MAP = {
    "injection": check_injection,
    "buffer_handling": check_buffer_handling,
    "authentication": check_authentication,
    "cryptography": check_cryptography,
    "input_validation": check_input_validation,
    "resource_management": check_resource_management,
    "information_exposure": check_information_exposure,
    "access_control": check_access_control,
    "error_handling": check_error_handling,
    "concurrency": check_concurrency,
}

__all__ = [
    "check_injection", "check_injection_tool",
    "check_buffer_handling", "check_buffer_handling_tool",
    "check_authentication", "check_authentication_tool",
    "check_cryptography", "check_cryptography_tool",
    "check_input_validation", "check_input_validation_tool",
    "check_resource_management", "check_resource_management_tool",
    "check_information_exposure", "check_information_exposure_tool",
    "check_access_control", "check_access_control_tool",
    "check_error_handling", "check_error_handling_tool",
    "check_concurrency", "check_concurrency_tool",
    "SKILL_TOOLS", "SKILL_MAP",
]
