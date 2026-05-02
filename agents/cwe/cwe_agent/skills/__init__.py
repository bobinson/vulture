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
from cwe_agent.skills.web_security_check import check_web_security, check_web_security_tool
from cwe_agent.skills.configuration_check import check_configuration, check_configuration_tool
from cwe_agent.skills.dependency_check import check_dependency_security, check_dependency_security_tool
from cwe_agent.skills.data_handling_check import check_data_handling, check_data_handling_tool
from cwe_agent.skills.memory_safety_check import check_memory_safety, check_memory_safety_tool
from cwe_agent.skills.path_equivalence_check import check_path_equivalence, check_path_equivalence_tool
from cwe_agent.skills.divide_by_zero_check import check_divide_by_zero, check_divide_by_zero_tool
from cwe_agent.skills.dangerous_function_check import check_dangerous_function, check_dangerous_function_tool
from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging, check_insufficient_logging_tool
from cwe_agent.skills.uncaught_exception_check import check_uncaught_exception, check_uncaught_exception_tool
from cwe_agent.skills.weak_entropy_check import check_weak_entropy, check_weak_entropy_tool
from cwe_agent.skills.catalog_detector import check_catalog_generic, check_catalog_generic_tool
from cwe_agent.skills.secret_scan import check_secrets, check_secrets_tool

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
    check_web_security_tool,
    check_configuration_tool,
    check_dependency_security_tool,
    check_data_handling_tool,
    check_memory_safety_tool,
    check_path_equivalence_tool,
    check_divide_by_zero_tool,
    check_dangerous_function_tool,
    check_insufficient_logging_tool,
    check_uncaught_exception_tool,
    check_weak_entropy_tool,
    check_catalog_generic_tool,
    check_secrets_tool,
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
    "web_security": check_web_security,
    "configuration": check_configuration,
    "dependency_security": check_dependency_security,
    "data_handling": check_data_handling,
    "memory_safety": check_memory_safety,
    "path_equivalence": check_path_equivalence,
    "divide_by_zero": check_divide_by_zero,
    "dangerous_function": check_dangerous_function,
    "insufficient_logging": check_insufficient_logging,
    "uncaught_exception": check_uncaught_exception,
    "weak_entropy": check_weak_entropy,
    "catalog_generic": check_catalog_generic,
    "secrets": check_secrets,
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
    "check_web_security", "check_web_security_tool",
    "check_configuration", "check_configuration_tool",
    "check_dependency_security", "check_dependency_security_tool",
    "check_data_handling", "check_data_handling_tool",
    "check_memory_safety", "check_memory_safety_tool",
    "check_path_equivalence", "check_path_equivalence_tool",
    "check_divide_by_zero", "check_divide_by_zero_tool",
    "check_dangerous_function", "check_dangerous_function_tool",
    "check_insufficient_logging", "check_insufficient_logging_tool",
    "check_uncaught_exception", "check_uncaught_exception_tool",
    "check_weak_entropy", "check_weak_entropy_tool",
    "check_catalog_generic", "check_catalog_generic_tool",
    "check_secrets", "check_secrets_tool",
    "SKILL_TOOLS", "SKILL_MAP",
]
