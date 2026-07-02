"""CWE Weakness Auditor agent configuration."""

ALL_CATEGORIES: list[str] = [
    "injection",
    "buffer_handling",
    "authentication",
    "cryptography",
    "input_validation",
    "resource_management",
    "information_exposure",
    "access_control",
    "error_handling",
    "concurrency",
    "web_security",
    "configuration",
    "dependency_security",
    "data_handling",
    "memory_safety",
    "path_equivalence",
    "divide_by_zero",
    "dangerous_function",
    "insufficient_logging",
    "uncaught_exception",
    "weak_entropy",
    "catalog_generic",
]

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "categories": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ALL_CATEGORIES,
            },
            "description": "CWE weakness categories to audit",
            "default": ALL_CATEGORIES,
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "CWE Weakness Auditor",
    "type": "cwe",
    "description": (
        "Analyzes code for Common Weakness Enumeration (CWE v4.19.1) "
        "vulnerabilities. Deterministic skills detect ~73 declared CWE-ID "
        "categories plus 7 trusted signature CWEs; N=10 CWE types are "
        "corpus-VERIFIED (see VERIFIED_CWES.md). The 846-entry CWE catalog is "
        "metadata/context (not a detection-coverage claim); it drives "
        "self-learning confidence scoring and MMR-based memory retrieval"
    ),
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "injection_check",
        "buffer_check",
        "auth_check",
        "crypto_check",
        "input_validation_check",
        "resource_check",
        "info_exposure_check",
        "access_control_check",
        "error_handling_check",
        "concurrency_check",
        "web_security_check",
        "configuration_check",
        "dependency_check",
        "data_handling_check",
        "memory_safety_check",
        "path_equivalence_check",
        "divide_by_zero_check",
        "dangerous_function_check",
        "insufficient_logging_check",
        "uncaught_exception_check",
        "weak_entropy_check",
        "catalog_detector",
    ],
}
