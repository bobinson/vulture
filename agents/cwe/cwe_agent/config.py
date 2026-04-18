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
        "vulnerabilities across 846 software-relevant CWE IDs in 17 categories "
        "with catalog-driven detection, self-learning confidence scoring, "
        "and MMR-based memory retrieval"
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
        "catalog_detector",
    ],
}
