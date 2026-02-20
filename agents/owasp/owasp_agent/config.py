"""OWASP agent configuration."""

ALL_CATEGORIES: list[str] = [
    "injection",
    "auth_failure",
    "crypto_failure",
    "access_control",
    "security_misconfig",
    "insecure_design",
    "vulnerable_components",
    "data_integrity",
    "logging_failure",
    "ssrf",
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
            "description": "OWASP categories to audit",
            "default": ALL_CATEGORIES,
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "OWASP Security Auditor",
    "type": "owasp",
    "description": "Analyzes code for OWASP Top 10 security vulnerabilities",
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "injection_check",
        "auth_check",
        "crypto_check",
        "access_control",
        "security_misconfig",
        "insecure_design",
        "vulnerable_components",
        "data_integrity",
        "logging_check",
        "ssrf_check",
    ],
}
