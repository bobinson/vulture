"""SSDF agent configuration."""

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "practice_groups": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["PO", "PS", "PW", "RV"],
            },
            "description": "SSDF practice groups to audit",
            "default": ["PO", "PS", "PW", "RV"],
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "NIST SSDF v1.1 Auditor",
    "type": "ssdf",
    "description": "Analyzes codebases for NIST SP 800-218 SSDF v1.1 compliance across 4 practice groups and 19 practices",
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "security_policy",
        "roles_governance",
        "toolchain_check",
        "security_criteria",
        "secure_environment",
        "code_protection",
        "release_integrity",
        "archive_protection",
        "secure_design",
        "dependency_reuse",
        "secure_coding",
        "build_security",
        "code_review",
        "security_testing",
        "secure_defaults",
        "vuln_identification",
        "vuln_remediation",
        "root_cause_analysis",
    ],
}

ALL_CATEGORIES: list[str] = ["PO", "PS", "PW", "RV"]

# Backward-compatible alias for existing imports
ALL_PRACTICE_GROUPS = ALL_CATEGORIES
