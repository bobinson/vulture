"""SOC2 agent configuration."""

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "clauses": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["CC6", "CC7", "CC8"],
            },
            "description": "SOC2 compliance clauses to audit",
            "default": ["CC6", "CC7", "CC8"],
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "SOC2 Compliance Auditor",
    "type": "soc2",
    "description": "Analyzes code for SOC2 compliance requirements",
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "access_logging",
        "encryption_check",
        "change_management",
        "monitoring_check",
        "data_retention",
    ],
}

ALL_CATEGORIES: list[str] = ["CC6", "CC7", "CC8"]

# Backward-compatible alias for existing imports
ALL_CLAUSES = ALL_CATEGORIES
