"""Chaos Engineering agent configuration."""

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "categories": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ["retry", "circuit_breaker", "timeout", "fallback", "blast_radius"],
            },
            "description": "Resilience pattern categories to audit",
            "default": ["retry", "circuit_breaker", "timeout", "fallback", "blast_radius"],
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "Chaos Engineering Auditor",
    "type": "chaos",
    "description": "Analyzes code for resilience and chaos engineering patterns",
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "retry_analysis",
        "circuit_breaker",
        "timeout_analysis",
        "fallback_analysis",
        "blast_radius",
    ],
}

ALL_CATEGORIES: list[str] = [
    "retry", "circuit_breaker", "timeout", "fallback", "blast_radius",
]
