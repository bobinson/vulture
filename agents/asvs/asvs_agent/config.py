"""ASVS Compliance Auditor agent configuration."""

ALL_CATEGORIES: list[str] = ["asvs_requirements"]

_CHAPTERS = [
    "V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9",
    "V10", "V11", "V12", "V13", "V14", "V15", "V16", "V17",
]

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "categories": {
            "type": "array",
            "items": {"type": "string", "enum": ALL_CATEGORIES},
            "description": "Always ['asvs_requirements']; kept for API symmetry with other agents.",
            "default": ALL_CATEGORIES,
        },
        "chapters": {
            "type": "array",
            "items": {"type": "string", "enum": _CHAPTERS},
            "description": "ASVS chapters to audit (empty list = all chapters)",
            "default": [],
        },
        "levels": {
            "type": "array",
            "items": {"type": "integer", "enum": [1, 2, 3]},
            "description": "Verification levels to include. L1 reqs apply at all levels; L2 at L2+L3; L3 at L3 only.",
            "default": [1, 2, 3],
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "ASVS Compliance Auditor",
    "type": "asvs",
    "description": (
        "Audits source code against OWASP Application Security "
        "Verification Standard (ASVS) v5.0.0 — 345 requirements "
        "across 17 chapters and 3 verification levels (L1/L2/L3) with "
        "consolidated per-requirement dispatch and CWE cross-linking."
    ),
    "config_schema": CONFIG_SCHEMA,
    "skills": ["asvs_requirements_check"],
}
