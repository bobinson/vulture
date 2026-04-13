"""Discover agent configuration."""

ALL_CATEGORIES: list[str] = [
    "endpoint_discovery",
    "security_exposure",
    "technology_detection",
    "attack_surface",
]

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "target_url": {
            "type": "string",
            "description": "Target URL to discover (required)",
        },
        "source_path": {
            "type": "string",
            "description": "Optional path to source code for route extraction",
            "default": "",
        },
        "no_cache": {
            "type": "boolean",
            "description": "Skip cached results and run full rediscovery",
            "default": False,
        },
        "rate_limit": {
            "type": "number",
            "description": "Delay in seconds between HTTP requests (0 = no limit)",
            "default": 0,
            "minimum": 0,
        },
        "categories": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ALL_CATEGORIES,
            },
            "description": "Discovery categories to run",
            "default": ALL_CATEGORIES,
        },
        "ignore_scan_results": {
            "type": "boolean",
            "description": "Skip using scan results for discovery enrichment (default: false)",
            "default": False,
        },
        "scan_findings": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Scan findings injected by pipeline orchestrator",
            "default": [],
        },
    },
    "required": ["target_url"],
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "Endpoint Discover",
    "type": "discover",
    "description": (
        "Discovers API endpoints, maps attack surface, detects technologies, "
        "and identifies security exposures on a target URL using a 22-plugin "
        "tiered discovery pipeline"
    ),
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "endpoint_discovery",
        "security_exposure_analysis",
        "technology_detection",
        "attack_surface_mapping",
    ],
}
