"""DO-178C agent configuration and DAL severity mapping."""

ALL_CATEGORIES = [
    "dead_code",
    "mcdc_coverage",
    "recursion",
    "malloc",
    "traceability",
    "timing",
]

DAL_LEVELS = ["A", "B", "C", "D", "E"]

_DAL_MAP: dict[str, dict[str, str]] = {
    "A": {
        "dead_code": "critical",
        "mcdc_coverage": "critical",
        "recursion": "critical",
        "malloc": "critical",
        "traceability": "critical",
        "timing": "critical",
    },
    "B": {
        "dead_code": "critical",
        "mcdc_coverage": "high",
        "recursion": "critical",
        "malloc": "critical",
        "traceability": "high",
        "timing": "high",
    },
    "C": {
        "dead_code": "high",
        "recursion": "high",
        "malloc": "high",
        "traceability": "high",
        "timing": "medium",
    },
    "D": {
        "dead_code": "medium",
        "malloc": "medium",
        "traceability": "medium",
    },
    "E": {},
}


def dal_severity(dal: str, skill: str) -> str:
    return _DAL_MAP.get(dal, {}).get(skill, "info")


def dal_skip(dal: str, skill: str) -> bool:
    return skill not in _DAL_MAP.get(dal, {})


CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "dal_level": {
            "type": "string",
            "enum": DAL_LEVELS,
            "default": "C",
            "description": "Design Assurance Level (A=catastrophic through E=no effect)",
        },
        "categories": {
            "type": "array",
            "items": {"type": "string", "enum": ALL_CATEGORIES},
            "default": ALL_CATEGORIES,
            "description": "DO-178C objective categories to audit",
        },
    },
}

AGENT_INFO = {
    "type": "do178c",
    "name": "DO-178C Compliance Auditor",
    "description": "Static analysis for DO-178C/ED-12C software assurance objectives. "
    "Configurable by Design Assurance Level (DAL A-E). Covers dead code, "
    "MC/DC coverage gaps, recursion, dynamic allocation, requirements "
    "traceability, and deterministic timing.",
    "config_schema": CONFIG_SCHEMA,
    "skills": ALL_CATEGORIES,
}
