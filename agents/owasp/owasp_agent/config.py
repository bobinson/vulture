"""OWASP agent configuration (mapping mode, feature 0063).

The OWASP agent maps CWE findings onto OWASP Top 10 categories; it performs
no detection. Edition options are read lazily and fault-tolerantly so a bad
data file can never break agent import (the agent must always start).
"""

CATEGORY_IDS: list[str] = [f"A{n:02d}" for n in range(1, 11)]


def _default_edition() -> str:
    try:
        from shared.owasp.mapping import load_edition

        return load_edition().edition_id
    except Exception:
        return "2025"


def _editions() -> list[str]:
    try:
        from shared.owasp.mapping import available_editions

        return available_editions()
    except Exception:
        return ["2025", "2021"]


CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "edition": {
            "type": "string",
            "enum": _editions(),
            "description": "OWASP Top 10 edition to map against",
            "default": _default_edition(),
        },
        "categories": {
            "type": "array",
            "items": {"type": "string", "enum": CATEGORY_IDS},
            "description": "OWASP category ids to include (empty = all)",
            "default": [],
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "OWASP Top 10 Categorizer",
    "type": "owasp",
    "description": (
        "Maps CWE findings (produced by the CWE agent, a prerequisite) onto "
        "OWASP Top 10 categories for a selected edition (2021 or 2025). "
        "Performs no detection of its own; emits per-category coverage."
    ),
    "requires": ["cwe"],
    "config_schema": CONFIG_SCHEMA,
    "skills": [],
}
