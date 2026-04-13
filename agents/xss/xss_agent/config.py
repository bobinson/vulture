"""XSS vulnerability scanner agent configuration."""

ALL_CATEGORIES: list[str] = [
    "reflected_xss",
    "stored_xss",
    "dom_xss",
    "template_injection",
    "header_injection",
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
            "description": "XSS vulnerability categories to audit",
            "default": ALL_CATEGORIES,
        },
    },
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "XSS Scanner",
    "type": "xss",
    "description": (
        "Detects cross-site scripting vulnerabilities across 5 categories: "
        "reflected XSS, stored XSS, DOM-based XSS, template injection (SSTI), "
        "and header injection with missing security headers. "
        "Covers CWE-79, CWE-113, CWE-644, and CWE-1336."
    ),
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "reflected_xss_check",
        "stored_xss_check",
        "dom_xss_check",
        "template_injection_check",
        "header_injection_check",
    ],
}
