"""Prove agent configuration."""

ALL_TYPES: list[str] = [
    "owasp",
    "chaos",
    "soc2",
    "cwe",
    "ssdf",
    "xss",
]

CONFIG_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "types": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": ALL_TYPES,
            },
            "description": "Scanner types whose findings to verify",
            "default": ALL_TYPES,
        },
        "staging_url": {
            "type": "string",
            "description": "Staging environment URL to test against",
        },
        "max_iterations": {
            "type": "integer",
            "description": "Max verification attempts per finding (capped at 10)",
            "default": 3,
            "minimum": 1,
            "maximum": 10,
        },
        "allow_local": {
            "type": "boolean",
            "description": "Allow targeting localhost/local IPs",
            "default": False,
        },
        "schemas": {
            "type": "object",
            "description": "User-provided schema file paths for discovery (e.g. graphql, openapi)",
            "properties": {
                "graphql": {
                    "type": "string",
                    "description": "Path to GraphQL schema file (.graphql SDL or introspection JSON)",
                },
                "openapi": {
                    "type": "string",
                    "description": "Path to OpenAPI/Swagger spec file (.json or .yaml)",
                },
                "wsdl": {
                    "type": "string",
                    "description": "Path to WSDL service description file",
                },
                "grpc": {
                    "type": "string",
                    "description": "Path to gRPC .proto file or directory",
                },
                "proto": {
                    "type": "string",
                    "description": "Path to Protocol Buffers .proto file",
                },
            },
            "additionalProperties": True,
        },
    },
    "required": ["staging_url"],
    "additionalProperties": False,
}

AGENT_INFO: dict = {
    "name": "Prove Companion Agent",
    "type": "prove",
    "description": "Autonomously verifies scanner findings against a staging environment using Plan-Review-Execute loops",
    "config_schema": CONFIG_SCHEMA,
    "skills": [
        "owasp_verification",
        "chaos_verification",
        "soc2_verification",
        "cwe_verification",
    ],
}
