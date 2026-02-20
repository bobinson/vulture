# OWASP Audit - Implementation Plan

## Overview

The OWASP audit agent analyzes source code for security vulnerabilities aligned with the OWASP Top 10 (2021). It inspects code for common web application security flaws including injection attacks, broken authentication, sensitive data exposure, and more. The agent runs as a standalone Python FastAPI microservice.

## Requirements

1. Analyze source code against the OWASP Top 10 2021 categories
2. Each OWASP category is independently selectable -- users choose which categories to audit
3. Support custom rule sets beyond the standard Top 10
4. Produce structured findings with severity, CWE references, file location, and remediation guidance
5. Stream analysis progress via SSE
6. Return a security score (0-100) with per-category breakdowns

## Technical Design

### Agent Definition

```python
# agents/owasp/agent.py
owasp_agent = Agent(
    name="OWASPSecurityAuditor",
    instructions="...",
    tools=[list_files, read_file, parse_ast,
           check_injection, check_broken_auth,
           check_sensitive_data, check_xxe,
           check_broken_access, check_misconfig,
           check_xss, check_deserialization,
           check_components, check_logging],
)
```

### Skills

| Skill | OWASP Category | Description |
|-------|---------------|-------------|
| `check_injection` | A01:2021 Broken Access Control | SQL injection, command injection, LDAP injection |
| `check_broken_auth` | A02:2021 Cryptographic Failures | Weak password handling, session management, credential storage |
| `check_sensitive_data` | A03:2021 Injection | Hardcoded secrets, unencrypted PII, API key exposure |
| `check_xxe` | A04:2021 Insecure Design | XML external entity processing, DTD parsing |
| `check_broken_access` | A05:2021 Security Misconfiguration | Missing authorization checks, privilege escalation paths |
| `check_misconfig` | A06:2021 Vulnerable Components | Default credentials, debug mode, unnecessary services |
| `check_xss` | A07:2021 Auth Failures | Cross-site scripting: reflected, stored, DOM-based |
| `check_deserialization` | A08:2021 Software Integrity | Unsafe deserialization, pickle/yaml loading |
| `check_components` | A09:2021 Logging Failures | Known vulnerable dependencies, outdated libraries |
| `check_logging` | A10:2021 SSRF | Insufficient logging, missing audit trails, log injection |

### Config Schema

```json
{
  "type": "object",
  "properties": {
    "categories": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
      },
      "default": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
      "description": "OWASP Top 10 categories to audit"
    },
    "custom_rules": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "pattern": { "type": "string" },
          "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
          "message": { "type": "string" }
        }
      },
      "description": "Custom regex-based rules to apply"
    }
  }
}
```

### Finding Format

```json
{
  "severity": "critical",
  "category": "A03-injection",
  "title": "SQL Injection via string concatenation",
  "description": "User input directly concatenated into SQL query without parameterization",
  "file_path": "src/db/queries.go",
  "line_start": 45,
  "line_end": 47,
  "recommendation": "Use parameterized queries or prepared statements",
  "references": [
    "https://owasp.org/Top10/A03_2021-Injection/",
    "https://cwe.mitre.org/data/definitions/89.html"
  ]
}
```

### Scoring

- Each OWASP category: 0-100 based on violation count and severity
- Critical finding: -25 points, High: -15, Medium: -8, Low: -3
- Overall score: weighted average across selected categories
- Categories with zero findings score 100

## API Changes

No changes to the Go backend API. Agent uses the standard internal protocol.

## Testing Strategy

### E2E Tests (`agents/owasp/tests/e2e/`)

- Submit source with known SQL injection patterns and verify critical finding
- Submit source with hardcoded secrets and verify sensitive data finding
- Submit clean source and verify high score
- Select specific categories and verify only those are audited
- Verify CWE references in findings are valid
- Verify SSE stream event sequence

### Unit Tests (`agents/owasp/tests/unit/`)

- Each skill function tested with vulnerable and clean code samples
- Test injection detection across languages (Go, Python, JS, Java)
- Test secret detection patterns (API keys, passwords, tokens)
- Test scoring calculation
- Test custom rule application

## Dependencies

- `agents-sdk`: OpenAI Agents SDK
- `litellm`: Model-agnostic LLM access
- `fastapi` + `sse-starlette`: HTTP and SSE
- `agents/shared/`: Common tools and transport
