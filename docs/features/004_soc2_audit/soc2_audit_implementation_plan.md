# SOC2 Audit - Implementation Plan

## Overview

The SOC2 audit agent analyzes source code for compliance with SOC2 Trust Services Criteria. It is configurable down to specific Common Criteria (CC) clauses, allowing targeted audits against CC6 (Logical and Physical Access Controls), CC7 (System Operations), CC8 (Change Management), and other SOC2 criteria. The agent uses sub-agent delegation for each clause family.

## Requirements

1. Analyze source code against SOC2 Trust Services Criteria
2. Configurable to specific CC clauses (CC6, CC7, CC8, CC9, etc.)
3. Each CC clause family handled by a dedicated sub-agent with specialized skills
4. Produce findings with SOC2 clause references, evidence, and remediation steps
5. Stream progress via SSE with per-clause status updates
6. Return compliance scores per clause and an overall compliance percentage

## Technical Design

### Agent Architecture

The SOC2 agent uses a hierarchical agent pattern:

```
SOC2OrchestratorAgent (top-level)
  ├── CC6Agent (Logical and Physical Access Controls)
  ├── CC7Agent (System Operations)
  ├── CC8Agent (Change Management)
  └── CC9Agent (Risk Mitigation)
```

The orchestrator delegates to sub-agents based on the selected clauses.

### Skills by Clause

#### CC6 - Logical and Physical Access Controls

| Skill | Description |
|-------|-------------|
| `check_auth_mechanisms` | Authentication implementation quality (MFA, password hashing, session management) |
| `check_access_control` | Authorization checks, RBAC implementation, least privilege |
| `check_encryption` | Data encryption at rest and in transit, key management |
| `check_network_security` | TLS configuration, certificate validation, secure headers |

#### CC7 - System Operations

| Skill | Description |
|-------|-------------|
| `check_monitoring` | Logging infrastructure, alerting, observability |
| `check_incident_response` | Error handling patterns, circuit breakers, health checks |
| `check_vulnerability_mgmt` | Dependency scanning, security headers, input validation |
| `check_backup_recovery` | Data persistence patterns, backup logic, recovery procedures |

#### CC8 - Change Management

| Skill | Description |
|-------|-------------|
| `check_version_control` | Git workflow, branch protection indicators, commit signing |
| `check_testing_practices` | Test coverage, CI/CD patterns, test quality |
| `check_deployment_safety` | Feature flags, rollback mechanisms, canary deployment patterns |
| `check_code_review` | Review process indicators, approval patterns |

#### CC9 - Risk Mitigation

| Skill | Description |
|-------|-------------|
| `check_error_handling` | Error propagation, graceful degradation, panic recovery |
| `check_input_validation` | Input sanitization, boundary checks, type safety |
| `check_dependency_risk` | License compliance, dependency freshness, known vulnerabilities |

### Config Schema

```json
{
  "type": "object",
  "properties": {
    "clauses": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["CC6", "CC7", "CC8", "CC9"]
      },
      "default": ["CC6", "CC7", "CC8"],
      "description": "SOC2 Common Criteria clause families to audit"
    },
    "depth": {
      "type": "string",
      "enum": ["surface", "standard", "deep"],
      "default": "standard",
      "description": "Audit depth: surface (quick scan), standard (balanced), deep (thorough)"
    }
  }
}
```

### Finding Format

```json
{
  "severity": "high",
  "category": "CC6-access-control",
  "title": "Missing authorization check on admin endpoint",
  "description": "The /admin/users endpoint does not verify the caller has admin privileges before returning user data",
  "file_path": "src/handlers/admin.go",
  "line_start": 23,
  "line_end": 35,
  "recommendation": "Add middleware or explicit authorization check verifying admin role before processing the request",
  "references": [
    "https://www.aicpa.org/resources/article/soc-2-trust-services-criteria",
    "CC6.1 - Logical access security"
  ]
}
```

### Scoring

- Per-clause score: 0-100 based on criteria coverage and finding severity
- Compliance percentage: (clauses passing threshold / total clauses) * 100
- Pass threshold: configurable, default 70
- Critical finding: clause automatically fails regardless of other scores
- Overall score: weighted average with critical clause penalties

### SSE Event Flow

```
agent_start →
  StepStarted("CC6") → tool_calls → findings → StepFinished("CC6") →
  StepStarted("CC7") → tool_calls → findings → StepFinished("CC7") →
  StepStarted("CC8") → tool_calls → findings → StepFinished("CC8") →
result({scores: {CC6: 85, CC7: 72, CC8: 90}, overall: 82}) →
agent_end
```

## API Changes

No changes to the Go backend API. Agent uses the standard internal protocol.

## Testing Strategy

### E2E Tests (`agents/soc2/tests/e2e/`)

- Submit source with missing auth checks and verify CC6 findings
- Submit source with no logging and verify CC7 findings
- Submit source with no tests and verify CC8 findings
- Select specific clauses and verify only those are audited
- Verify per-clause scoring in results
- Verify deep audit produces more findings than surface audit
- Verify SSE stream contains per-clause step events

### Unit Tests (`agents/soc2/tests/unit/`)

- Each skill function tested with compliant and non-compliant code
- Test sub-agent delegation logic
- Test scoring and threshold calculations
- Test config validation (clause selection, depth)

## Dependencies

- `agents-sdk`: OpenAI Agents SDK (supports sub-agent handoff)
- `litellm`: Model-agnostic LLM access
- `fastapi` + `sse-starlette`: HTTP and SSE
- `agents/shared/`: Common tools and transport
