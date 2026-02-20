# Chaos Engineering Audit - Implementation Plan

## Overview

The Chaos Engineering audit agent analyzes source code for resilience patterns and chaos engineering readiness. It evaluates whether the codebase implements proper retry logic, circuit breakers, timeouts, fallbacks, and blast radius containment. The agent runs as a standalone Python FastAPI microservice using the OpenAI Agents SDK.

## Requirements

1. Analyze source code for five resilience pattern categories: retry, circuit breaker, timeout, fallback, and blast radius
2. Each category is independently configurable -- users select which patterns to audit
3. Produce structured findings with severity, file location, and recommendations
4. Stream analysis progress via SSE to the Go backend
5. Return an overall resilience score (0-100)
6. Support Go, Python, Java, TypeScript, and Rust codebases

## Technical Design

### Agent Definition

```python
# agents/chaos_engineering/agent.py
chaos_agent = Agent(
    name="ChaosEngineeringAuditor",
    instructions="...",
    tools=[list_files, read_file, parse_ast,
           check_retry_patterns, check_circuit_breaker,
           check_timeout_handling, check_fallback_logic,
           check_blast_radius],
)
```

### Skills

| Skill | Function | Description |
|-------|----------|-------------|
| Retry Analysis | `check_retry_patterns` | Detects retry logic, exponential backoff, max attempts, jitter |
| Circuit Breaker | `check_circuit_breaker` | Identifies circuit breaker implementations, state management, thresholds |
| Timeout Handling | `check_timeout_handling` | Finds timeout configurations on HTTP calls, DB queries, external services |
| Fallback Logic | `check_fallback_logic` | Detects fallback/degradation patterns for service failures |
| Blast Radius | `check_blast_radius` | Evaluates failure isolation, bulkhead patterns, resource limits |

### Config Schema

Exposed via `GET /info` for frontend dynamic rendering:

```json
{
  "type": "object",
  "properties": {
    "categories": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["retry", "circuit_breaker", "timeout", "fallback", "blast_radius"]
      },
      "default": ["retry", "circuit_breaker", "timeout", "fallback", "blast_radius"],
      "description": "Resilience pattern categories to audit"
    }
  }
}
```

### SSE Event Flow

```
agent_start → tool_call(list_files) → tool_result → tool_call(read_file) →
tool_result → thinking("Analyzing retry patterns...") → finding({severity: "high", ...}) →
progress({files_analyzed: 5, total: 20}) → ... → result({score: 72, findings: [...]}) → agent_end
```

### Scoring

Each category contributes to the overall score:

- Per-category score: 0-100 based on pattern coverage and quality
- Overall score: weighted average across selected categories
- Weights: equal by default, configurable per category
- Critical findings reduce the category score by 20 points each
- High findings reduce by 10, medium by 5, low by 2

### FastAPI Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/run` | Execute audit with SSE streaming response |
| GET | `/health` | Health check |
| GET | `/info` | Agent metadata and config schema |

## API Changes

No changes to the Go backend API. The Go backend dispatches to this agent via the internal agent protocol defined in `docs/architecture/agent_protocol.md`.

## Testing Strategy

### E2E Tests (`agents/chaos_engineering/tests/e2e/`)

- Submit a source path with known retry patterns and verify findings
- Submit a source path with no resilience patterns and verify low score
- Submit with specific categories selected and verify only those are audited
- Verify SSE event stream contains expected event sequence
- Verify structured finding format (severity, file path, line numbers)

### Unit Tests (`agents/chaos_engineering/tests/unit/`)

- Each skill function tested with sample code snippets
- Test retry detection across Go, Python, TypeScript patterns
- Test circuit breaker detection (Hystrix, resilience4j, gobreaker, custom)
- Test scoring calculation with various finding combinations
- Test config schema validation

## Dependencies

- `agents-sdk`: OpenAI Agents SDK for agent definition and tool execution
- `litellm`: Model-agnostic LLM access
- `fastapi` + `sse-starlette`: HTTP server with SSE streaming
- `agents/shared/`: Common tools and transport layer
