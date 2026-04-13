# Vulture - Extensibility Guide

## Adding a New Audit Type

Vulture is designed so that adding a new audit type (e.g., GDPR, HIPAA, PCI-DSS) requires changes in exactly three places with zero frontend modifications. The frontend auto-discovers new agents via `GET /api/agents`.

This guide walks through adding a hypothetical **GDPR** audit agent.

---

## Step 1: Create the Python Agent Service

Create `agents/gdpr/` using the existing agent template structure.

### Directory Structure

```
agents/gdpr/
  agent.py          # Agent definition (name, instructions, tools)
  main.py           # FastAPI entrypoint with /run, /health, /info endpoints
  skills/           # Compliance-specific skill functions
    __init__.py
    data_mapping.py
    consent_check.py
    retention_policy.py
  tests/
    e2e/
      test_gdpr_e2e.py
    unit/
      test_skills.py
  SKILLS.md         # Agent capability documentation (REQUIRED)
  Dockerfile
  pyproject.toml
```

### agent.py

Define the agent using the OpenAI Agents SDK:

```python
from agents import Agent
from agents.shared.tools import list_files, read_file, parse_ast
from .skills.data_mapping import check_data_mapping
from .skills.consent_check import check_consent_mechanisms
from .skills.retention_policy import check_retention_policies

gdpr_agent = Agent(
    name="GDPRComplianceAuditor",
    instructions="""You are a GDPR compliance auditor. Analyze source code for
    compliance with GDPR regulations including data mapping, consent mechanisms,
    data retention policies, right to erasure support, and data protection
    impact assessments.""",
    tools=[
        list_files,
        read_file,
        parse_ast,
        check_data_mapping,
        check_consent_mechanisms,
        check_retention_policies,
    ],
)
```

### Skills

Each skill is a `@function_tool` decorated function in the `skills/` directory:

```python
from agents import function_tool

@function_tool
def check_data_mapping(code: str, file_path: str) -> dict:
    """Analyze code for personal data handling and mapping compliance.

    Checks for:
    - Personal data field identification
    - Data flow tracking
    - Cross-border transfer markers
    """
    # Implementation here
    ...
```

### main.py

Use the shared FastAPI template from `agents/shared/`:

```python
from shared.transport.sse_app import create_sse_app

from gdpr_agent.agent import run_audit
from gdpr_agent.config import AGENT_INFO

app = create_sse_app(
    agent_name="gdpr",
    agent_info=AGENT_INFO,
    run_handler=run_audit,
)
```

### SKILLS.md

Every agent **must** have a SKILLS.md documenting its capabilities:

```markdown
# GDPR Compliance Auditor - Skills

## Agent: GDPRComplianceAuditor

### Skills

| Skill | Function | Description |
|-------|----------|-------------|
| Data Mapping | check_data_mapping | Identifies personal data fields, tracks data flows |
| Consent Check | check_consent_mechanisms | Verifies consent collection and management |
| Retention Policy | check_retention_policies | Validates data retention and deletion logic |

### Configurable Articles
- Art 5: Principles of processing
- Art 6: Lawfulness of processing
- Art 7: Conditions for consent
...
```

### Dockerfile

```dockerfile
FROM vulture-agent-base:latest
WORKDIR /app
COPY . .
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28009}"]
```

---

## Step 2: Register the Agent in the Go Backend

Add one entry to the `AllAgents` slice in `backend/pkg/agentregistry/registry.go`:

```go
// registry.go - Agent registry
var AllAgents = []AgentRegistryEntry{
    {"chaos", "Chaos Engineering", "28001", "chaos_engineering", "chaos_agent.main:app", "agent_chaos"},
    {"owasp", "OWASP", "28002", "owasp", "owasp_agent.main:app", "agent_owasp"},
    {"soc2", "SOC2", "28003", "soc2", "soc2_agent.main:app", "agent_soc2"},
    {"cwe", "CWE", "28004", "cwe", "cwe_agent.main:app", "agent_cwe"},
    // ... other agents ...
    // Add this single line:
    {"gdpr", "GDPR", "28009", "gdpr", "gdpr_agent.main:app", "agent_gdpr"},
}
```

The Go backend uses this registry to:
- Build the `GET /api/agents` response (frontend auto-discovery)
- Route audit requests to the correct agent URL
- Check agent health on startup

No other Go code changes are needed. The existing handlers, services, and SSE aggregation logic all work generically with any registered agent.

---

## Step 3: Add to docker-compose.yml

Add one service block:

```yaml
  agent-gdpr:
    build:
      context: ./agents
      dockerfile: gdpr/Dockerfile
    expose:
      - "${VULTURE_AGENT_GDPR_PORT:-28009}"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - VULTURE_LLM_MODEL=${VULTURE_LLM_MODEL:-gpt-4o}
      - VULTURE_AGENT_PORT=${VULTURE_AGENT_GDPR_PORT:-28009}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:28009/health"]
      interval: 10s
      timeout: 5s
      retries: 3
    depends_on:
      - backend
```

Add the environment variable to the backend service:

```yaml
  backend:
    environment:
      - VULTURE_AGENT_GDPR_URL=http://agent-gdpr:${VULTURE_AGENT_GDPR_PORT:-28009}
```

---

## Step 4: Frontend Auto-Discovery (No Changes Required)

The frontend calls `GET /api/agents` on load, which returns all registered agents from the Go backend. The response includes each agent's `config_schema`, which the frontend uses to dynamically render configuration options.

```json
GET /api/agents

[
  { "type": "chaos", "name": "Chaos Engineering", "config_schema": {...} },
  { "type": "owasp", "name": "OWASP", "config_schema": {...} },
  { "type": "soc2",  "name": "SOC2",  "config_schema": {...} },
  { "type": "gdpr",  "name": "GDPR",  "config_schema": {...} }
]
```

The frontend renders audit type selectors and configuration forms from the `config_schema` using JSON Schema form generation. The new GDPR agent appears automatically.

---

## Summary of Changes

| Location | Change | Lines |
|----------|--------|-------|
| `agents/gdpr/` | New agent service (from template) | ~200 |
| `backend/pkg/agentregistry/registry.go` | Add registry entry | 1 |
| `docker-compose.yml` | Add service block + env var | ~15 |
| Frontend | None | 0 |

## Shared Library (`agents/shared/`)

The shared library provides common functionality to all agents:

- **`tools/`**: file_scanner, file_reader, file_lister, ast_parser, pattern_matcher, dependency_checker, memory_client
- **`models/`**: audit_request, audit_result, finding
- **`transport/sse_app.py`**: FastAPI app factory with `/run`, `/health`, `/info` endpoints and SSE streaming
- **`llm/provider.py`**: LiteLLM configuration for model-agnostic LLM access

When building a new agent, import these shared components rather than reimplementing them.

## Testing Requirements

New agents must include:

1. **E2E tests** (`tests/e2e/`): Test the full `/run` endpoint with sample source code
2. **Unit tests** (`tests/unit/`): Test each skill function independently
3. **100% coverage**: All code paths must be covered
4. **Complexity < 10**: All functions must have cyclomatic complexity under 10
