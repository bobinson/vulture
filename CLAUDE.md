# Vulture - Compliance Audit Platform

## Project Overview

Vulture is a compliance audit platform that uses AI agents to inspect source code against multiple compliance frameworks (Chaos Engineering, OWASP, SOC2). It consists of three components: a Go backend orchestrator, Python agent microservices, and a Next.js frontend.

## Architecture

```
Frontend (Next.js + CopilotKit + ag-ui) → SSE/REST → Go Backend → HTTP/SSE → Python Agent Services
```

- **Go Backend** (`backend/`): Orchestrator. Receives audit requests, manages sources (git clone / local path), dispatches to Python agents, aggregates SSE streams, serves ag-ui events to frontend. SQLite for persistence.
- **Python Agents** (`agents/`): Each audit type (chaos, owasp, soc2) is a separate FastAPI microservice using OpenAI Agents SDK + LiteLLM. Shared library in `agents/shared/`.
- **Frontend** (`frontend/`): Next.js + Tailwind + CopilotKit. Warm cream theme, compact sidebar, terminal-style agent output.
- **Deployment**: docker-compose with all services.

## Directory Structure

```
vulture/
  backend/           # Go 1.23+ backend
    cmd/vulture/     # Entry point
    internal/        # Private packages (handler, service, model, agui, repository, config)
    pkg/             # Public packages (gitutil, fileutil)
    test/e2e/        # Go E2E tests
  agents/            # Python 3.12+
    shared/          # Common tools, models, transport, LLM config
    chaos_engineering/
    owasp/
    soc2/
  frontend/          # Next.js + TypeScript
    src/app/         # Pages
    src/components/  # UI components
    src/hooks/       # React hooks
    src/lib/         # Utilities, types, API client
  docs/
    architecture/    # System docs
    features/        # Per-feature: implementation_plan.md, rollback_plan.md, implementation_status.md
```

## Development Commands

```bash
make build          # Build all components
make test           # Run all tests (Go + Python + Frontend)
make e2e            # Run E2E test suites
make coverage       # Verify 100% test coverage
make complexity     # Verify cyclomatic complexity < 10
make lint           # Lint all components
make docker-up      # Start full stack via docker-compose
make docker-down    # Stop all services
```

## Code Quality Rules

These rules are mandatory for all code in this project:

1. **E2E tests first**: Write E2E business logic tests before implementation. Never modify existing E2E tests.
2. **DRY**: No duplicated logic. Extract shared code into appropriate shared modules.
3. **Cyclomatic complexity < 10**: No function may exceed 10 independent code paths. Use early returns, strategy pattern, and delegation.
4. **100% test coverage**: Every line of code must be covered by tests.
5. **ISO 26262 safety**: Code must be categorized for safety and adhere to ISO 26262 principles.
6. **Optimize**: Code must be optimized for performance.

## Coding Conventions

### Go (backend/)
- Use standard library where possible; minimize dependencies
- All handlers accept service interfaces for testability
- All services accept repository interfaces for mock injection
- Error handling: return errors, don't panic. Wrap errors with context using `fmt.Errorf("operation: %w", err)`
- Naming: `handler/audit_handler.go`, `service/audit_service.go`, `model/audit.go`
- Tests: `*_test.go` next to source files for unit tests, `test/e2e/` for E2E
- Use `golangci-lint` for linting, `gocyclo` for complexity checks

### Python (agents/)
- Python 3.12+, type hints on all functions
- Use `@function_tool` decorator for agent tools
- Agent definitions in `agent.py`, skills in `skills/` subdirectory
- Each agent has a `SKILLS.md` documenting its capabilities
- FastAPI for HTTP, SSE for streaming
- Tests: `pytest` with `pytest-cov`, E2E in `tests/e2e/`, unit in `tests/unit/`
- Use `ruff` for linting, `radon` for complexity checks

### Frontend (frontend/)
- TypeScript strict mode
- Functional components with hooks
- CopilotKit for ag-ui protocol integration
- Tailwind CSS with custom theme (cream bg `#F6F5F4`, blue accent `#3b82f6`, green highlight `#22c55e`)
- Tests: Playwright for E2E, Vitest for unit tests
- Use `eslint` + `prettier` for linting/formatting

## Agent Extensibility

To add a new audit type (e.g., GDPR):
1. Create `agents/gdpr/` from existing agent template (agent.py, skills/, main.py, Dockerfile)
2. Add 1 line to Go agent registry in `internal/config/agents.go`
3. Add 1 service block to `docker-compose.yml`
4. Frontend auto-discovers via `GET /api/agents` — no frontend changes needed

## Key APIs

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/sources` | Submit local path or git URL |
| POST | `/api/audits` | Start audit (source + types + config) |
| GET | `/api/audits/:id` | Get audit status and results |
| GET | `/api/audits/:id/stream` | SSE stream (ag-ui events) |
| GET | `/api/agents` | List available agent types |
| GET | `/health` | Health check |

## Environment Variables

```
# Go Backend
VULTURE_PORT=8080
VULTURE_DB_PATH=/data/vulture.db
VULTURE_AGENT_CHAOS_URL=http://agent-chaos:8001
VULTURE_AGENT_OWASP_URL=http://agent-owasp:8002
VULTURE_AGENT_SOC2_URL=http://agent-soc2:8003

# Python Agents (each service)
OPENAI_API_KEY=sk-...
VULTURE_LLM_MODEL=gpt-4o    # or claude-sonnet, gemini-pro
VULTURE_AGENT_PORT=8001      # varies per agent

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8080
```
