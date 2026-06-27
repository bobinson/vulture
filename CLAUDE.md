# Vulture - Compliance Audit Platform

## Project Overview

Vulture is an application that loads source code from a local folder or git repository and inspects it for compliance against:

1. **Chaos Engineering principles**
2. **OWASP guidelines**
3. **SOC2** (configurable down to specific compliance clauses)

Each audit option is further configurable based on complexity. For SOC2, users select specific compliance clauses to audit against. The system is built to be extensible for other types of compliance and audits.

AI agents for each audit type are launched independently. Each agent has precisely defined skills (documented in SKILLS.md) and uses the OpenAI Agents SDK (https://github.com/openai/openai-agents-python) with support for OpenAI, Claude, and Gemini models.

## Architecture

```
Frontend (React SPA + Vite) → SSE/REST → Go Backend → HTTP/SSE → Python Agent Services
                                              ↓
                                     PostgreSQL + pgvector
```

- **Go Backend** (`backend/`): Orchestrator. Receives audit requests, manages sources (git clone / local path), dispatches to Python agents concurrently, aggregates SSE streams, serves structured SSE events to frontend. PostgreSQL (pgvector) for production, SQLite fallback for local dev.
- **Python Agents** (`agents/`): Each audit type (chaos, owasp, soc2) is a separate FastAPI microservice using OpenAI Agents SDK + LiteLLM. Shared library in `agents/shared/`.
- **Frontend** (`frontend/`): React SPA (Vite) + Tailwind + react-i18next. Plain React with native EventSource for SSE streaming. Look and feel must be elegant like https://agentation.dev — intuitive, simple, elegant. Warm cream theme, compact sidebar, terminal-style agent output.
- **CLI** (`cli/`): Go CLI binary for headless audit execution (`vulture scan`, `vulture watch`, `vulture list`).
- **Deployment**: `docker compose` with all services (PostgreSQL, backend, 9 agents, frontend).

### Deployment Modes

Same binaries and Docker images serve all modes. Mode selection is via env vars only.

| Mode | Who runs it | Command | Notes |
|------|-------------|---------|-------|
| A: Dev-local | Developer laptop | `docker compose up` | SQLite or local Postgres; `VULTURE_LOCAL_MODE=true`; no new env vars required |
| B: Centralized server | Ops VM | `docker compose up -d` + Neon DSN + `VULTURE_API_KEYS_ENABLED=true` | See `docs/guides/central_server_deployment.md` (feature 0031) |
| C: Read-only viewer VM | Ops VM | `docker compose -f docker-compose.readonly.yml up -d` | Optional; set `VULTURE_READONLY=true`. See feature 0030 + `docs/guides/neon_deployment.md` |
| D: CI client | GitHub Actions etc. | `vulture scan <git-url> --api-key X --server Y --wait` | See `docs/guides/ci_integration.md` (feature 0031) |
| E: Native install | Single-user laptop, no Docker | `curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh \| sh` | One-shot nuclei-style installer; SQLite + bundled python; see `docs/guides/native_installation.md` (feature 0044) |

Mode A is the default when you clone the repo. No new env vars are required; all centralized features are opt-in.

## Directory Structure

```
vulture/
  backend/               # Go 1.24+ backend
    cmd/vulture/         # Entry point (serve, local_start, status, scan, version)
    internal/
      handler/           # HTTP handlers (audit, source, stream, auth, memory, agent, filesystem, health)
      service/           # Business logic (audit, source, stream, agent_proxy, memory, auth)
      repository/        # Data access (postgres_repo, sqlite_repo, *_memory_repo, user_repo, mocks)
      model/             # Data structures (audit, finding, source, user, agent, event, memory)
      server/            # HTTP server setup, middleware (CORS, logging, auth), request_id
      config/            # Environment configuration loading
      agui/              # SSE encoder & agent-to-agui translator
      embedding/         # Vector embedding client (OpenAI/Ollama compatible)
      localdev/          # Local dev launcher (detect, process management)
    pkg/
      gitutil/           # Git clone utilities
      fileutil/          # File tree walking
    internal/repository/migrations/  # SQL migrations + auto-runner (//go:embed; feature 0040)
    test/e2e/            # Go E2E tests
  agents/                # Python 3.12+
    shared/              # Common library
      shared/
        audit_runner.py  # Combined skill+LLM audit pipeline
        base_agent.py    # Agent factory
        llm/provider.py  # LiteLLM config, model resolution, context window detection
        tools/           # file_scanner, file_reader, file_lister, pattern_matcher, ast_parser, dependency_checker, git_history, memory_client
        transport/       # sse_app (FastAPI factory), event_emitter (SSE events)
        models/          # audit_request, audit_result, finding
      tests/             # Unit + E2E tests
    chaos_engineering/   # Chaos agent (skills: retry, circuit_breaker, timeout, fallback, blast_radius)
    owasp/               # OWASP agent (skills: injection, auth, crypto, misconfig, access_control)
    soc2/                # SOC2 agent (skills: access_logging, encryption, change_mgmt, monitoring, data_retention; clauses: CC6, CC7, CC8)
  frontend/              # React SPA (Vite) + TypeScript
    src/
      pages/             # Dashboard, AuditNew, AuditResults, Memories, Settings, Login, Register
      components/
        layout/          # Layout, Sidebar, Header
        audit/           # SourceInput, FolderBrowser, AuditTypeSelector
        results/         # AgentStream, FindingsTable, ScoreCard, SeveritySummary, TokenSavings, AuditTimeline, SeverityBadge
      hooks/             # useAgentStream, useAudit, useSource, useFindings, useCopyFeedback
      lib/               # api (HTTP client), auth (AuthProvider), types, constants, clipboard, markdown
      i18n/locales/      # en, es, de, fr, ja, pt
    e2e/                 # Playwright E2E tests (22 tests)
  cli/                   # Go CLI binary (scan, login, list, watch)
  docs/
    architecture/        # system_overview, data_flow, agent_protocol, extensibility
    features/            # 001-008 feature docs (each: plan, status, rollback)
    guides/              # cli_usage
  .github/workflows/     # CI/CD (lint, build, test for all components)
  docker-compose.yml     # Full stack orchestration
  Makefile               # Build, test, lint automation
```

## Scan-time exclusion (`.vultureignore` + `.gitignore`)

The file scanner (`agents/shared/shared/tools/file_scanner.py`) skips paths in three layers, in order:

1. Hardcoded `SKIP_DIRS` / `SKIP_FILES` (e.g. `.git`, `node_modules`, `__pycache__`, lock files).
2. `.gitignore` at the source root — read by default, gitignore-syntax via `pathspec`. Disable with `VULTURE_IGNORE_GITIGNORE=true`.
3. `.vultureignore` at the source root — same syntax, always honored when present. Use this to exclude paths that aren't gitignored but shouldn't be audited (test artifacts, vendored data files, recorded fixtures).

The repo ships its own `.vultureignore` covering `.playwright-mcp/`, `docs/cwe_version_*/`, `agents/cwe/cwe_agent/data/cwe_catalog.json`, etc. Add project-specific patterns at the bottom of that file.

## Audit Pipeline (Combined Skill + LLM)

Agents use a two-phase audit pipeline via `run_combined_audit()`:

```
Phase 1 (ALWAYS): Skill-based pattern matching → 100% file coverage, fast, deterministic
Phase 2 (OPTIONAL): LLM analysis → deeper reasoning on file subset that fits context window
                     ↓
              Deduplicate LLM findings against skill findings
                     ↓
              Merged result: all skill findings + new-only LLM findings
```

- **Skills always run first** across the entire codebase using `ThreadPoolExecutor`.
- **LLM runs second** only when `VULTURE_USE_LLM=true`, analyzing the subset of files that fits the model's context window.
- **Deduplication** (`_deduplicate_findings`) matches by normalized title + file_path, so only genuinely new LLM findings are added.
- **Context window sizing** (`get_context_window()`) resolves via: `VULTURE_LLM_CTX_SIZE` env > model lookup in `CONTEXT_WINDOWS` dict > 32K default.
- **Prior findings** from the memory system are passed as context to avoid redundant analysis. Dedup stats are emitted for observability.

## Database

- **PostgreSQL** (production): pgvector extension for embedding similarity search. Schema migrations in `backend/internal/repository/migrations/` (embedded into the binary via `//go:embed`; auto-applied at startup by the in-Go runner — feature 0040).
- **SQLite** (local dev fallback): WAL mode + busy_timeout. Embeddings stored as JSON text. SQLite schema is still managed by the inline `migrate()` function in `sqlite_repo.go` — unifying it with the Postgres migration runner is tracked as a follow-up to feature 0040.
- **Key tables**: `users`, `sources`, `audits`, `findings`, `audit_memories` (with vector column), `memory_edges` (graph relations).

## Development Commands

```bash
make build          # Build all components
make test           # Run all tests (Go + Python + Frontend)
make e2e            # Run E2E test suites
make coverage       # Measure + report test coverage
make complexity     # Report cyclomatic-complexity outliers (target < 10)
make lint           # Lint all components
make docker-up      # Start full stack via docker compose
make docker-down    # Stop all services
```

## Development Workflow (MANDATORY)

Every code change MUST follow this sequence:

1. **Think** — Understand the problem fully before writing any code.
2. **Plan** — Design the approach, identify affected components, consider edge cases.
3. **Write E2E business logic tests FIRST** — Define the expected behavior as E2E tests before any implementation code exists.
4. **Implement** — Write the code to make the E2E tests pass.
5. **Verify** — Run the full E2E business logic test suite to confirm the code satisfies the business logic.
6. **After EVERY code addition or change**, re-run the entire E2E business logic test suite. No code is considered complete until E2E passes.

### CRITICAL INVARIANT: NEVER modify E2E business logic tests to make code pass. The tests define the business contract. If tests fail, fix the implementation code, not the tests.

## Audits

When performing audits (security, code quality, documentation, performance):

1. **Do a SINGLE comprehensive pass and compile ALL issues BEFORE starting any fixes.** Output a numbered list with file paths, line numbers, severity, and category.
2. **Wait for approval** of the full list before making any changes.
3. **After fixes, do exactly ONE re-audit pass** to verify the fixes landed and catch regressions. Do not loop endlessly discovering new issues — if the re-audit surfaces fundamentally new issue classes, stop and escalate.
4. **Never split an audit into iterative discovery + fix cycles.** That pattern compounds rework. Enumerate first, fix once, verify once.

Multi-implementation features (Postgres + SQLite + memory repos) require checking ALL implementations in the enumeration phase, not just one. Audits that only examine the most-frequently-touched backend will miss issues in the others.

## Debugging & Infrastructure

Before implementing fixes to runtime errors or deployment bugs:

1. **Map the full environmental context first.** List all services, Docker networking, proxies/caching layers, database migration state, and relevant environment variables BEFORE attempting any fix.
2. **Ask about infrastructure constraints upfront** rather than discovering them through repeated failures. Examples: hostile caching proxies, Docker network topology, missing migrations, cross-container DNS resolution.
3. **When the user pastes a runtime error, focus on the SPECIFIC error context first.** Do not broadly explore the codebase — ask which command/endpoint/flow triggered the error, then investigate from that starting point.

When a runtime error has multiple possible causes (proxy behavior, container networking, environment-variable propagation), enumerate the topology once at the start. Serial-pivoting through possible causes without an inventory wastes time and obscures interactions between layers.

## Languages & Testing

Post-edit verification commands (run these after modifying files of the corresponding type):

- **Go** (`*.go`): `cd backend && go vet ./...` and `go test ./...` for the affected package
- **Python** (`*.py`): `cd agents/<component> && python -m pytest tests/unit/ -q`
- **TypeScript/React** (`*.ts`, `*.tsx`): `cd frontend && npx tsc --noEmit` and `npx vitest run` for affected test files
- **SQL migrations** (`*.sql`): see `docs/guides/migration_authoring.md` for the full contract (filename grammar, idempotency, FK type-match rule). Migrations are embedded into the Go binary and auto-applied at backend startup. Verify locally with the integration test: `POSTGRES_TEST_DSN=postgres://test:test@localhost:25439/test?sslmode=disable go test -tags=integration ./internal/repository/migrations/`

Do NOT batch multiple file edits before testing — test after each logical change so breakage is caught at the source rather than during a later audit pass.

## Complex Tasks

For complex multi-step tasks (deployment, E2E flows, formal verification, multi-component refactors):

1. **Break work into discrete, verifiable checkpoints.** Each checkpoint must have a clear pass/fail criterion.
2. **Verify each checkpoint works before moving to the next.** Do not attempt to fix everything in one sweep — cascading failures compound quickly.
3. **Scope-lock the session.** If scope naturally expands (e.g., "fix agent wiring" becomes "audit all agent wiring + add conformance tests"), STOP and confirm with the user before expanding. Default to the narrower interpretation.

Sessions that begin as narrow tasks (audit, merge, deploy) commonly expand into broad ones (full conformance test runs, multi-conflict resolution, debugging chains) when checkpoints are skipped. Gate progress at each checkpoint and stop to confirm with the user before broadening scope.

## Planning and documentation

Each new feature must have a unique folder in the format 4digits_feature_name under docs/features/ and each
folder must have a  4digits_implementation_plan.md, 4digits_implementation_status.md and  4digts_rollback_plan.md.

4digts = 0001, 0002 etc and should be incremented 

## Code Quality Rules

These rules are mandatory for all code in this project:

1. **E2E tests first**: E2E business logic tests must be written first, then the code. Code must be verified against the business logic after every change.
2. **NEVER modify E2E business logic tests**: These tests are the source of truth for business requirements. Changing them to make code pass is forbidden.
3. **DRY**: No duplicated logic. Extract shared code into appropriate shared modules.
4. **Low cyclomatic complexity (target < 10)**: Keep functions under ~10 independent code paths where practical — use early returns, strategy pattern, and delegation. `make complexity` reports `gocyclo`/`radon` outliers; it's a monitored target, not a hard gate (a known tail of older functions still exceeds it).
5. **High test coverage (target: comprehensive)**: New code should ship with tests; aim to cover every meaningful path. Coverage is measured and reported in CI, not gated at a fixed percentage.
6. **Performance-conscious**: Minimize allocations and unnecessary copies, use efficient data structures, and profile hot paths. (Vulture is application software, not a safety-certified system — it does not claim ISO 26262 / DO-178C compliance for its own code; those frameworks are *audit targets* the agents check other code against.)

## Coding Conventions

### Go (backend/)
- Use standard library where possible; minimize dependencies (current: `lib/pq`, `x/crypto`, `modernc.org/sqlite`)
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
- **Each agent MUST have a `SKILLS.md`** documenting its precise capabilities, skill definitions, and attributes. This is a core requirement — agents without a SKILLS.md are incomplete.
- FastAPI for HTTP, SSE for streaming
- All agents use `run_combined_audit()` from `shared.audit_runner` — do NOT use the old `if USE_LLM` branch pattern
- Tests: `pytest` with `pytest-cov`, E2E in `tests/e2e/`, unit in `tests/unit/`
- Use `ruff` for linting, `radon` for complexity checks

### Frontend (frontend/)
- React 19 SPA with Vite 7, TypeScript strict mode
- Functional components with hooks
- Native EventSource API for SSE streaming (no ag-ui client library)
- react-i18next for internationalization (en, es, de, fr, ja, pt)
- Tailwind CSS v4 with custom theme (cream bg `#F6F5F0`, blue accent `#2563eb`, green highlight `#22c55e`)
- Auth: JWT token in localStorage, AuthProvider context, protected routes
- Tests: Playwright for E2E (22 tests), Vitest for unit tests
- Use `eslint` + `prettier` for linting/formatting

## Audit Configurability

Each audit type must be configurable:
- **Chaos Engineering**: Configurable by resilience pattern categories (retry, circuit breaker, timeout, fallback, blast radius)
- **OWASP**: Configurable by OWASP Top 10 categories or custom rule sets
- **SOC2**: Configurable down to specific compliance clauses (CC6, CC7, CC8)
- Each agent's `/info` endpoint exposes a `config_schema` (JSON Schema) so the frontend can dynamically render configuration options

## Agent Extensibility

To add a new audit type (e.g., GDPR):
1. Create `agents/gdpr/` from existing agent template (agent.py, skills/, SKILLS.md, main.py, Dockerfile)
2. Add 1 line to Go agent registry in `internal/config/config.go`
3. Add 1 service block to `docker-compose.yml`
4. Frontend auto-discovers via `GET /api/agents` — no frontend changes needed

## Key APIs

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/sources` | Submit local path or git URL |
| POST | `/api/audits` | Start audit (source + types + config) |
| GET | `/api/audits` | List audits |
| GET | `/api/audits/:id` | Get audit status and results |
| GET | `/api/audits/:id/stream` | SSE stream (live or replay) |
| GET | `/api/audits/cache` | Check for cached audit results |
| GET | `/api/agents` | List available agent types |
| GET | `/api/agents/:type/info` | Get agent config schema & skills |
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login and get JWT token |
| GET | `/api/auth/me` | Get current user (requires auth) |
| GET | `/api/auth/local-session` | Passwordless token (local mode) |
| GET | `/api/memories/search` | Semantic search (pgvector) |
| GET | `/api/memories/by-path` | Get findings for a codebase path |
| GET | `/api/memories/:id/edges` | Get related memories (graph) |
| POST | `/api/filesystem/browse` | Browse local filesystem |
| GET | `/health` | Health check |

## Memory System

The memory system provides cross-audit intelligence via pgvector:

1. **Storage**: Each finding → `audit_memories` record with text embedding.
2. **Embeddings**: Generated via OpenAI (`text-embedding-3-small`) or Ollama (`nomic-embed-text`).
3. **Auto-linking**: Cosine similarity search finds related memories → `memory_edges` graph.
4. **Reuse**: Agents receive prior findings as context to avoid redundant analysis and track token savings.
5. **Search**: Frontend exposes semantic search on the Memories page.

## Environment Variables

```
# Go Backend
VULTURE_PORT=8080                                    # Server port
VULTURE_DB_PATH=/data/vulture.db                     # SQLite path (fallback)
VULTURE_DB_DSN=postgres://...                        # PostgreSQL DSN (if set, uses Postgres)
VULTURE_JWT_SECRET=change-me-in-production           # JWT signing key
VULTURE_LOCAL_MODE=true                              # Enable passwordless auth
VULTURE_AGENT_CHAOS_URL=http://agent-chaos:8001      # Agent endpoints
VULTURE_AGENT_OWASP_URL=http://agent-owasp:8002
VULTURE_AGENT_SOC2_URL=http://agent-soc2:8003
VULTURE_AGENT_CWE_URL=http://agent-cwe:8004
VULTURE_EMBEDDING_URL=                               # Custom embedding endpoint
VULTURE_EMBEDDING_MODEL=                             # Embedding model override

# Python Agents (each service)
OPENAI_API_KEY=sk-...                                # LLM API key
OPENAI_BASE_URL=                                     # Custom OpenAI-compatible endpoint (LM Studio, vLLM)
VULTURE_LLM_MODEL=gpt-4o                            # Model: gpt-4o, claude-sonnet, gemini-pro, qwen3:1.7b, etc.
VULTURE_USE_LLM=false                               # Enable LLM phase for most agents (true = skills + LLM, false = skills only). NOTE: the CWE agent runs the LLM phase ON BY DEFAULT, model-gated (does NOT key off this flag)
VULTURE_CWE_DISABLE_LLM=false                        # CWE agent only: escape hatch to force skills-only, overriding the LLM-on-by-default behaviour
VULTURE_LLM_CTX_SIZE=                                # Override context window (tokens); auto-detected from model if unset
VULTURE_LLM_MAX_FILES=10000                          # Cap on files swept by the LLM phase (partial results emitted when hit)
VULTURE_LLM_BUDGET_USD=                              # Optional USD spend cap for the LLM phase; unset / <= 0 = no cap
VULTURE_AGENT_PORT=8001                              # Service port (varies per agent)
VULTURE_BACKEND_URL=http://backend:8080              # Backend URL for memory API
OLLAMA_API_BASE=http://localhost:11434               # Ollama endpoint (local models)

# Frontend
VITE_API_URL=http://localhost:8080                   # Backend URL
```

## SSE Event Types

Events emitted during an audit stream:

| Event | Description |
|-------|-------------|
| `agent_start` | Audit begins (run_id) |
| `thinking` | Text messages (progress, context, status) |
| `finding` | Individual finding (severity, title, file, etc.) |
| `progress` | Files analyzed / total / findings count |
| `dedup_stats` | Deduplication metrics (findings_deduped, prior_findings_used) |
| `token_savings` | Token savings from memory context |
| `result` | Final result (all findings, summary, score) |
| `agent_end` | Audit completed |
