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
- **CLI** (`cli/`): Go CLI binary for headless audit execution (`vulture scan`, `vulture status`, `vulture results`).
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
    owasp/               # OWASP Top 10 CATEGORIZER (feature 0063): maps CWE-agent findings onto OWASP categories per edition (2021/2025). No detection; CWE agent is its prerequisite. See owasp_agent/skills/SKILLS.md
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

The repo ships its own `.vultureignore` covering `.playwright-mcp/`, `docs/cwe_version_*/`, `agents/cwe/cwe_agent/data/cwe_catalog.json`, etc. Add project-specific patterns at the bottom of that file. Note `.vultureignore` is read from the **scanned** root, so this repo's copy has no effect when auditing some other project.

Above those three layers sits an **extension allowlist**: a file is only scanned if its extension is in the scan set. That set is `CODE_EXTENSIONS` (narrow, source-only) ∪ `WHITELIST_EXTENSIONS` (templates, docs, `.sql`/`.tf`/`.hcl`, config dialects) ∪ `VULTURE_EXTRA_EXTENSIONS`, plus canonical extensionless files (`Dockerfile`, `Makefile`, `.npmrc`, …) via `WELL_KNOWN_FILENAMES`. Two things to know:

- **Backup markers are not entries.** `effective_suffix()` resolves `notes.md.bak` to `.md`, so whitelisting a type covers its shadow copies. Adding `.bak` would be meaningless. Exposure of a backup is reported separately by `scan_backup_files()`, which walks filenames and ignores the extension set entirely.
- **Some skills pass their own narrower set** (`configuration_check`, `buffer_check`, `memory_safety_check`, `secret_scan`, `dependency_check`) and do not widen with the whitelist. When a file looks unscanned, check the owning skill's set, not just the global one — `.html` is reached by `dependency_check` but not by `injection_check` unless the whitelist is on.

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
make complexity     # Report cyclomatic-complexity outliers (target < 5)
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

Every feature is tracked by a unique 4-digit number; branches and PRs reference it
(e.g. feature/0071_name). Planning follows the workflow described in CLAUDE.local.md.
Do not add feature or planning documents to this repository.

## Code Quality Rules

These rules are mandatory for all code in this project:

1. **E2E tests first**: E2E business logic tests must be written first, then the code. Code must be verified against the business logic after every change.
2. **NEVER modify E2E business logic tests**: These tests are the source of truth for business requirements. Changing them to make code pass is forbidden.
3. **DRY**: No duplicated logic. Extract shared code into appropriate shared modules.
4. **Low cyclomatic complexity (target < 5)**: Keep functions under ~5 independent code paths where practical — use early returns, strategy pattern, and delegation. `make complexity` reports `gocyclo`/`radon` outliers; it's a monitored target, not a hard gate (a known tail of older functions still exceeds it).
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
- **OWASP**: A categorizer over CWE findings (feature 0063), not a detector. Configurable by `edition` (`2025` default, `2021`) and by `categories` (OWASP ids to include). Runs as a deferred phase after the scan agents; the CWE agent is its prerequisite and is auto-injected when OWASP is selected. Emits a per-category coverage manifest on the `result` event (`owasp_coverage`). Adding a future edition = a new file under `agents/shared/shared/owasp/editions/` + one registry line. OWASP↔CWE mapping is data-driven and single-sourced there; the 0050 representative map is guarded against divergence by `agents/shared/tests/unit/test_0050_reconciliation.py`. See `docs/guides/owasp_agent.md` for how the agent works and reports the Top 10.
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
VULTURE_AGENT_PROXY_TIMEOUT_SEC=600                  # Backend per-agent whole-audit timeout (default 600s/10m). Raise for slow local models (LM Studio/Ollama) on large trees. MARGIN RULE: must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS + VULTURE_LLM_CALL_TIMEOUT_SEC — NOT merely >= MAX_AUDIT. An agent checks its own deadline only BETWEEN llm calls, so it can overshoot by one full call; if the backend closes first the agent never emits its result snapshot and its findings are rescued from the delta path WITHOUT provenance, validation, snippets or score. Measured: 7500/7200/600 satisfied the old rule and still truncated four agents at exactly 2h5m. The backend warns at startup when the margin is unsafe
VULTURE_AGENT_RESPONSE_HEADER_TIMEOUT_SEC=300        # Backend wait for an agent's HTTP response headers (default 300s)
VULTURE_AGENT_CHAOS_URL=http://agent-chaos:8001      # Agent endpoints
VULTURE_AGENT_OWASP_URL=http://agent-owasp:8002
VULTURE_AGENT_SOC2_URL=http://agent-soc2:8003
VULTURE_AGENT_CWE_URL=http://agent-cwe:8004
VULTURE_EMBEDDING_URL=                               # Custom embedding endpoint
VULTURE_EMBEDDING_MODEL=                             # Embedding model override

# Audit dispatch and event broadcast (feature 0071)
VULTURE_AUDIT_AUTODISPATCH=true                       # POST /api/audits starts the run in the background. Default on. Set false to restore the pre-0071 behavior where a run only starts when an SSE client connects — which is why `vulture scan --wait` (it never opens a stream) used to poll `pending` forever. One-release rollback switch
VULTURE_AUDIT_BROADCAST_HISTORY=8192                  # Per-run replay buffer, in EVENTS not findings. Bounds what a client attaching mid-run can be shown of what it missed; it can never affect persisted findings, because the aggregator reads the live channel, not this buffer. On overflow the oldest events are dropped and the client is sent an explicit truncation notice
VULTURE_AUDIT_BROADCAST_HISTORY_BYTES=67108864        # Byte budget for the same buffer (64MB). Separate because an event COUNT is not a memory bound: one result snapshot can approach the 16MB agent frame ceiling, so 8192 frames alone would permit ~176MB per audit, times every concurrent run. Whichever cap binds first evicts
VULTURE_AUDIT_BROADCAST_TTL_SEC=60                    # How long a FINISHED run stays attachable. Within the window a client gets the run's real event stream; after it, the synthesized replay, which cannot reconstruct agent thinking text or per-finding deltas (they are not persisted). Raise it if viewers routinely open results well after completion

# Security hardening (feature 0065) — opt-in; defaults preserve current behavior
VULTURE_TRUSTED_PROXIES=                             # Comma CIDR/IP list of proxies allowed to set X-Forwarded-For. Unset = trust the direct peer only. MUST be set to the proxy address when behind a reverse proxy, else every client collapses to the proxy IP and shares one rate-limit / login-throttle bucket
VULTURE_LOGIN_LOCKOUT_MAX=5                          # Failed logins per (email,IP) before the escalating (capped) delay engages; a hard ceiling at 2x returns 429. Non-positive value falls back to 5
VULTURE_LOGIN_LOCKOUT_WINDOW_SEC=900                 # Sliding window (seconds) for the login throttle (default 900 = 15 min). Non-positive value falls back to 900
VULTURE_ALLOW_OPEN_REGISTRATION=                     # Allow public POST /api/auth/register. Default: true when VULTURE_LOCAL_MODE is set, false otherwise. When false, provision users via admin-only POST /api/admin/users
VULTURE_SOURCE_ROOT=                                 # Confines local-path (Type=local) source ingest to this directory (symlinked parents resolved so they cannot escape). In centralized mode (VULTURE_LOCAL_MODE unset) local ingest is REJECTED unless this is set
VULTURE_GIT_HOST_ALLOWLIST=                          # Comma list of git hosts permitted even if they resolve to an internal IP (SSRF guard). Empty = public hosts only; internal targets blocked
VULTURE_GIT_ALLOW_REDIRECTS=false                    # Allow git to follow HTTP redirects during clone. Default off (http.followRedirects=false) blocks redirect-based SSRF; enable only for trusted hosts
VULTURE_GIT_SSH_STRICT=accept-new                    # SSH StrictHostKeyChecking mode for key clones (TOFU on first contact). Requires OpenSSH >= 7.6 (startup probe falls back and warns otherwise)
VULTURE_GIT_SSH_KNOWN_HOSTS=                         # UserKnownHostsFile path for SSH clones. Default: a per-install path under the data dir
VULTURE_GIT_SSH_INSECURE=false                       # Restore legacy no-host-key-verification for SSH clones (rollback escape hatch; disables MITM protection)
VULTURE_WEBHOOK_HOST_ALLOWLIST=                      # Comma list of internal hosts permitted as webhook targets. Empty = public-only (internal webhook targets blocked)
VULTURE_AGENT_ENV_SCRUB=true                         # Native modes (feature 0073): spawned agents receive a FILTERED copy of the backend env — backend credentials (JWT secret, DB DSN/password, webhook HMAC, broker mint key) and injection vectors (LD_PRELOAD, LD_AUDIT, DYLD_*, PYTHONSTARTUP, PYTHONUSERBASE, PYTHONHOME) are removed. All VULTURE_* CONFIG still reaches agents, as does VULTURE_AGENT_TOKEN; provider keys are kept unless the broker is on. Docker is unaffected (compose enumerates agent env). false = pre-0073 full inheritance
VULTURE_AGENT_ENV_PASSTHROUGH=                       # Comma list of var names exempt from the 0073 filter. Injection vectors are refused even when listed. Neither hatch can be set from config/.env — only the real process environment
VULTURE_ALLOW_INSECURE_LLM=false                     # Allow sending the provider API key over an http:// (non-TLS) LLM endpoint and skip endpoint validation
VULTURE_STRICT_LLM_ENDPOINT=false                    # Hard-fail backend startup on an insecure LLM endpoint instead of the default degrade-with-warning (the key is withheld either way)

# Python Agents (each service)
OPENAI_API_KEY=sk-...                                # LLM API key
OPENAI_BASE_URL=                                     # Custom OpenAI-compatible endpoint (LM Studio, vLLM)
VULTURE_LLM_MODEL=gpt-4o                            # Model: gpt-4o, claude-sonnet, gemini-pro, qwen3:1.7b, etc.
VULTURE_USE_LLM=false                               # Enable LLM phase for ALL agents (true = skills + LLM, false = skills only). Default skills-only; opt-in via VULTURE_USE_LLM=true. The CWE agent keys off this flag like every other agent (when enabled, CWE still applies its graceful model-health gate)
VULTURE_CWE_DISABLE_LLM=false                        # CWE agent only: escape hatch to force CWE skills-only even when VULTURE_USE_LLM=true
VULTURE_CWE_DISABLE_DANGEROUS_FN=false               # CWE agent only: kill switch for the language-aware dangerous_function skill (CWE-676/242); one-release rollback safety (feature 0060)
VULTURE_LLM_CTX_SIZE=                                # Override context window (tokens); auto-detected from model if unset
VULTURE_LLM_MAX_FILES=10000                          # Cap on files swept by the LLM phase (partial results emitted when hit)

# Scan coverage (scanner-wide; apply to every agent)
VULTURE_MAX_FILES=50000                              # Cap on files enumerated per scan. Truncation is logged as `scan_truncated` — coverage is PARTIAL when it fires
VULTURE_MAX_FILE_SIZE=524288                         # Per-source-file read cap (512KB). Files above it are skipped
VULTURE_MAX_MANIFEST_SIZE=16777216                   # Read cap for dependency manifests only (16MB). Separate because a lock file's size tracks its dependency count, so the source cap dropped exactly the manifests with the most to report
VULTURE_EXTRA_EXTENSIONS=                            # Comma list of extra extensions to scan, e.g. ".sol,jsonnet,.CUE" (leading dot optional, case-insensitive). Added on top of the built-in whitelist
VULTURE_DISABLE_EXTENSION_WHITELIST=false            # Restore the narrow code-only extension set (drops templates, docs, .sql/.tf, and canonical Dockerfile/.npmrc coverage). Rollback escape hatch
VULTURE_SCAN_MINIFIED=false                          # Scan minified/bundled artefacts (*.min.js, *.bundle.css) as source. Off by default: one bundle produces dozens of line-1 findings for code you don't control
VULTURE_SECRET_SCAN_ENTROPY=                         # Opt-in entropy scanning for the secret skill; without it a bare key blob with no assignment context yields nothing
VULTURE_LLM_BUDGET_USD=                              # Optional USD spend cap for the LLM phase; unset / <= 0 = no cap

# LLM request sizing and safety (feature 0070 P5). The token budget and the
# gateway's limit are different units — a token window cannot bound a request BODY.
VULTURE_LLM_MAX_BODY_BYTES=131072                    # Ceiling on the ENCODED request body (128KB). Deliberately below the ~192KB body that produced a gateway 413 — a cap above the failure can never prevent it. Oversized batches roll into the next request rather than being dropped, so a lower value costs latency, not coverage. <= 0 disables
VULTURE_MAX_SOURCE_CHARS=400000                      # Pre-existing per-batch character budget for inlined source. A CHARACTER cap cannot enforce a byte limit (1 char = 1-4 bytes), which is why the byte ceiling above is separate
VULTURE_LLM_GATEWAY_GUESS_CTX=32000                  # Window ceiling trusted when the resolved context window is a GUESS (family inference or the bare default) AND a custom OPENAI_BASE_URL is set. Behind a gateway only three sources are authoritative: VULTURE_LLM_CTX_SIZE, the broker registry, or an exact model-table match — a gateway may proxy a smaller window than the upstream model advertises. Set VULTURE_LLM_CTX_SIZE to lift it
VULTURE_REQUIRE_LOOP_GUARD=false                     # Refuse the LLM phase outright when the tool-loop guard cannot be attached, instead of degrading. The guard raises at VULTURE_LOOP_GLOBAL_LIMIT tool calls; without it the only bound on a runaway loop is VULTURE_AGENT_MAX_AUDIT_SECONDS
VULTURE_LLM_MAX_CONSECUTIVE_FAILURES=3               # Abort the batch sweep after N CONSECUTIVE failing batches (a success resets the counter, so one blip never ends the phase). Guards the case where every batch fails for the same structural reason (bad key, dead gateway, 413) and walking the remaining batches only burns wall-clock. The abort is always logged (llm_consecutive_failure_abort) and reported as a partial-results notice — never silent. 0 disables
VULTURE_LLM_MAX_TURNS=12                             # Cap on agent turns per LLM call (passed to Runner.run). Bounds a model that keeps calling tools without ever producing a final answer; complements the tool-call loop guard, which counts calls rather than turns

# What the LLM tier actually SEES (feature 0075). The prompt is the input to every
# LLM-citing agent — cwe, asvs, do178c, chaos, soc2, ssdf, xss, owasp all reach the
# model through the same two prompt paths, so these apply to all eight at once.
VULTURE_LLM_TIER3=false                              # Feature 0059 cost guard, and the LARGEST coverage lever here. Off (default) scopes the sweep to flagged + entry/config files and skips the long tail: measured on one 7,598-file target, 828 of 2,828 eligible files are rendered. Raise coverage here BEFORE tuning anything below
VULTURE_LLM_LINE_NUMBERS=true                        # Files reach the prompt with absolute line numbers ("30: code") so the model reads a line instead of counting newlines. Measured: raw files mislocated 78% of findings vs 13% for numbered; adjudicated precision 15.7% -> 30.0%. Costs ~5-7 chars/line of budget. false = pre-0075 presentation (snippets stay numbered — that predates the switch)
VULTURE_LLM_SNIPPET_CONTEXT=10                       # Lines of context each side of a finding. The default is byte-identical to pre-0075 output. Widening buys the model the guard that would REFUTE a finding (measured as `guard_present` false positives) and costs budget — fewer files per batch
VULTURE_LLM_WHOLE_FILE_MAX_LINES=0                   # Render files at or below N lines whole instead of windowed; 0 disables. For a small file the elision markers cost nearly what the omitted lines would
VULTURE_LLM_FEED_PROSE=false                         # Send prose/data (.md .txt .csv .rst .adoc) to the prompt. Off on BUDGET grounds — doc text displaces real source inside a fixed ceiling — NOT because prose is clean. Skills still scan it; VULTURE_SECRET_SCAN_PROSE covers the gap
VULTURE_LLM_INELIGIBLE_EXTENSIONS=                   # Extensions removed from the PROMPT only, never from the scanner. SHIPS EMPTY: the evidence for excluding .graphql was confounded with the unnumbered-presentation defect, and re-adjudication found 2 of 11 real. Populate it (e.g. ".graphql,.gql") if you cannot send config dialects to a third-party provider
VULTURE_LLM_FEED_UNIFY=true                          # Both feed paths resolve ONE extension set. false restores the pre-0075 asymmetry (narrow for single-shot, wide for the sweep) — that pair IS the defect, so this is an unblock hatch, not a supported configuration
VULTURE_SECRET_SCAN_PROSE=true                       # CWE agent: scan prose/data files for secrets. The compensating control for VULTURE_LLM_FEED_PROSE=false — without it a credential in a README loses the only tier reading it. Measured live: recovered a real `INBOUND_AUTH_TOKEN` in a README. false re-opens that hole
# NOTE: retries on the audit path are owned by retry_llm_call() (which classifies the error and
# halves oversized bodies first); leaving the client's own retry layer on multiplies attempts and
# re-sends a too-large body unchanged. That single authority is enforced by passing max_retries=0
# (plus its alias num_retries=0) ON THE COMPLETION CALL, via ModelSettings.extra_args from
# provider.litellm_retry_extra_args(). The MODULE attribute litellm.num_retries=0 does NOT do it —
# measured against a stub gateway answering 429, one logical call still made 3 HTTP attempts with
# the module pin applied and 1 with the per-call kwarg (agents/shared/tests/unit/
# test_0070_p5_d1_retry_pin.py stands the stub up and counts). litellm reads max_retries from
# per-call kwargs only; the surviving module read is `litellm.num_retries or DEFAULT_MAX_RETRIES`,
# for which 0 is falsy. The kwarg is gated to LiteLLM-routed models: on the native OpenAI path
# (gpt-4o) and the broker path, extra_args are splatted into openai's create(), which accepts
# neither the kwarg nor **kwargs — the broker's own client already sets max_retries=0.
# SCOPE: this covers the GENERATE path only. The L5 judge builds its own client
# (validate/llm_judge.py) and is NOT covered — it keeps the SDK default of 2 retries.

# Evidence quotation and anchor verification (feature 0076). The LLM tier now has to QUOTE
# the source it accuses, and the quote is checked by whitespace-normalised string search in
# the cited file — no second model call, no network. Every actuator ships INERT: on defaults
# 0076 only LABELS, it cannot move a line, demote a finding, or change a finding count.
# Rollback flip ORDER (never widens egress at any intermediate step): QUOTE_DEMOTE_ABSENT ->
# QUOTE_REANCHOR -> QUOTE_VERIFY=off -> QUOTE_REQUIRED=false -> TRUST_MODEL_SNIPPET=true ->
# COERCE_LINES=false -> JSON_SCAN=false; the Go switch flips independently.
VULTURE_LLM_JSON_SCAN=true                           # Parse a bare (unfenced) JSON array by scanning for balanced arrays instead of the old `\[.*\]` regex. The regex truncates at the first `}]`, so ONE finding whose evidence quote contains `}]` (e.g. `const rows = [{ id: 1 }]`) lost the WHOLE batch — a code-bearing field cannot cross it. The fenced path is tried first and is untouched, so a compliant model is unaffected byte for byte. false restores the regex
VULTURE_LLM_JSON_SALVAGE=true                        # Recover whole rows from an array the model never closed because it hit VULTURE_LLM_MAX_OUTPUT_TOKENS. Without it a response cut mid-array is a total loss of the batch. Never silent — emits `llm_json_salvaged` with the recovered row count. false restores the total loss
VULTURE_LLM_COERCE_LINES=true                        # Coerce `line_start`/`line_end` to int, then clamp `line_end >= line_start >= 0`. A model that answers `"55"` is otherwise dropped in SILENCE by Go's `LineStart int` unmarshal (`agui/finding_parse.go`) — the finding reaches the backend and disappears there, so the loss is invisible from the agent side. false restores the verbatim copy
VULTURE_LLM_TRUST_MODEL_SNIPPET=false                # true readmits a model-AUTHORED `code_snippet` as though it were read from source. Off because that string is the model's paraphrase, not evidence: `code_snippet` is produced only by `_attach_code_snippet` reading the FILE (and, under enforce, at the VERIFIED line). Rollback hatch, not a supported configuration
VULTURE_LLM_TRUST_MODEL_CHECK_ID=false               # true restores a model-authored `check_id` as the dedup identity. Split from TRUST_MODEL_SNIPPET because it is a different risk, not the same one: `_dedup_key` prefers `check_id` over the normalised title, so stripping it RE-KEYS every structured-path row and could collide one onto a skill row and delete it. The strip preserves the value privately and `_dedup_key` falls back to it, so the post-dedup count is invariant — this switch is for the operator who nonetheless sees a dedup regression and needs to reverse exactly this
VULTURE_LLM_QUOTE_REQUIRED=true                      # Both prompt contracts ask for `evidence_quote` and the field whitelist admits it. Without it a volunteered quote is discarded by `_normalize_finding`, and "does this claim exist where it says it does" is undecidable by anything cheaper than a second model call. The quote NEVER egresses in any configuration — it is a private field stripped before SSE, the DB and the L5 prompt. false removes it from both contracts, the schema and the whitelist
VULTURE_LLM_QUOTE_VERIFY=observe                     # `off` / `observe` (default) / `enforce` — a mode string, matching VULTURE_OBLIGATION_MODE. `observe` runs the verifier and records one of exact / reanchored / ambiguous / near_miss / found_elsewhere / absent / unquoted / unreadable / oversize in the `anchor` check's extras inside the persisted `validation` blob, changing nothing else — that is what makes the delta measurable before anything acts on it. `enforce` merely ARMS the two actuators below, each still individually off. `off` skips the verifier entirely
VULTURE_LLM_QUOTE_REANCHOR=false                     # The LINE actuator; requires `enforce`. true rewrites `line_start`/`line_end` when the quote is found elsewhere in the cited file (status `reanchored`), retaining `claimed_line`, and only within QUOTE_MAX_DELTA. Off on ship because moving a CORRECT line to a wrong one is the one way this feature could lose a finding; the Go winner-selection guard VULTURE_DEDUP_PREFER_DETERMINISTIC is its hard prerequisite, because re-anchoring newly creates the dedup collisions that guard arbitrates
VULTURE_LLM_QUOTE_DEMOTE_ABSENT=false                # The ONLY demoting actuator; requires `enforce`. true gives status `absent` weight -1.0 AND puts `anchor` in AUTHORITATIVE_CHECKS. One switch for both halves deliberately: the weight alone drives confidence to 0.0 and puts `high_confidence` out of reach through the ADDITIVE path, with no authoritative check visible in the blob to explain it. No other status ever demotes, and no status ever promotes — a located claim is not a true one, and the best-quoting rows include the false positives
VULTURE_LLM_QUOTE_KEEP_TEXT=false                    # true retains a REDACTED copy of the quote (the same `_redact_snippet` `code_snippet` already gets) in the validation extras, for offline debugging of the verifier. The raw quote never egresses under any setting, so this widens what is PERSISTED, never whether verification works
# 0076 signal floor and candidate selection — eight numeric knobs, all read at call time. An
# unset or unparseable value falls back to the default shown, never to zero.
VULTURE_LLM_QUOTE_MIN_CHARS=24                       # Minimum whitespace-normalised length before a quote is searchable at all; below it the status is `unquoted`, never `absent`. Guards the degenerate quote (`}`, `return;`) that would match hundreds of lines and make every match meaningless. Measured: at this floor (24 chars AND 2 tokens) 82.0% of source positions still admit a qualifying window
VULTURE_LLM_QUOTE_MIN_TOKENS=2                       # The other half of the floor, counted in identifier tokens rather than characters. Separable from MIN_CHARS on purpose — 24 characters of punctuation is not a signal. BOTH halves must pass
VULTURE_LLM_QUOTE_MAX_LINES=3                        # A quote may span at most N consecutive non-blank lines. In-file uniqueness of the matched window rises 85.3% (1 line) -> 89.5% (2) -> 92.5% (3); past that the extra lines cost prompt budget without buying uniqueness
VULTURE_LLM_QUOTE_MAX_LINE_CHARS=400                 # PER-LINE cap. Any single quoted line longer than this yields `unquoted` with reason `line_too_long` — a minified line is not evidence. 400 matches the existing per-line caps in `tools/snippet.py` and the L5 judge, so the three agree
VULTURE_LLM_QUOTE_MAX_CHARS=1200                     # WHOLE-QUOTE cap (3 x MAX_LINE_CHARS). Separate from the per-line cap because three individually legal lines are still an oversized payload. Over it the quote is whole-line truncated and then evaluated, hard-clamped so truncation can never turn a quote into `absent`
VULTURE_LLM_QUOTE_RADIUS=25                          # Lines. When a quote matches in several places, the nearest candidate re-anchors only if it is within RADIUS of the claimed line AND strictly nearer than the runner-up; otherwise `ambiguous`. A LONE candidate re-anchors regardless of RADIUS — this arbitrates BETWEEN candidates, it is not a search bound
VULTURE_LLM_QUOTE_MAX_DELTA=200                      # Absolute ceiling, in lines, on how far re-anchoring may move a finding. A 200+ line correction is likelier a coincidental match than a corrected claim, so beyond it the line is left where the model put it
VULTURE_LLM_QUOTE_NEAR_MISS_MIN=0.6                  # Similarity at or above which a non-matching window is `near_miss` rather than `absent` — the model reformatted rather than invented. ASSERTED, not measured: the one knob here with no corpus behind it, and it exists to keep the single demoting class narrow. Raise it to demote more, lower it to demote less
VULTURE_DEDUP_PREFER_DETERMINISTIC=true              # GO / backend, not an agent switch. On a cross-agent dedup collision a deterministic (skill) row outranks an `llm` row at equal-or-lower severity, replacing 0075's score-only "richer row wins". Hard prerequisite of re-anchoring: moving an LLM row's line CREATES collisions that did not previously exist, and without the guard the LLM row can displace the skill row that found the same thing. Scope is exactly llm-vs-deterministic — det-vs-det, llm-vs-llm and rollup collisions still go to the detail score. false restores 0075 selection
VULTURE_AGENT_MAX_AUDIT_SECONDS=900                  # Feature 0061: whole-audit wall-clock ceiling (skill+generate+L5); backstops disconnect cancellation. Should be <= the backend per-agent timeout VULTURE_AGENT_PROXY_TIMEOUT_SEC (default 600s) so the backend doesn't cut the agent off first; 0 disables (removes the hard guarantee)
VULTURE_LLM_CALL_TIMEOUT_SEC=120                     # Feature 0061: per-LLM-call timeout so a hung model can't starve the between-batch cancel/deadline checks
VULTURE_AUDIT_EXECUTOR_WORKERS=8                     # Feature 0061: dedicated audit-producer thread pool size = per-agent concurrent-audit cap
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
