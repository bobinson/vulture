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
| B: Centralized server | Ops VM | `docker compose up -d` + Neon DSN + `VULTURE_API_KEYS_ENABLED=true` | See `docs/guides/central_server_deployment.md` |
| C: Read-only viewer VM | Ops VM | `docker compose -f docker-compose.readonly.yml up -d` | Optional; set `VULTURE_READONLY=true`. See + `docs/guides/neon_deployment.md` |
| D: CI client | GitHub Actions etc. | `vulture scan <git-url> --api-key X --server Y --wait` | See `docs/guides/ci_integration.md` |
| E: Native install | Single-user laptop, no Docker | `curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh \| sh` | One-shot nuclei-style installer; SQLite + bundled python; see `docs/guides/native_installation.md` |

Mode A is the default when you clone the repo. No new env vars are required; all centralized features are opt-in.

## Directory Structure

```
vulture/
  backend/  # Go 1.24+ backend
    cmd/vulture/  # Entry point (serve, local_start, status, scan, version)
    internal/
      handler/  # HTTP handlers (audit, source, stream, auth, memory, agent, filesystem, health)
      service/  # Business logic (audit, source, stream, agent_proxy, memory, auth)
      repository/  # Data access (postgres_repo, sqlite_repo, *_memory_repo, user_repo, mocks)
      model/  # Data structures (audit, finding, source, user, agent, event, memory)
      server/  # HTTP server setup, middleware (CORS, logging, auth), request_id
      config/  # Environment configuration loading
      agui/  # SSE encoder & agent-to-agui translator
      embedding/  # Vector embedding client (OpenAI/Ollama compatible)
      localdev/  # Local dev launcher (detect, process management)
    pkg/
      gitutil/  # Git clone utilities
      fileutil/  # File tree walking
    internal/repository/migrations/  # SQL migrations + auto-runner (//go:embed; )
    test/e2e/  # Go E2E tests
  agents/  # Python 3.12+
    shared/  # Common library
      shared/
        audit_runner.py  # Combined skill+LLM audit pipeline
        base_agent.py  # Agent factory
        llm/provider.py  # LiteLLM config, model resolution, context window detection
        tools/  # file_scanner, file_reader, file_lister, pattern_matcher, ast_parser, dependency_checker, git_history, memory_client
        transport/  # sse_app (FastAPI factory), event_emitter (SSE events)
        models/  # audit_request, audit_result, finding
      tests/  # Unit + E2E tests
    chaos_engineering/  # Chaos agent (skills: retry, circuit_breaker, timeout, fallback, blast_radius)
    owasp/  # OWASP Top 10 CATEGORIZER: maps CWE-agent findings onto OWASP categories per edition (2021/2025). No detection; CWE agent is its prerequisite. See owasp_agent/skills/SKILLS.md
    soc2/  # SOC2 agent (skills: access_logging, encryption, change_mgmt, monitoring, data_retention; clauses: CC6, CC7, CC8)
  frontend/  # React SPA (Vite) + TypeScript
    src/
      pages/  # Dashboard, AuditNew, AuditResults, Memories, Settings, Login, Register
      components/
        layout/  # Layout, Sidebar, Header
        audit/  # SourceInput, FolderBrowser, AuditTypeSelector
        results/  # AgentStream, FindingsTable, ScoreCard, SeveritySummary, TokenSavings, AuditTimeline, SeverityBadge
      hooks/  # useAgentStream, useAudit, useSource, useFindings, useCopyFeedback
      lib/  # api (HTTP client), auth (AuthProvider), types, constants, clipboard, markdown
      i18n/locales/  # en, es, de, fr, ja, pt
    e2e/  # Playwright E2E tests (22 tests)
  cli/  # Go CLI binary (scan, login, list, watch)
  docs/
    architecture/  # system_overview, data_flow, agent_protocol, extensibility
    features/  # 001-008 feature docs (each: plan, status, rollback)
    guides/  # cli_usage.github/workflows/  # CI/CD (lint, build, test for all components)
  docker-compose.yml  # Full stack orchestration
  Makefile  # Build, test, lint automation
```

## Scan-time exclusion (`.vultureignore` + `.gitignore`)

The file scanner (`agents/shared/shared/tools/file_scanner.py`) skips paths in three layers, in order:

1. Hardcoded `SKIP_DIRS` / `SKIP_FILES` (e.g. `.git`, `node_modules`, `__pycache__`, lock files).
2. `.gitignore` at the source root — read by default, gitignore-syntax via `pathspec`. Disable with `VULTURE_IGNORE_GITIGNORE=true`.
3. `.vultureignore` at the source root — same syntax, always honored when present. Use this to exclude paths that aren't gitignored but shouldn't be audited (test artifacts, vendored data files, recorded fixtures).

The repo ships its own `.vultureignore` covering `.playwright-mcp/`, `docs/cwe_version_*/`, `agents/cwe/cwe_agent/data/cwe_catalog.json`, etc. Add project-specific patterns at the bottom of that file. Note `.vultureignore` is read from the **scanned** root, so this repo's copy has no effect when auditing some other project.

Above those three layers sits an **extension allowlist**: a file is only scanned if its extension is in the scan set. That set is `CODE_EXTENSIONS` (narrow, source-only) ∪ `WHITELIST_EXTENSIONS` (templates, docs, `.sql`/`.tf`/`.hcl`, config dialects) ∪ `VULTURE_EXTRA_EXTENSIONS`, plus canonical extensionless files (`Dockerfile`, `Makefile`, `.npmrc`, …) via `WELL_KNOWN_FILENAMES`. Two things to know:

- **Backup markers are not entries.** `effective_suffix` resolves `notes.md.bak` to `.md`, so whitelisting a type covers its shadow copies. Adding `.bak` would be meaningless. Exposure of a backup is reported separately by `scan_backup_files`, which walks filenames and ignores the extension set entirely.
- **Some skills pass their own narrower set** (`configuration_check`, `buffer_check`, `memory_safety_check`, `secret_scan`, `dependency_check`) and do not widen with the whitelist. When a file looks unscanned, check the owning skill's set, not just the global one — `.html` is reached by `dependency_check` but not by `injection_check` unless the whitelist is on.

## Audit Pipeline (Combined Skill + LLM)

Agents use a two-phase audit pipeline via `run_combined_audit`:

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
- **Context window sizing** (`get_context_window`) resolves via: `VULTURE_LLM_CTX_SIZE` env > model lookup in `CONTEXT_WINDOWS` dict > 32K default.
- **Prior findings** from the memory system are passed as context to avoid redundant analysis. Dedup stats are emitted for observability.

## Database

- **PostgreSQL** (production): pgvector extension for embedding similarity search. Schema migrations in `backend/internal/repository/migrations/` (embedded into the binary via `//go:embed`; auto-applied at startup by the in-Go runner — ).
- **SQLite** (local dev fallback): WAL mode + busy_timeout. Embeddings stored as JSON text. SQLite schema is still managed by the inline `migrate` function in `sqlite_repo.go` — unifying it with the Postgres migration runner is tracked as a follow-up to - **Key tables**: `users`, `sources`, `audits`, `findings`, `audit_memories` (with vector column), `memory_edges` (graph relations).

## Development Commands

```bash
make build  # Build all components
make test  # Run all tests (Go + Python + Frontend)
make e2e  # Run E2E test suites
make coverage  # Measure + report test coverage
make complexity  # Report cyclomatic-complexity outliers (target < 5)
make lint  # Lint all components
make docker-up  # Start full stack via docker compose
make docker-down  # Stop all services
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

- **Go** (`*.go`): `cd backend && go vet./...` and `go test./...` for the affected package
- **Python** (`*.py`): `cd agents/<component> && python -m pytest tests/unit/ -q`
- **TypeScript/React** (`*.ts`, `*.tsx`): `cd frontend && npx tsc --noEmit` and `npx vitest run` for affected test files
- **SQL migrations** (`*.sql`): see `docs/guides/migration_authoring.md` for the full contract (filename grammar, idempotency, FK type-match rule). Migrations are embedded into the Go binary and auto-applied at backend startup. Verify locally with the integration test: `POSTGRES_TEST_DSN=postgres://test:test@localhost:25439/test?sslmode=disable go test -tags=integration./internal/repository/migrations/`

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
6. **NO NEW ENVIRONMENT FLAGS.** Fixing a defect by adding a switch institutionalises it: the honest behaviour becomes opt-in, and every operator
   has to discover the interaction to get it. Correct the behaviour instead, and make the DEFAULT the value that is right — derive it from
   configuration that already exists where two settings must agree, so they cannot drift apart. A flag is justified only for a genuine deployment
   choice or a one-release rollback of a risky change, and the reason belongs in its entry below. If a change cannot ship safely without a new
   switch, that is a signal the change is not understood well enough to ship. Corollary: tuning guidance in this file is a smell — if the right
   value is knowable, encode it in the code instead of asking the reader to set it.
7. **Performance-conscious**: Minimize allocations and unnecessary copies, use efficient data structures, and profile hot paths. (Vulture is application software, not a safety-certified system — it does not claim ISO 26262 / DO-178C compliance for its own code; those frameworks are *audit targets* the agents check other code against.)

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
- All agents use `run_combined_audit` from `shared.audit_runner` — do NOT use the old `if USE_LLM` branch pattern
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
- **OWASP**: A categorizer over CWE findings, not a detector. Configurable by `edition` (`2025` default, `2021`) and by `categories` (OWASP ids to include). Runs as a deferred phase after the scan agents; the CWE agent is its prerequisite and is auto-injected when OWASP is selected. It maps each scan agent's FINISHED `result` snapshot, not the pre-enrichment deltas, so every OWASP row carries its CWE twin's validation verdict and the OWASP report cannot contain a row whose CWE twin was never persisted. Emits a per-category coverage manifest on the `result` event (`owasp_coverage`). Adding a future edition = a new file under `agents/shared/shared/owasp/editions/` + one registry line. OWASP↔CWE mapping is data-driven and single-sourced there; the representative map is guarded against divergence by `agents/shared/tests/unit/test_0050_reconciliation.py`. See `docs/guides/owasp_agent.md` for how the agent works and reports the Top 10.
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
VULTURE_PORT=8080  # Server port
VULTURE_DB_PATH=/data/vulture.db  # SQLite path (fallback)
VULTURE_DB_DSN=postgres://...  # PostgreSQL DSN (if set, uses Postgres)
VULTURE_JWT_SECRET=change-me-in-production  # JWT signing key
VULTURE_LOCAL_MODE=true  # Enable passwordless auth
VULTURE_AGENT_PROXY_TIMEOUT_SEC=600  # Backend per-agent whole-audit timeout. MARGIN RULE: must be >= VULTURE_AGENT_MAX_AUDIT_SECONDS + VULTURE_LLM_CALL_TIMEOUT_SEC, not merely >= MAX_AUDIT — an agent checks its deadline only BETWEEN llm calls, so it can overshoot by one full call and lose its result snapshot. The backend warns at startup when the margin is unsafe
VULTURE_AGENT_RESPONSE_HEADER_TIMEOUT_SEC=300  # Backend wait for an agent's HTTP response headers (default 300s)
VULTURE_AGENT_CHAOS_URL=http://agent-chaos:8001  # Agent endpoints
VULTURE_AGENT_OWASP_URL=http://agent-owasp:8002
VULTURE_AGENT_SOC2_URL=http://agent-soc2:8003
VULTURE_AGENT_CWE_URL=http://agent-cwe:8004
VULTURE_EMBEDDING_URL=  # Custom embedding endpoint
VULTURE_EMBEDDING_MODEL=  # Embedding model override

# Audit dispatch and event broadcast
VULTURE_AUDIT_AUTODISPATCH=true  # POST /api/audits starts the run in the background. Default on; false restores the pre-behaviour where a run only starts when an SSE client connects
VULTURE_AUDIT_CONFIG_MERGE=true  # a `config` key named after an agent goes to that agent; any OTHER key goes to EVERY agent, with the agent's own block winning.
VULTURE_AUDIT_BROADCAST_HISTORY=8192  # Per-run replay buffer, in EVENTS not findings. Bounds what a client attaching mid-run can be shown of what it missed; it can never affect persisted findings, because the aggregator reads the live channel, not this buffer.
VULTURE_AUDIT_BROADCAST_HISTORY_BYTES=67108864  # Byte budget for the same buffer (64MB). Separate because an event COUNT is not a memory bound: one result snapshot can approach the 16MB agent frame ceiling, so 8192 frames alone would permit ~176MB per audit, times every concurrent run.
VULTURE_AUDIT_BROADCAST_TTL_SEC=60  # How long a FINISHED run stays attachable. Within the window a client gets the run's real event stream; after it, the synthesized replay, which cannot reconstruct agent thinking text or per-finding deltas (they are not persisted).

# Fix detection and finding lineage
VULTURE_LINEAGE_FIX_MODE=evidence  # `evidence` (default) or `legacy`. When a scan may mark a lineage row FIXED. Under `evidence` an LLM-tier row closes only when the agent re-reads the file and reports the evidence quote GONE; absence alone closes only a deterministic row. `legacy` restores absence-means-fixed for every tier (one-release rollback)
VULTURE_LINEAGE_KEY=target  # `target` (default) or `path`. What counts as "the same codebase" for lineage: the normalised git remote, else the nearest scan-root marker, else the canonical path. `path` restores pre-P3 source_path partitioning (one-release rollback)
VULTURE_FINDING_IDENTITY=observe  # `observe` (default) / `off` / `enforce`. Whether a finding is stamped with `fingerprint_v2`, the identity keyed on check_id and a root-canonical path so it survives an LLM rephrasing and a mount change. `enforce` also swaps `fingerprint` itself and is irreversible; `off` is the rollback
VULTURE_MEMORY_SYNC=true  # Propagate every lineage status transition onto `audit_memories.remediation_status` (open/in_progress/regression/unconfirmed -> `open`; fixed/resolved -> `resolved`; false_positive and accepted_risk map to themselves).

# Security hardening — opt-in; defaults preserve current behavior
VULTURE_TRUSTED_PROXIES=  # Comma CIDR/IP list of proxies allowed to set X-Forwarded-For. Unset = trust the direct peer only.
VULTURE_LOGIN_LOCKOUT_MAX=5  # Failed logins per (email,IP) before the escalating (capped) delay engages; a hard ceiling at 2x returns 429. Non-positive value falls back to 5
VULTURE_LOGIN_LOCKOUT_WINDOW_SEC=900  # Sliding window (seconds) for the login throttle (default 900 = 15 min). Non-positive value falls back to 900
VULTURE_ALLOW_OPEN_REGISTRATION=  # Allow public POST /api/auth/register. Default: true when VULTURE_LOCAL_MODE is set, false otherwise. When false, provision users via admin-only POST /api/admin/users
VULTURE_SOURCE_ROOT=  # Confines local-path (Type=local) source ingest to this directory (symlinked parents resolved so they cannot escape). In centralized mode (VULTURE_LOCAL_MODE unset) local ingest is REJECTED unless this is set
VULTURE_GIT_HOST_ALLOWLIST=  # Comma list of git hosts permitted even if they resolve to an internal IP (SSRF guard). Empty = public hosts only; internal targets blocked
VULTURE_GIT_ALLOW_REDIRECTS=false  # Allow git to follow HTTP redirects during clone. Default off (http.followRedirects=false) blocks redirect-based SSRF; enable only for trusted hosts
VULTURE_GIT_SSH_STRICT=accept-new  # SSH StrictHostKeyChecking mode for key clones (TOFU on first contact). Requires OpenSSH >= 7.6 (startup probe falls back and warns otherwise)
VULTURE_GIT_SSH_KNOWN_HOSTS=  # UserKnownHostsFile path for SSH clones. Default: a per-install path under the data dir
VULTURE_GIT_SSH_INSECURE=false  # Restore legacy no-host-key-verification for SSH clones (rollback escape hatch; disables MITM protection)
VULTURE_WEBHOOK_HOST_ALLOWLIST=  # Comma list of internal hosts permitted as webhook targets. Empty = public-only (internal webhook targets blocked)
VULTURE_AGENT_ENV_SCRUB=true  # Native modes: spawned agents receive a FILTERED copy of the backend env — backend credentials (JWT secret, DB DSN/password, webhook HMAC, broker mint key) and injection vectors (LD_PRELOAD, LD_AUDIT, DYLD_*, PYTHONSTARTUP, PYTHONUSERBASE, PYTHONHOME) are removed.
VULTURE_AGENT_ENV_PASSTHROUGH=  # Comma list of var names exempt from the filter. Injection vectors are refused even when listed. Neither hatch can be set from config/.env — only the real process environment
VULTURE_ALLOW_INSECURE_LLM=false  # Allow sending the provider API key over an http:// (non-TLS) LLM endpoint and skip endpoint validation
VULTURE_STRICT_LLM_ENDPOINT=false  # Hard-fail backend startup on an insecure LLM endpoint instead of the default degrade-with-warning (the key is withheld either way)

# Python Agents (each service)
OPENAI_API_KEY=sk-...  # LLM API key
OPENAI_BASE_URL=  # Custom OpenAI-compatible endpoint (LM Studio, vLLM)
VULTURE_LLM_MODEL=gpt-4o  # Model: gpt-4o, claude-sonnet, gemini-pro, qwen3:1.7b, etc.
VULTURE_USE_LLM=false  # Enable LLM phase for ALL agents (true = skills + LLM, false = skills only). Default skills-only; opt-in via VULTURE_USE_LLM=true.
VULTURE_CWE_DISABLE_LLM=false  # CWE agent only: escape hatch to force CWE skills-only even when VULTURE_USE_LLM=true
VULTURE_CWE_DISABLE_DANGEROUS_FN=false  # CWE agent only: kill switch for the language-aware dangerous_function skill (CWE-676/242); one-release rollback safety
VULTURE_LLM_CTX_SIZE=  # Override context window (tokens); auto-detected from model if unset
VULTURE_LLM_MAX_FILES=10000  # Cap on files swept by the LLM phase (partial results emitted when hit)

# Scan coverage (scanner-wide; apply to every agent)
VULTURE_MAX_FILES=50000  # Cap on files enumerated per scan. Truncation is logged as `scan_truncated` — coverage is PARTIAL when it fires
VULTURE_MAX_FILE_SIZE=524288  # Per-source-file read cap (512KB). Files above it are skipped
VULTURE_MAX_MANIFEST_SIZE=16777216  # Read cap for dependency manifests only (16MB). Separate because a lock file's size tracks its dependency count, so the source cap dropped exactly the manifests with the most to report
VULTURE_EXTRA_EXTENSIONS=  # Comma list of extra extensions to scan, e.g. ".sol,jsonnet,.CUE" (leading dot optional, case-insensitive). Added on top of the built-in whitelist
VULTURE_DISABLE_EXTENSION_WHITELIST=false  # Restore the narrow code-only extension set (drops templates, docs,.sql/.tf, and canonical Dockerfile/.npmrc coverage). Rollback escape hatch
VULTURE_SCAN_MINIFIED=false  # Scan minified/bundled artefacts (*.min.js, *.bundle.css) as source. Off by default: one bundle produces dozens of line-1 findings for code you don't control
VULTURE_SCAN_EDITOR_CONFIG=true  # the walker yields WELL_KNOWN_AUTORUN_FILES (.vscode/*.json,.idea/*,.claude/*,.devcontainer/*) even though those dirs are in SKIP_DIRS, so the CWE `workspace_autorun` skill can find a task that shells out on folder-open. Everything else in them stays pruned. false prunes them entirely
VULTURE_SECRET_SCAN_ENTROPY=  # Opt-in entropy scanning for the secret skill; without it a bare key blob with no assignment context yields nothing
VULTURE_LLM_BUDGET_USD=  # Optional USD spend cap for the LLM phase; unset / <= 0 = no cap

# LLM request sizing and safety. The token budget and the
# gateway's limit are different units — a token window cannot bound a request BODY.
VULTURE_LLM_MAX_BODY_BYTES=131072  # Ceiling on the ENCODED request body (128KB). Deliberately below the ~192KB body that produced a gateway 413 — a cap above the failure can never prevent it.
VULTURE_MAX_SOURCE_CHARS=400000  # Pre-existing per-batch character budget for inlined source. A CHARACTER cap cannot enforce a byte limit (1 char = 1-4 bytes), which is why the byte ceiling above is separate
VULTURE_LLM_GATEWAY_GUESS_CTX=32000  # Window ceiling trusted when the resolved context window is a GUESS (family inference or the bare default) AND a custom OPENAI_BASE_URL is set.
VULTURE_REQUIRE_LOOP_GUARD=false  # Refuse the LLM phase outright when the tool-loop guard cannot be attached, instead of degrading. The guard raises at VULTURE_LOOP_GLOBAL_LIMIT tool calls; without it the only bound on a runaway loop is VULTURE_AGENT_MAX_AUDIT_SECONDS
VULTURE_LLM_MAX_CONSECUTIVE_FAILURES=3  # Abort the batch sweep after N CONSECUTIVE failing batches (a success resets the counter, so one blip never ends the phase).
VULTURE_LLM_MAX_TURNS=12  # Cap on agent turns per LLM call (passed to Runner.run). Bounds a model that keeps calling tools without ever producing a final answer; complements the tool-call loop guard, which counts calls rather than turns

# What the LLM tier actually SEES. The prompt is the input to every
# LLM-citing agent — cwe, asvs, do178c, chaos, soc2, ssdf, xss, owasp all reach the
# model through the same two prompt paths, so these apply to all eight at once.
VULTURE_LLM_TIER3=false  # cost guard, and the LARGEST coverage lever here. Off (default) scopes the sweep to flagged + entry/config files and skips the long tail: measured on one 7,598-file target, 828 of 2,828 eligible files are rendered.
VULTURE_LLM_LINE_NUMBERS=true  # Files reach the prompt with absolute line numbers ("30: code") so the model reads a line instead of counting newlines. Measured: raw files mislocated 78% of findings vs 13% for numbered; adjudicated precision 15.7% -> 30.0%.
VULTURE_LLM_SNIPPET_CONTEXT=10  # Lines of context each side of a finding. The default is byte-identical to pre-output. Widening buys the model the guard that would REFUTE a finding (measured as `guard_present` false positives) and costs budget — fewer files per batch
VULTURE_LLM_WHOLE_FILE_MAX_LINES=0  # Render files at or below N lines whole instead of windowed; 0 disables. For a small file the elision markers cost nearly what the omitted lines would
VULTURE_LLM_FEED_PROSE=false  # Send prose/data (.md.txt.csv.rst.adoc) to the prompt. Off on BUDGET grounds — doc text displaces real source inside a fixed ceiling — NOT because prose is clean. Skills still scan it; VULTURE_SECRET_SCAN_PROSE covers the gap
VULTURE_LLM_INELIGIBLE_EXTENSIONS=  # Extensions removed from the PROMPT only, never from the scanner. SHIPS EMPTY: the evidence for excluding.graphql was confounded with the unnumbered-presentation defect, and re-adjudication found 2 of 11 real. Populate it (e.g.
VULTURE_LLM_FEED_UNIFY=true  # Both feed paths resolve ONE extension set. false restores the pre-asymmetry (narrow for single-shot, wide for the sweep) — that pair IS the defect, so this is an unblock hatch, not a supported configuration
VULTURE_SECRET_SCAN_PROSE=true  # CWE agent: scan prose/data files for secrets. The compensating control for VULTURE_LLM_FEED_PROSE=false — without it a credential in a README loses the only tier reading it. Measured live: recovered a real `INBOUND_AUTH_TOKEN` in a README.
# NOTE: retries on the audit path are owned by retry_llm_call (which classifies the error and
# halves oversized bodies first); leaving the client's own retry layer on multiplies attempts and
# re-sends a too-large body unchanged. That single authority is enforced by passing max_retries=0
# (plus its alias num_retries=0) ON THE COMPLETION CALL, via ModelSettings.extra_args from
# provider.litellm_retry_extra_args. The MODULE attribute litellm.num_retries=0 does NOT do it —
# measured against a stub gateway answering 429, one logical call still made 3 HTTP attempts with
# the module pin applied and 1 with the per-call kwarg (agents/shared/tests/unit/
# test_0070_p5_d1_retry_pin.py stands the stub up and counts). litellm reads max_retries from
# per-call kwargs only; the surviving module read is `litellm.num_retries or DEFAULT_MAX_RETRIES`,
# for which 0 is falsy. The kwarg is gated to LiteLLM-routed models: on the native OpenAI path
# (gpt-4o) and the broker path, extra_args are splatted into openai's create, which accepts
# neither the kwarg nor **kwargs — the broker's own client already sets max_retries=0.
# SCOPE: this covers the GENERATE path only. The L5 judge builds its own client
# (validate/llm_judge.py) and is NOT covered — it keeps the SDK default of 2 retries.

# Evidence quotation and anchor verification. The LLM tier now has to QUOTE
# the source it accuses, and the quote is checked by whitespace-normalised string search in
# the cited file — no second model call, no network. Every actuator ships INERT: on defaults
# only LABELS, it cannot move a line, demote a finding, or change a finding count.
# Rollback flip ORDER (never widens egress at any intermediate step): QUOTE_DEMOTE_ABSENT ->
# QUOTE_REANCHOR -> QUOTE_VERIFY=off -> QUOTE_REQUIRED=false -> TRUST_MODEL_SNIPPET=true ->
# COERCE_LINES=false -> JSON_SCAN=false; the Go switch flips independently.
VULTURE_LLM_JSON_SCAN=true  # Parse a bare (unfenced) JSON array by scanning for balanced arrays instead of the old `\[.*\]` regex. The regex truncates at the first `}]`, so ONE finding whose evidence quote contains `}]` (e.g.
VULTURE_LLM_JSON_SALVAGE=true  # Recover whole rows from an array the model never closed because it hit VULTURE_LLM_MAX_OUTPUT_TOKENS. Without it a response cut mid-array is a total loss of the batch. Never silent — emits `llm_json_salvaged` with the recovered row count.
VULTURE_LLM_COERCE_LINES=true  # Coerce `line_start`/`line_end` to int and clamp `line_end >= line_start >= 0`. A model answering `"55"` is otherwise dropped in silence by Go's int unmarshal
VULTURE_LLM_TRUST_MODEL_SNIPPET=false  # true readmits a model-AUTHORED `code_snippet` as though it were read from source. Off because that string is the model's paraphrase, not evidence. Rollback hatch, not a supported configuration
VULTURE_LLM_TRUST_MODEL_CHECK_ID=false  # true restores a model-authored `check_id` as the dedup identity. Split from TRUST_MODEL_SNIPPET because stripping it re-keys every structured-path row and could collide one onto a skill row
VULTURE_LLM_QUOTE_REQUIRED=true  # Both prompt contracts ask for `evidence_quote` and the field whitelist admits it; without it a volunteered quote is discarded and anchor verification is undecidable. The quote never egresses in any configuration
VULTURE_LLM_QUOTE_VERIFY=observe  # `off` / `observe` (default) / `enforce`. `observe` records an anchor status (exact/reanchored/ambiguous/near_miss/absent/...) in the validation blob and changes nothing else; `enforce` merely ARMS the two actuators below, each still individually off
VULTURE_LLM_QUOTE_REANCHOR=false  # The LINE actuator; requires `enforce`. true rewrites `line_start`/`line_end` when the quote is found elsewhere in the cited file (status `reanchored`), retaining `claimed_line`, and only within QUOTE_MAX_DELTA.
VULTURE_LLM_QUOTE_DEMOTE_ABSENT=false  # The ONLY demoting actuator; requires `enforce`. true gives status `absent` weight -1.0 AND puts `anchor` in AUTHORITATIVE_CHECKS.
VULTURE_LLM_QUOTE_KEEP_TEXT=false  # true retains a REDACTED copy of the quote (the same `_redact_snippet` `code_snippet` already gets) in the validation extras, for offline debugging of the verifier.
# signal floor and candidate selection — eight numeric knobs, all read at call time. An
# unset or unparseable value falls back to the default shown, never to zero.
VULTURE_LLM_QUOTE_MIN_CHARS=24  # Minimum whitespace-normalised length before a quote is searchable at all; below it the status is `unquoted`, never `absent`. Guards the degenerate quote (`}`, `return;`) that would match hundreds of lines and make every match meaningless.
VULTURE_LLM_QUOTE_MIN_TOKENS=2  # The other half of the floor, counted in identifier tokens rather than characters. Separable from MIN_CHARS on purpose — 24 characters of punctuation is not a signal. BOTH halves must pass
VULTURE_LLM_QUOTE_MAX_LINES=3  # A quote may span at most N consecutive non-blank lines. In-file uniqueness of the matched window rises 85.3% (1 line) -> 89.5% (2) -> 92.5% (3); past that the extra lines cost prompt budget without buying uniqueness
VULTURE_LLM_QUOTE_MAX_LINE_CHARS=400  # PER-LINE cap. Any single quoted line longer than this yields `unquoted` with reason `line_too_long` — a minified line is not evidence. 400 matches the existing per-line caps in `tools/snippet.py` and the L5 judge, so the three agree
VULTURE_LLM_QUOTE_MAX_CHARS=1200  # WHOLE-QUOTE cap (3 x MAX_LINE_CHARS). Separate from the per-line cap because three individually legal lines are still an oversized payload.
VULTURE_LLM_QUOTE_RADIUS=25  # Lines. When a quote matches in several places, the nearest candidate re-anchors only if it is within RADIUS of the claimed line AND strictly nearer than the runner-up; otherwise `ambiguous`.
VULTURE_LLM_QUOTE_MAX_DELTA=200  # Absolute ceiling, in lines, on how far re-anchoring may move a finding. A 200+ line correction is likelier a coincidental match than a corrected claim, so beyond it the line is left where the model put it
VULTURE_LLM_QUOTE_NEAR_MISS_MIN=0.6  # Similarity at or above which a non-matching window is `near_miss` rather than `absent` — the model reformatted rather than invented.
VULTURE_DEDUP_PREFER_DETERMINISTIC=true  # GO / backend, not an agent switch. On a cross-agent dedup collision a deterministic (skill) row outranks an `llm` row at equal-or-lower severity, replacing score-only "richer row wins".
VULTURE_FINDING_PATH_CANON=enforce  # GO/backend. Canonicalises the path inside the cross-agent DEDUP KEY against the source root; the stored `file_path` is never rewritten. Without it the deterministic tier (absolute paths) and the LLM tier (relative) can never collide, so one weakness becomes two findings and two lineage rows. `off` is the rollback

VULTURE_FINDING_WINDOW_PARITY=true  # Records WHY a finding has no code window, as a zero-weight `window` check inside the existing `validation` blob: inherited / rollup_parent / no_code_location / unreadable / no_line / present.
VULTURE_AGENT_MAX_AUDIT_SECONDS=900  # whole-audit wall-clock ceiling (skill+generate+L5); backstops disconnect cancellation. Keep this at or below VULTURE_AGENT_PROXY_TIMEOUT_SEC - VULTURE_LLM_CALL_TIMEOUT_SEC. 0 disables
VULTURE_LLM_CALL_TIMEOUT_SEC=  # per-LLM-call/per-batch timeout so a hung model can't starve the between-batch cancel/deadline checks.
VULTURE_AUDIT_EXECUTOR_WORKERS=8  # dedicated audit-producer thread pool size = per-agent concurrent-audit cap
VULTURE_AGENT_PORT=8001  # Service port (varies per agent)
VULTURE_BACKEND_URL=http://backend:8080  # Backend URL for memory API
OLLAMA_API_BASE=http://localhost:11434  # Ollama endpoint (local models)

# Frontend
VITE_API_URL=http://localhost:8080  # Backend URL
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
