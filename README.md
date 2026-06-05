# Vulture

[![CI](https://github.com/bobinson/vulture/actions/workflows/ci.yml/badge.svg)](https://github.com/bobinson/vulture/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](https://go.dev/)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-3776AB.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6.svg)](https://www.typescriptlang.org/)

Vulture is an AI-powered compliance audit platform that inspects source code against multiple security and reliability frameworks. Point it at a Git repository or a local folder; it dispatches specialized agents that flag compliance issues across **Chaos Engineering principles, OWASP Top 10, CWE 4.19.1, SOC2, NIST SSDF, XSS, formal provenance verification, attack-surface discovery, DO-178C (avionics safety), and OWASP ASVS 5.0.0** — ten frameworks today, with the architecture designed for adding more in three steps. The two-phase audit pipeline runs fast deterministic skill-based pattern matching across the entire codebase first, followed by optional LLM-driven deep analysis with automatic deduplication.

## Key Features

- **Multi-framework auditing** -- Ten built-in agents (Chaos, OWASP, SOC2, CWE, SSDF, XSS, Prove, Discover, DO-178C, ASVS) with per-framework configurability down to individual compliance clauses
- **Specialized AI agents** -- Each audit type runs as an independent FastAPI microservice with precisely defined skills, using the OpenAI Agents SDK with support for OpenAI, Claude, and Gemini models via LiteLLM
- **Two-phase audit pipeline** -- Deterministic skill-based pattern matching covers 100% of files first; optional LLM analysis adds deeper reasoning with automatic deduplication against skill findings
- **Real-time SSE streaming** -- Live audit progress, findings, and agent output streamed to the browser as Server-Sent Events
- **Memory system with pgvector** -- Cross-audit intelligence via vector embeddings; prior findings are reused as context to avoid redundant analysis and reduce token usage
- **Extensible architecture** -- Add a new audit type in three steps: create the agent, register it in the Go backend, add a Docker service block. The frontend auto-discovers new agents
- **CLI tool** -- Headless audit execution with `vulture scan`, `vulture watch`, and `vulture list`
- **Multi-language UI** -- React SPA with internationalization support for English, Spanish, German, French, Japanese, and Portuguese

## Architecture

```
                         +-------------------+
                         |   React Frontend  |
                         |  (Vite + Tailwind)|
                         +--------+----------+
                                  |
                            SSE / REST
                                  |
                         +--------v----------+
                         |    Go Backend     |
                         |   (Orchestrator)  |
                         +---+----+----+----++
                             |    |    |    |
                  +----------+    |    |    +----------+
                  |               |    |               |
           +------v-----+ +------v----v-+ +-----v------+
           |Agent: Chaos | |Agent: OWASP | |Agent: SOC2 |  ...
           |  (FastAPI)  | |  (FastAPI)  | |  (FastAPI)  |
           +-------------+ +-------------+ +-------------+
                             |
                    +--------v---------+
                    |   PostgreSQL     |
                    |   + pgvector     |
                    +------------------+
```

The Go backend orchestrates audit requests, dispatches them to Python agent services concurrently, aggregates SSE streams, and serves structured events to the frontend. PostgreSQL with pgvector handles persistence and vector similarity search. SQLite is available as a local development fallback.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- An LLM API key (OpenAI, Anthropic, or Gemini) if using LLM-enhanced analysis

### 1. Configure

Copy and edit the configuration file:

```bash
cp config.ini.example config.ini
```

Edit `config.ini` to set your database password and any other values. At minimum, review:

| Setting | Location | Purpose |
|---------|----------|---------|
| `database.password` | `config.ini` | PostgreSQL password (required) |
| `auth.jwt_secret` | `config.ini` | JWT signing key (auto-generated if blank) |
| `OPENAI_API_KEY` | Environment | Required only if `VULTURE_USE_LLM=true` |

Generate the `.env` file from `config.ini`:

```bash
make gen-env
```

### 2. Launch

```bash
make docker-up
```

This builds all images (Go backend, Python agents, React frontend) and starts the full stack: PostgreSQL, backend, all agent services, and the frontend.

### 3. Access

- **Frontend**: http://localhost:23001
- **Backend API**: http://localhost:28080
- **Health check**: http://localhost:28080/health

### Stop

```bash
make docker-down
```

## Deployment Modes

The same binaries and Docker images serve every deployment mode; mode is selected
by environment variables. The default `make docker-up` starts **Mode A**.

| Mode | Who runs it | Command | Notes |
|------|-------------|---------|-------|
| **A — Dev-local** | Developer laptop | `make docker-up` | SQLite or local Postgres; `VULTURE_LOCAL_MODE=true`; no extra config. **Supported in v0.1.0.** |
| **B — Centralized server** | Ops VM | `docker compose up -d` + Neon DSN + `VULTURE_API_KEYS_ENABLED=true` | See [docs/guides/central_server_deployment.md](docs/guides/central_server_deployment.md). ⚠️ Mode B hardening is tracked in feature 0036 Phase 3 / 0037; review SECURITY.md before exposing publicly. |
| **C — Read-only viewer** | Ops VM | `docker compose -f docker-compose.readonly.yml up -d` | Optional. Set `VULTURE_READONLY=true`. See [docs/guides/neon_deployment.md](docs/guides/neon_deployment.md). |
| **D — CI client** | GitHub Actions etc. | `vulture scan <git-url> --api-key X --server Y --wait` | See [docs/guides/ci_integration.md](docs/guides/ci_integration.md). |
| **E — Native install** | Single-user laptop, no Docker | `curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh \| sh` | One-shot installer in the style of nuclei: per-platform tarball + SQLite, all under `~/.vulture/`. Installs the `vulture` CLI (scan/start/stop/doctor) + the embedded UI. **Current limitation:** agent-based (multi-framework / LLM) scanning currently requires Docker (Mode A or B); a self-contained Python agent runtime is a planned follow-up. See [docs/guides/native_installation.md](docs/guides/native_installation.md). |

## Native install (no Docker)

If you don't want to install Docker, Node, and Python by hand, run:

```bash
curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
```

The installer detects your OS/arch, downloads the matching release tarball
from GitHub, verifies it (cosign + Rekor transparency log, falling back to
SHA-256 if cosign isn't on PATH), extracts under `~/.vulture/`, generates a
unique JWT secret with `/dev/urandom`, and drops a symlink at
`~/.local/bin/vulture` — **no sudo, ever**. After install:

```bash
vulture scan ./some-repo        # nuclei-style one-shot
vulture start                   # daemon + UI on http://127.0.0.1:23000
vulture stop
vulture doctor                  # diagnose install health
vulture uninstall
```

The installed CLI runs `vulture scan` (Go-native checks + skills), `vulture
start`/`stop` (daemon + UI), and `vulture doctor`.

**Current limitation:** agent-based (multi-framework / LLM) scanning currently
requires Docker (Mode A or B). The native install does not yet bundle a Python
agent runtime — that is a planned follow-up (see 0055 Tier B). Note that the
agent pipeline is LLM-driven and still needs a configured endpoint either way.

Full security model (19 invariants — JWT CSPRNG, bind 127.0.0.1, env
scrubbing, audit log, etc.) is documented in
[docs/features/0044_native_installer/0044_implementation_plan.md](docs/features/0044_native_installer/0044_implementation_plan.md).

## Local Development

### Go Backend

```bash
cd backend
go build -o bin/vulture ./cmd/vulture/
go test ./...
```

The backend falls back to SQLite in local mode when `VULTURE_DB_DSN` is not set.

### Python Agents

```bash
cd agents
pip install -e shared/ -e chaos_engineering/ -e owasp/ -e soc2/ -e cwe/ -e prove/ -e xss/ -e ssdf/ -e discover/ -e do178c/ -e asvs/

# Run unit tests for individual agents (one example each)
cd shared && python -m pytest tests/unit/ -v
cd chaos_engineering && python -m pytest tests/unit/ -v
cd owasp && python -m pytest tests/unit/ -v
cd soc2 && python -m pytest tests/unit/ -v
cd cwe && python -m pytest tests/unit/ -v
```

> **Note:** Vulture requires Python 3.12+ (declared in `.python-version`).
> If `pip install -e` fails on Python 3.11 or earlier, install Python 3.12 via
> `pyenv` or your distribution's package manager first.

Each agent is a standalone FastAPI service. Start one individually:

```bash
cd agents/owasp
VULTURE_AGENT_PORT=28002 python -m uvicorn main:app --port 28002
```

### React Frontend

```bash
cd frontend
npm ci
npm run dev    # Development server with hot reload
npm test       # Vitest unit tests
npx playwright test  # E2E tests
```

### Make Targets

```bash
make build          # Build all components
make test           # Run all unit tests (Go + Python + Frontend)
make e2e            # Run all E2E test suites
make coverage       # Verify test coverage
make complexity     # Verify cyclomatic complexity thresholds
make lint           # Lint all components (golangci-lint, ruff, eslint)
make docker-up      # Start full stack via docker compose
make docker-down    # Stop all services
```

## Configuration

### Environment Variables

#### Go Backend

| Variable | Default | Description |
|----------|---------|-------------|
| `VULTURE_PORT` | `28080` | Backend server port |
| `VULTURE_DB_DSN` | -- | PostgreSQL connection string (uses SQLite if unset) |
| `VULTURE_DB_PATH` | `/data/vulture.db` | SQLite database path (fallback) |
| `VULTURE_JWT_SECRET` | -- | JWT signing key (required in production) |
| `VULTURE_LOCAL_MODE` | `false` | Enable passwordless authentication (set `true` for development) |
| `VULTURE_AGENT_CHAOS_URL` | `http://agent-chaos:28001` | Chaos agent endpoint |
| `VULTURE_AGENT_OWASP_URL` | `http://agent-owasp:28002` | OWASP agent endpoint |
| `VULTURE_AGENT_SOC2_URL` | `http://agent-soc2:28003` | SOC2 agent endpoint |
| `VULTURE_AGENT_CWE_URL` | `http://agent-cwe:28004` | CWE agent endpoint |
| `VULTURE_AGENT_PROVE_URL` | `http://agent-prove:28005` | Prove agent endpoint |
| `VULTURE_AGENT_XSS_URL` | `http://agent-xss:28006` | XSS agent endpoint |
| `VULTURE_AGENT_SSDF_URL` | `http://agent-ssdf:28007` | SSDF agent endpoint |
| `VULTURE_AGENT_DISCOVER_URL` | `http://agent-discover:28008` | Discover agent endpoint |
| `VULTURE_AGENT_DO178C_URL` | `http://agent-do178c:28009` | DO-178C agent endpoint |
| `VULTURE_AGENT_ASVS_URL` | `http://agent-asvs:28010` | ASVS agent endpoint |
| `VULTURE_EMBEDDING_URL` | -- | Custom embedding endpoint |
| `VULTURE_EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model |

#### Python Agents

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | -- | LLM API key |
| `OPENAI_BASE_URL` | -- | Custom OpenAI-compatible endpoint (LM Studio, vLLM, Ollama) |
| `ANTHROPIC_API_KEY` | -- | Anthropic API key (for Claude models) |
| `GEMINI_API_KEY` | -- | Google Gemini API key |
| `VULTURE_LLM_MODEL` | `gpt-4o` | Model identifier (gpt-4o, claude-sonnet, gemini-pro, etc.) |
| `VULTURE_USE_LLM` | `false` | Enable LLM analysis phase (`true` = skills + LLM, `false` = skills only) |
| `VULTURE_LLM_CTX_SIZE` | -- | Override context window size in tokens (auto-detected if unset) |
| `VULTURE_AGENT_PORT` | varies | Agent service port |
| `VULTURE_BACKEND_URL` | `http://backend:28080` | Backend URL for memory API callbacks |
| `OLLAMA_API_BASE` | `http://localhost:11434` | Ollama endpoint for local models |

#### Frontend

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_URL` | `http://localhost:28080` | Backend API URL |

### Configuration File

Vulture uses a `config.ini` file at the project root as the single source of truth for ports, database settings, and service defaults. Run `make gen-env` to generate the `.env` file consumed by `docker compose`.

## Adding New Audit Types

Vulture is designed for easy extensibility. To add a new audit type (for example, GDPR):

1. **Create the agent** -- Copy an existing agent directory (e.g., `agents/owasp/`) to `agents/gdpr/`. Implement skills in the `skills/` subdirectory, define the agent in `agent.py`, document capabilities in `SKILLS.md`, and create a `Dockerfile`.

2. **Register in the Go backend** -- Add one line to the agent registry in `backend/internal/config/config.go`:
   ```go
   "gdpr": {URL: getEnv("VULTURE_AGENT_GDPR_URL", "http://agent-gdpr:28009")},
   ```

3. **Add to docker-compose** -- Add a service block to `docker-compose.yml` following the pattern of existing agents.

The frontend auto-discovers available agents via `GET /api/agents` and dynamically renders configuration options from each agent's `/info` endpoint -- no frontend changes are needed.

## API Overview

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/sources` | Submit a local path or git URL for auditing |
| `POST` | `/api/audits` | Start an audit (source + types + configuration) |
| `GET` | `/api/audits` | List all audits |
| `GET` | `/api/audits/:id` | Get audit status and results |
| `GET` | `/api/audits/:id/stream` | SSE stream for live or replayed audit events |
| `GET` | `/api/audits/cache` | Check for cached audit results |
| `GET` | `/api/agents` | List available agent types |
| `GET` | `/api/agents/:type/info` | Get agent configuration schema and skills |
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Authenticate and receive a JWT token |
| `GET` | `/api/auth/me` | Get current user (requires authentication) |
| `GET` | `/api/auth/local-session` | Passwordless token for local mode |
| `GET` | `/api/memories/search` | Semantic search across audit findings (pgvector) |
| `GET` | `/api/memories/by-path` | Get findings for a specific codebase path |
| `GET` | `/api/memories/:id/edges` | Get related memories via graph edges |
| `POST` | `/api/filesystem/browse` | Browse local filesystem directories |
| `GET` | `/health` | Health check |

### SSE Event Types

During an audit stream, the following event types are emitted:

| Event | Description |
|-------|-------------|
| `agent_start` | Audit begins with a run ID |
| `thinking` | Progress and status messages |
| `finding` | Individual finding with severity, title, file, and details |
| `progress` | Files analyzed, total count, findings count |
| `dedup_stats` | Deduplication metrics |
| `token_savings` | Token savings from memory context reuse |
| `result` | Final aggregated result with all findings, summary, and score |
| `agent_end` | Audit completed |

## CLI

The Vulture CLI provides headless audit execution:

```bash
vulture scan --source /path/to/code --type owasp,cwe
vulture list
vulture watch <audit-id>
```

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on development workflow, coding standards, and pull request requirements.

## Attributions

Vulture redistributes the following third-party content. Full notices are in
[NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

- **MITRE CWE™** — Copyright © MITRE Corporation, distributed under the
  [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
- **OWASP ASVS v5.0.0** — Copyright © OWASP Foundation, distributed under
  [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The data
  files under `agents/asvs/asvs_agent/data/` inherit CC BY-SA 4.0; see the
  per-directory [LICENSE.md](agents/asvs/asvs_agent/data/LICENSE.md).
- **NIST SSDF (SP 800-218)** — public domain.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
