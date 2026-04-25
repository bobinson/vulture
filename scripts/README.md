# Scripts

## Quick start

```bash
scripts/vulture.sh dev skills        # Fastest: no LLM, no API key
scripts/vulture.sh dev lmstudio      # Local LLM via LM Studio
scripts/vulture.sh stop              # Stop everything
```

## Entry point

All modes go through `scripts/vulture.sh`:

```
scripts/vulture.sh <command> [options]
```

| Command | Mode | Transport | What runs |
|---------|------|-----------|-----------|
| `dev <provider> [model]` | A: Dev-local | Bare metal | Backend + 9 agents + frontend on localhost |
| `server <provider> [model]` | B: Central server | Docker | Same, but containerized + remote DB |
| `viewer` | C: Viewer VM | Docker | Read-only backend + frontend only |
| `build` | — | Bare metal | Go backend + CLI + Python agents + Node frontend |
| `build docker` | — | Docker | Base image + all compose services |
| `stop` | A | Bare metal | Kill processes by port |
| `stop docker [--volumes]` | B/C | Docker | `docker compose down` |

Mode D (CI client) uses the CLI binary directly — no script needed.

## Providers

Used with `dev` and `server` commands:

| Provider | Requires | Default model |
|----------|----------|---------------|
| `skills` | Nothing | (none) — pattern matching only |
| `lmstudio [model]` | LM Studio running on localhost:1234 | Auto-detected from loaded models |
| `ollama [model]` | Ollama running on localhost:11434 | `qwen3:1.7b` |
| `openai [model]` | `OPENAI_API_KEY` in `.env` | `gpt-4o` |
| `anthropic [model]` | `ANTHROPIC_API_KEY` in `.env` | `claude-sonnet` |

## Examples

### Build

```bash
scripts/vulture.sh build              # All components
scripts/vulture.sh build backend      # Go backend only
scripts/vulture.sh build cli          # Go CLI only
scripts/vulture.sh build agents       # Python agents only
scripts/vulture.sh build frontend     # Node frontend only
scripts/vulture.sh build docker       # Docker images
scripts/vulture.sh build docker --up  # Docker images + start
```

### Mode A: Dev-local

```bash
scripts/vulture.sh dev skills
scripts/vulture.sh dev lmstudio
scripts/vulture.sh dev lmstudio "qwen/qwen3.5-35b-a3b"
scripts/vulture.sh dev ollama qwen3:8b
scripts/vulture.sh dev openai
scripts/vulture.sh dev openai gpt-4o
scripts/vulture.sh dev anthropic
```

Runs on bare metal. Backend at `localhost:28080`, frontend at `localhost:23001`. Ports from `config.ini`. Ctrl+C to stop, or `scripts/vulture.sh stop`.

### Mode B: Central server

```bash
scripts/vulture.sh server skills
scripts/vulture.sh server lmstudio
scripts/vulture.sh server openai
```

Requires `.env` or `config.ini` with:
- `VULTURE_DB_DSN` — remote Postgres (e.g. Neon)
- `VULTURE_API_KEYS_ENABLED=true` (for CI access)

See `docs/guides/central_server_deployment.md`.

### Mode C: Viewer VM

```bash
scripts/vulture.sh viewer
```

Requires `.env` with:
- `VULTURE_DB_DSN` — same remote DB as Mode B
- `VULTURE_JWT_SECRET` — same secret as Mode B

Uses `docker-compose.readonly.yml` (backend + frontend only, no agents). All writes return 503.

### Mode D: CI client

```bash
vulture scan https://github.com/org/repo.git \
  --api-key vk_abc123 \
  --server https://vulture.example.com \
  --types cwe,owasp,do178c \
  --wait --exit-on high --output json
```

No server-side script. The CLI binary talks to a Mode B server. Exit code 1 if findings exceed `--exit-on` threshold.

### Stop

```bash
scripts/vulture.sh stop                  # Mode A (bare metal)
scripts/vulture.sh stop docker           # Modes B/C (docker compose down)
scripts/vulture.sh stop docker --volumes # + delete DB data
```

## Individual scripts

| Script | Called by | Purpose |
|--------|-----------|---------|
| `vulture.sh` | User | Unified entry point |
| `start.sh` | `vulture.sh dev` | Bare-metal launcher (`vulture local_start`) |
| `stop.sh` | `vulture.sh stop` | Kills bare-metal processes by port |
| `prod_start.sh` | `vulture.sh server` | Docker compose launcher with LLM config |
| `prod_stop.sh` | `vulture.sh stop docker` | `docker compose down` |
| `build.sh` | `vulture.sh build` | Builds Go + Python + Node locally |
| `build-docker.sh` | `vulture.sh build docker` | Builds Docker images |
| `gen-env.sh` | `prod_start.sh` | Generates `.env` from `config.ini` |

## Config files

| File | Purpose | Required by |
|------|---------|-------------|
| `config.ini` | Ports, DB, LLM, embedding settings | All modes |
| `.env` | Generated from `config.ini`; Docker Compose reads it | Modes B/C |
| `docker-compose.yml` | Full stack (Postgres + backend + 9 agents + frontend) | Mode B |
| `docker-compose.readonly.yml` | Viewer (backend + frontend, no agents, no Postgres) | Mode C |
