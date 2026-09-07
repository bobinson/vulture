# Vulture CLI Usage Guide

The Vulture CLI provides a terminal-native workflow for running compliance audits without opening the web UI. It connects to the same backend and agents as the frontend.

## Installation

Build the CLI binary from the `cli/` directory:

```bash
cd cli && go build -o vulture .
```

Optionally move it onto your PATH:

```bash
sudo mv cli/vulture /usr/local/bin/vulture
```

## Quick Start

```bash
# Start all services locally (backend, agents, frontend)
vulture localstart

# Scan a local project
vulture scan /path/to/my-project

# Scan a Git repository
vulture scan https://github.com/org/repo.git

# Stop all services
vulture localstop
```

## Commands

### `vulture login`

Authenticate with the Vulture server and store a JWT token.

```bash
vulture login
```

You will be prompted for your email and password interactively. The token is saved to `~/.vulture/token` (mode 0600).

When running against `localhost`, the CLI auto-logs in via the
passwordless `/api/auth/local-session` endpoint (only available when
the backend is started with `VULTURE_LOCAL_MODE=true`). No password
is needed — and no longer hardcoded. If you ever want to log in via
the password form for the seeded admin user, export
`VULTURE_LOCAL_DEV_PASSWORD` before starting the backend and use the
same value at the login prompt; otherwise the backend regenerates a
fresh random password on every start and prints it to its log:
`Seeded local dev user: admin@vulture.local / <hex>`.

### `vulture scan <path-or-url>`

Submit source code for compliance scanning and stream results in real time.

```bash
# Scan a local directory (all audit types)
vulture scan /path/to/project

# Scan specific audit types only
vulture scan /path/to/project --types owasp,soc2

# Scan a Git repository
vulture scan https://github.com/org/repo.git --types chaos

# Force a fresh scan, ignoring cached results
vulture scan /path/to/project --no-cache
```

**Shorthand** -- passing a path directly is equivalent to `vulture scan`:

```bash
vulture /path/to/project
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--types <list>` | Comma-separated audit types: `chaos`, `owasp`, `soc2`, `cwe`, `xss`, `ssdf` | all scan types |
| `--no-cache` | Ignore cached results; re-execute the audit | off |
| `--fresh` | Clean-room scan: also ignore prior-findings memory. Implies `--no-cache` | off |
| `--no-llm` | Skip the LLM generate phase; skills still run. Implies `--no-cache` | off |
| `--llm-tier3` | Include non-flagged, non-entry files in the LLM sweep (full-tree, costlier) | off |
| `--validate-llm` | Enable the L5 LLM judge for this audit | off |
| `--validate-llm-top-n <n>` | Cap findings sent to the judge | server default |
| `--validate-llm-batch-size <n>` | Findings per judge request | server default |

**CI flags** (accepted by `scan`, `discover` and `prove`):

| Flag | Description | Default |
|------|-------------|---------|
| `--server <url>` | Backend base URL; overrides `VULTURE_API_URL` | `http://localhost:28080` |
| `--api-key <key>` | Authenticate with an API key instead of a stored token | - |
| `--wait` | Block until the audit completes | off (returns after dispatch) |
| `--output <path>` | Write the result as JSON to `<path>` | stdout only |
| `--exit-on <sev>` | Exit non-zero if a finding at or above `<sev>` exists | never |
| `--webhook <url>` | POST the result to `<url>` on completion | - |
| `--ref <ref>` | Git ref (branch, tag or SHA) to check out | default branch |
| `--git-credentials <spec>` | Credentials for a private repository | - |

Flags are validated per subcommand. `scan` rejects an unknown flag rather
than ignoring it, and names the subcommand that owns it:

```
$ vulture scan . --staging-url https://staging.example.com
Error: unknown flag for `scan`: --staging-url
  --staging-url and --max-iterations belong to `vulture prove`.
  Plugins are enabled server-side via VULTURE_PLUGINS, not a CLI flag.
```

**What happens:**

1. The CLI submits the source (local path or git URL) to the backend.
2. If a cached audit exists for the same source and types, it shows those results immediately (unless `--no-cache` is set).
3. Otherwise it starts a new audit and opens an SSE stream.
4. Agent progress, findings, and scores are printed in real time with color-coded severity.
5. A summary with scores, severity breakdown, and a link to the web UI is printed at the end.

### `vulture status`

Show the 10 most recent audits in a table.

```bash
vulture status
```

```
AUDIT ID          STATUS     TYPES              FINDINGS  DATE
3fbacb0864ae...   completed  chaos,owasp,soc2   12        2026-02-18 14:30
a1b2c3d4e5f6...   running    owasp              --        2026-02-18 14:25
```

### `vulture results <audit-id>`

Display detailed results for a specific audit, including every finding.

```bash
vulture results 3fbacb0864aefc9587bf72ca4fb9b8a1
```

Output includes:

- Audit status and types
- Scores per agent (e.g. `owasp=72%  chaos=85%`)
- Severity breakdown (critical, high, medium, low, info)
- Each finding with severity, title, file location, category, and recommendation
- Link to the web UI for the full interactive view

### `vulture localstart`

Start all Vulture services locally (backend, Python agents, frontend). This is the recommended way to run Vulture for local development.

```bash
vulture localstart
```

Aliases: `local-start`, `local_start`

The command:

1. Locates the project root (by finding `docker-compose.yml` and `backend/`).
2. Auto-detects Ollama if running, pulls required models, and configures env vars.
3. Starts the backend (which launches agents and frontend as subprocesses).

If the backend binary is not found, you will be prompted to build it:

```bash
cd backend && go build -o vulture ./cmd/vulture/
```

### `vulture localstop`

Stop all locally running Vulture services.

```bash
vulture localstop
```

Aliases: `local-stop`, `local_stop`

Sends SIGTERM to processes on ports 28080 (backend), 28001-28008 (all agents), and 23001 (frontend), with a SIGKILL fallback after 500ms.

### `vulture discover <path-or-url> --target-url <url>`

Run endpoint discovery against a live target. Maps API endpoints, infrastructure configuration, and service dependencies by combining static analysis of the codebase with live probing of the target URL.

```bash
vulture discover /path/to/project --target-url https://staging.example.com
vulture discover --target-url https://staging.example.com
vulture discover /path/to/project --target-url https://staging.example.com --rate-limit 1
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target-url` | URL of the target environment to discover | Required |
| `--rate-limit` | Delay in seconds between HTTP requests | 0 (no limit) |
| `--no-cache` | Skip cached results | Off |

### `vulture prove <path-or-url>`

Run formal verification against a staging environment. Attempts to prove or disprove audit findings with evidence.

```bash
vulture prove /path/to/project --staging-url https://staging.example.com
vulture prove /path/to/project --staging-url https://staging.example.com --max-iterations 5
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--staging-url` | URL of the staging environment to test against | Required |
| `--target-url` | Alias for `--staging-url` | - |
| `--max-iterations` | Maximum prove iterations per finding | 3 |
| `--allow-local` | Allow proving against localhost targets | Off |
| `--rate-limit` | Max requests per second to the staging URL | Unlimited |
| `--no-cache` | Skip cached results | Off |

### `vulture help`

Print usage information.

```bash
vulture help
vulture --help
vulture -h
```

## Environment Variables

Read by the CLI:

| Variable | Description | Default |
|----------|-------------|---------|
| `VULTURE_API_URL` | Backend API base URL | `http://localhost:28080` |
| `VULTURE_FRONTEND_URL` | Frontend URL (used in result links) | `http://localhost:23001` |

Read by the server and agents, set at start time. Prefer the launcher flags in
[Model Selection](#model-selection) — they keep the tiers consistent:

| Variable | Description |
|----------|-------------|
| `VULTURE_LLM_MODEL` | Model for the generate phase |
| `VULTURE_VALIDATE_LLM_MODEL` | Model for the L5 judge; superseded by the launcher unless set via `--validate-model` |
| `VULTURE_USE_LLM` | Enable the LLM generate phase |
| `VULTURE_USE_VALIDATE_LLM` | Enable the L5 judge |
| `OPENAI_BASE_URL` | OpenAI-compatible chat endpoint |
| `VULTURE_EMBEDDING_URL` | Embedding endpoint; falls back to `OPENAI_BASE_URL`, then OpenAI cloud |
| `VULTURE_EMBEDDING_MODEL` | Embedding model |
| `VULTURE_PLUGINS` | Plugin activation: `all`, `none`, or a comma list. Server-side only — there is no CLI flag |

`host.docker.internal` resolves only inside a container. In bare-metal dev mode
use `localhost`; a Docker-only address there fails every call, and a judge whose
calls all fail reports a parse error rather than a connection error.

Example with a remote server:

```bash
export VULTURE_API_URL=https://vulture.example.com
vulture login
vulture scan /path/to/project
```

## Authentication

The CLI stores its JWT token at `~/.vulture/token`. The token is sent as an `Authorization: Bearer` header on every API request.

**Local development**: When the API URL points to `localhost` or `127.0.0.1` and no token exists, the CLI automatically logs in with the default dev account.

**Remote servers**: Run `vulture login` first. You will be prompted for credentials.

## Source Type Detection

The CLI automatically determines whether a source is a Git repository or a local path:

| Input | Detected As |
|-------|-------------|
| `https://github.com/org/repo.git` | Git |
| `http://gitlab.example.com/repo` | Git |
| `/path/to/project` | Local path |
| `./relative/path` | Local path |

Local paths are resolved to absolute paths before submission.

## Audit Types

### Scan Types (used by `vulture scan`)

| Type | Description |
|------|-------------|
| `chaos` | Chaos Engineering resilience patterns (retry, circuit breaker, timeout, fallback, blast radius) |
| `owasp` | OWASP Top 10 security vulnerabilities (injection, auth, crypto, access control, misconfiguration) |
| `soc2` | SOC2 compliance clauses (CC6, CC7, CC8, etc.) |
| `cwe` | CWE (Common Weakness Enumeration) detection across multiple categories |
| `xss` | XSS (Cross-Site Scripting) vulnerability scanning |
| `ssdf` | NIST SSDF v1.1 (Secure Software Development Framework) compliance |

By default all scan types run. Use `--types` to select a subset:

```bash
vulture scan /path/to/project --types owasp
vulture scan /path/to/project --types owasp,soc2,cwe
```

### Additional Commands

| Command | Description |
|---------|-------------|
| `vulture discover` | Endpoint discovery — maps API endpoints and infrastructure configuration |
| `vulture prove` | Formal verification — attempts to prove or disprove findings with evidence |

## Model Selection

Models are chosen when the stack starts, not per scan. These are flags of the
launcher `scripts/vulture.sh`, not of the `vulture` CLI.

```
scripts/vulture.sh dev <provider> [model] [--scan-model M] [--validate-model M]
```

| Flag | Applies to | Default |
|------|------------|---------|
| `<model>` (positional) | every LLM tier | provider default |
| `--scan-model M`, `--generate-model M` | the generate phase | positional model |
| `--validate-model M`, `--judge-model M` | the L5 judge | positional model |

Both `--flag M` and `--flag=M` forms are accepted.

```bash
# one model everywhere
scripts/vulture.sh dev gemini gemini-2.5-flash --pg

# cheap generate, stronger judge
scripts/vulture.sh dev gemini gemini-2.5-flash --validate-model gemini-2.5-pro
```

The positional model applies to **every** tier. Omit the flags unless a tier
needs to differ.

### Precedence

For each tier, the first value that is set wins:

```
--scan-model      >  positional model  >  provider default        (generate)
--validate-model  >  positional model  >  VULTURE_LLM_MODEL        (judge)
```

A `VULTURE_VALIDATE_LLM_MODEL` inherited from the environment or `.env` is
**superseded** by the launcher and the substitution is reported:

```
Note: VULTURE_VALIDATE_LLM_MODEL=qwen/qwen3.8-27b from the environment
      is superseded by gemini-2.5-flash (pass --validate-model to choose one explicitly)
```

This is deliberate. A stale value silently winning is how a run ends up scanning
with one provider while the judge requests a model the broker cannot serve —
every judge batch then fails, and because a failed call returns no text the
symptom is a parse error, not a configuration error. Pass `--validate-model` to
make the choice explicit; the launcher then honours it.

### Broker caveat

With the LLM broker on (the default), the broker fronts a single provider. A
`--validate-model` naming a model that provider cannot serve is accepted, but
warned about, and every judge batch will fail:

```
Warning: --validate-model X differs from the scan model Y while the broker is
         on. The broker fronts one provider — if it cannot serve X, every judge
         batch will fail.
```

Use `--no-broker` to reach two providers independently.

### Provider model-id conventions

The launcher applies the provider's own convention to whichever model you pass,
so all three options accept a bare id:

| Provider | Bare id | Sent as |
|----------|---------|---------|
| `gemini` | `gemini-2.5-flash` | `litellm/gemini/gemini-2.5-flash` |
| `lmstudio` | `qwen/qwen3.8-27b` | `openai/qwen/qwen3.8-27b` |
| `openai`, `anthropic`, `ollama` | as given | as given |

Under the broker the routing prefix is stripped again — the broker's native
adapters take a bare id.

### Embeddings

Embeddings are configured separately from chat, so a run can use a cloud chat
model with local embeddings:

| Flag | Variable |
|------|----------|
| `--embed-url URL` | `VULTURE_EMBEDDING_URL` |
| `--embed-model NAME` | `VULTURE_EMBEDDING_MODEL` |

An empty `VULTURE_EMBEDDING_URL` falls back to `OPENAI_BASE_URL`, then to the
OpenAI cloud endpoint. Leaving it empty while `OPENAI_API_KEY` holds a local
placeholder sends that placeholder to OpenAI and every embedding returns 401.

Changing the embedding model changes the vector width (`text-embedding-3-small`
is 1536, `nomic-embed-text-v1.5` is 768). The column is untyped, so both store,
but vectors of different widths are not comparable — similarity search silently
degrades across the boundary.

## Using Local Models

Vulture supports any OpenAI-compatible local inference server, including Ollama and LM Studio.

### Ollama

When running via `vulture localstart`, Ollama is auto-detected. If found, the launcher pulls `qwen3:1.7b` (LLM) and `nomic-embed-text` (embeddings) and configures all services automatically.

For Docker-based deployments, set the Ollama env vars explicitly:

```bash
VULTURE_LLM_MODEL=qwen3:1.7b \
VULTURE_USE_LLM=true \
OLLAMA_API_BASE=http://host.docker.internal:11434 \
VULTURE_EMBEDDING_URL=http://host.docker.internal:11434/v1 \
VULTURE_EMBEDDING_MODEL=nomic-embed-text \
docker compose up
```

### LM Studio

LM Studio exposes an OpenAI-compatible API on port 1234 by default. Point the agents and backend at it using `OPENAI_BASE_URL` and `VULTURE_EMBEDDING_URL`.

**Local development (without Docker):**

```bash
export OPENAI_API_KEY=lm-studio            # dummy value, LM Studio doesn't validate
export OPENAI_BASE_URL=http://localhost:1234/v1
export VULTURE_LLM_MODEL=<model-name>      # model loaded in LM Studio
export VULTURE_USE_LLM=true
export VULTURE_EMBEDDING_URL=http://localhost:1234/v1
export VULTURE_EMBEDDING_MODEL=<embedding-model>  # embedding model loaded in LM Studio
vulture localstart
```

Replace `<model-name>` and `<embedding-model>` with the identifiers shown in the LM Studio UI.

**Example with GPT-OSS 20B and Nomic embeddings:**

```bash
export OPENAI_API_KEY=lm-studio
export OPENAI_BASE_URL=http://localhost:1234/v1
export VULTURE_LLM_MODEL=openai/gpt-oss-20b
export VULTURE_USE_LLM=true
export VULTURE_EMBEDDING_URL=http://localhost:1234/v1
export VULTURE_EMBEDDING_MODEL=text-embedding-nomic-embed-text-v1.5
vulture localstart
```

**Docker Compose:**

```bash
OPENAI_API_KEY=lm-studio \
OPENAI_BASE_URL=http://host.docker.internal:1234/v1 \
VULTURE_LLM_MODEL=<model-name> \
VULTURE_USE_LLM=true \
VULTURE_EMBEDDING_URL=http://host.docker.internal:1234/v1 \
VULTURE_EMBEDDING_MODEL=<embedding-model> \
docker compose up
```

### Other OpenAI-Compatible Servers

Any server that implements the OpenAI `/v1/chat/completions` and `/v1/embeddings` endpoints (vLLM, LocalAI, text-generation-inference, etc.) can be used the same way as LM Studio. Set `OPENAI_BASE_URL` to the server's `/v1` URL and `VULTURE_EMBEDDING_URL` to the same.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (connection failure, API error, missing arguments, auth failure) |

## Examples

**Full local workflow:**

```bash
# Build and start everything
cd backend && go build -o vulture ./cmd/vulture/ && cd ..
cd cli && go build -o vulture . && cd ..

cli/vulture localstart

# Run an audit
cli/vulture scan /path/to/my-app --types owasp

# Check recent audits
cli/vulture status

# View detailed results
cli/vulture results 3fbacb0864aefc9587bf72ca4fb9b8a1

# Stop services when done
cli/vulture localstop
```

**CI/CD pipeline:**

```bash
export VULTURE_API_URL=https://vulture.internal.example.com
vulture login
vulture scan . --types owasp,soc2 --no-cache
```
