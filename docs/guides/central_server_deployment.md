# Central Server Deployment Guide (Mode B)

Deploy Vulture as a centralized audit server that CI pipelines, desktop users, and optional read-only viewer VMs can connect to. This is Mode B in the deployment matrix.

```
CI runners (ephemeral)          Central server (persistent VM)         Neon DB (persistent)
  vulture scan --api-key X  -->   backend + 9 agents + LLM     --->    findings, memories
  vulture scan --api-key Y  -->   clones repos, runs audits    <---    lineage, embeddings

Desktop users               -->   same backend (UI or CLI)
```

---

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| VM | 2 vCPU, 4 GB RAM, 50 GB disk | Agent workloads are CPU/memory-intensive |
| Docker + Docker Compose | v24+ / v2.20+ | Compose V2 (`docker compose`, not `docker-compose`) |
| Domain name | e.g. `vulture.example.com` | For TLS termination |
| Neon account | Free or Pro tier | Pro recommended for production (no autosuspend) |
| LLM API key | OpenAI, Anthropic, or local | Needed only if `VULTURE_USE_LLM=true` |

### Cloud VM examples

| Provider | Instance type | vCPU | RAM | Monthly cost (approx.) |
|----------|--------------|------|-----|----------------------|
| AWS | t3.medium | 2 | 4 GB | ~$30 |
| DigitalOcean | Basic Droplet 4GB | 2 | 4 GB | ~$24 |
| Hetzner | CX21 | 2 | 4 GB | ~$5 |

Avoid free-tier instances for agent workloads. The combined memory usage of 9 agents plus the backend requires at least 3 GB available.

---

## Step 1: Provision Neon

Follow the Neon setup instructions in [neon_deployment.md](neon_deployment.md), specifically Section 1 ("Provision Neon"). You need:

1. A Neon project with pgvector, uuid-ossp, and pg_trgm extensions enabled.
2. The **pooled** connection string (the one with `-pooler` in the hostname).

Save the connection string -- you will need it for Step 4.

---

## Step 2: Provision the VM

Provision a VM from your chosen cloud provider. Then install Docker and Docker Compose:

```bash
# Ubuntu 24.04 example
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect. Verify:

```bash
docker compose version
# Docker Compose version v2.x.x
```

---

## Step 3: Install Docker and Docker Compose

If you used a provider image that already has Docker (e.g. DigitalOcean Docker droplet), verify the version and skip to Step 4:

```bash
docker --version    # >= 24.0
docker compose version  # >= 2.20
```

Otherwise, follow the install instructions in Step 2.

---

## Step 4: Clone Vulture and configure environment

```bash
git clone https://github.com/bobinson/vulture.git /opt/vulture
cd /opt/vulture

# Create the host directory for VULTURE_SOURCE_DIR (set below). Compose
# mounts it read-only at /mnt/source in the backend and every agent, for
# local paths to scan, if any. Git clones do not go here: the backend clones
# into its own temp dir.
sudo mkdir -p /var/vulture/sources
sudo chown $USER:$USER /var/vulture/sources
```

Create the `.env` file with all required variables:

```bash
cat > .env <<'EOF'
# Database -- Neon pooled connection string from Step 1
VULTURE_DB_DSN=postgres://USER:PASSWORD@ep-xxx-xxxxxx-pooler.REGION.aws.neon.tech/vulture?sslmode=require

# Auth
VULTURE_JWT_SECRET=CHANGE_ME          # generate with: openssl rand -hex 32
VULTURE_API_KEYS_ENABLED=true

# Webhooks
VULTURE_WEBHOOK_SECRET=CHANGE_ME      # generate with: openssl rand -hex 32

# Source management
VULTURE_SOURCE_DIR=/var/vulture/sources
VULTURE_CLEANUP_RUN_DIRS=true

# LLM (OpenAI example -- adjust for your provider)
OPENAI_API_KEY=sk-...
VULTURE_LLM_MODEL=gpt-4o
VULTURE_USE_LLM=true

# Embeddings
VULTURE_EMBEDDING_MODEL=text-embedding-3-small
VULTURE_EMBEDDING_URL=https://api.openai.com/v1

# Security hardening (feature 0065) -- see "Security hardening variables" below
# REQUIRED behind the Step 7 reverse proxy: set to the address the proxy
# connects from, or all clients collapse to the proxy IP and share one
# rate-limit / login-throttle bucket. Verify against `docker compose logs
# backend` (the logged remote= address) and tighten to the narrowest CIDR.
VULTURE_TRUSTED_PROXIES=172.16.0.0/12
# Server-side local paths (Type=local ingest, the folder browser, and audits
# of stored local sources) are refused in centralized mode unless a
# confinement root is set. Most Mode B servers scan git URLs and don't need
# it. If you do, use a dedicated directory (never the checkout, which holds
# .env, nor the clone temp dir) as VULTURE_SOURCE_DIR above: the backend
# container sees host files only at /mnt/source, its mount, so the root is
# that container path (a host path such as /srv/vulture/allowed-sources
# would refuse every local path). See "Stored local sources" below before
# upgrading a server that already holds local sources:
# VULTURE_SOURCE_ROOT=/mnt/source
# Public self-registration is OFF by default in Mode B; provision users via the
# admin-only POST /api/admin/users (see Step 8 for first-admin bootstrap).
# VULTURE_ALLOW_OPEN_REGISTRATION=false
# Optional egress controls (see "Security hardening variables" below). The git
# list limits clones to the hosts it names, each still on a public address; the
# webhook list exempts internal receivers from the SSRF guard:
# VULTURE_GIT_HOST_ALLOWLIST=github.com
# VULTURE_WEBHOOK_HOST_ALLOWLIST=hooks.internal.example
EOF
```

Generate the secrets inline:

```bash
sed -i "s/VULTURE_JWT_SECRET=CHANGE_ME/VULTURE_JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/VULTURE_WEBHOOK_SECRET=CHANGE_ME/VULTURE_WEBHOOK_SECRET=$(openssl rand -hex 32)/" .env
```

### Security hardening variables (feature 0065)

Not every default here preserves older behavior: some now refuse what an older release allowed, such as local paths in centralized mode without `VULTURE_SOURCE_ROOT`. Three of these controls materially affect a Mode B deployment:

| Variable | Mode B guidance |
|---|---|
| `VULTURE_TRUSTED_PROXIES` | **Set this.** With TLS terminated by the Step 7 reverse proxy, the backend sees the proxy as the client. Unless you list the proxy's source address (CIDR/IP), `X-Forwarded-For` is ignored and per-IP rate limiting **and** the login throttle key on the proxy address — so every client shares one bucket. Tighten to the narrowest range that covers your proxy. |
| `VULTURE_ALLOW_OPEN_REGISTRATION` | Defaults to **false** in Mode B (`VULTURE_LOCAL_MODE` unset), so `POST /api/auth/register` returns 403. Create users with the admin-only `POST /api/admin/users`; see Step 8 for first-admin bootstrap. Set to `true` only if you intend a shared, self-service workspace. |
| `VULTURE_SOURCE_ROOT` | Only needed if you ingest **local paths** (`type=local`) or use the **folder browser** on the server. Centralized mode refuses both unless this confinement root is set: browse answers 403 and ingest 400 `local paths are disabled on this server: …` for every path, before the path is looked at. A read-only (Mode C) server refuses both whatever the root: browse gives a member or admin that same 403, although its advice to set the root cannot help there, and ingest is refused as a write before the path is looked at, with 503 `read-only mode: …` (a viewer gets 403 `write access requires member, admin, or api-key credentials` instead). With a root set, a local path must be absolute, without `..`, at most 4096 bytes, and spelled under the root; an outside symlink that points into the root is refused, so submit the canonical path. Ingest then gives every path that is outside the root, missing, unreadable, unresolvable or linked out of it the same 400 `path not permitted: must be an existing directory inside the source root`; only a path inside the root gets an error that names it (`path does not exist: …`, `path is not a directory: …`). Browse is open to members and admins only (viewers and API keys get 403 `requires member or admin role`), is confined the same way, and gives every outside path the same refusal, so neither reveals anything about the rest of the filesystem. Every audit re-checks its stored local source against the same policy before any agent runs (see "Stored local sources" below). Point the root at a dedicated directory: never the checkout (it holds `.env`), never the clone temp dir, and never one containing automount or network mounts, where a path probe can block. The root is a path as the backend sees it. Under `docker compose` the backend sees host files only through the `VULTURE_SOURCE_DIR` bind mount at `/mnt/source`, so set `VULTURE_SOURCE_ROOT=/mnt/source` and point `VULTURE_SOURCE_DIR` at the dedicated host directory (its default, `./`, is the checkout). A host path such as `/srv/vulture/allowed-sources` fits only a backend that runs on the host; under compose it refuses every local path. Browse also refuses the denylisted system trees (`/var`, `/usr`, `/etc`, …) even inside the root, so do not place the root under them. Git-URL scans (the usual CI flow) don't need it. |

Egress controls (all default to blocking internal/private targets, which is correct for a public-facing server):

- `VULTURE_GIT_HOST_ALLOWLIST` — comma list of the only git hosts a clone may use; empty means any public host. It narrows the SSRF guard and never widens it: a listed host must still resolve to a public address, so the list cannot admit an internal git server. A git host missing from the list is refused with a `400` that names the host and the variable.
- `VULTURE_WEBHOOK_HOST_ALLOWLIST` — comma list of internal hosts to exempt from the SSRF guard, for a trusted internal webhook receiver.
- A git or webhook host that is internal or cannot be resolved is refused with a `400` that carries a fixed message and a `request_id`. For an internal host, the backend log line for that id names the host and the allowlist variable: for a webhook, the variable that would exempt it; for git, that `VULTURE_GIT_HOST_ALLOWLIST` does not exempt it.
- `VULTURE_GIT_ALLOW_REDIRECTS` — off by default (git redirects are blocked to prevent redirect-SSRF); enable only for a trusted host that redirects.
- `VULTURE_GIT_SSH_STRICT` / `VULTURE_GIT_SSH_KNOWN_HOSTS` / `VULTURE_GIT_SSH_INSECURE` — SSH host-key policy for key-based clones (default `accept-new` TOFU; `_INSECURE=true` is a rollback escape hatch that disables MITM protection).
- `VULTURE_ALLOW_INSECURE_LLM` / `VULTURE_STRICT_LLM_ENDPOINT` — govern whether the provider API key may be sent to a non-TLS LLM endpoint. Default: the key is withheld from an `http://` endpoint and the server boots with a warning; set `VULTURE_STRICT_LLM_ENDPOINT=true` to hard-fail startup instead.

The failed-login throttle (per email+IP, escalating capped delay, with a hard-ceiling 429) is always on. Its threshold and window are tunable via `VULTURE_LOGIN_LOCKOUT_MAX` (default 5) and `VULTURE_LOGIN_LOCKOUT_WINDOW_SEC` (default 900 = 15 min); a non-positive value falls back to the default.

### Stored local sources (feature 0102)

Every audit re-checks its stored local source (`sources.type = 'local'`) against the current local-path policy before any agent runs. An audit of a row the policy refuses fails with `source refused by the local-path policy`, and nothing is scanned. Such rows exist when a database created in local mode is served centralized, when the root is narrowed, or when a row was stored through a path spelling an older release accepted (a `..` after a symlink, or an outside symlink into the root). A stored path keeps the spelling of its original request, so these rows can be listed before upgrading and re-ingested under their canonical path.

**When the root itself is unavailable.** The backend opens the root to confine every path, so its user needs read and search permission on the root itself, not only search. A root that is missing or unmounted, is not a directory, or cannot be opened is the server's fault, not the caller's: browse and ingest answer the generic `500` (`internal error` and a `request_id`), never the `path not permitted` refusal a caller's own path gets, and an audit of a stored local source fails with `source root unavailable`. No response names the root. The backend logs `source_root_unavailable` at ERROR with the cause: once at startup, naming `VULTURE_SOURCE_ROOT`, and again on each refused browse or ingest, just before that request's `http_internal_error` line, which carries the `request_id` and reads `source root unavailable`. A refused audit is logged as `local_source_refused`.

**When the root does not answer.** The startup check waits at most 5 seconds for the root. A root on a mount that has stopped answering, such as a hung hard-mounted network share, is logged the same way, with the cause `probe timed out after 5s`, and the backend starts anyway. Browse, ingest and the audit of a stored local source still check the root themselves, with no such bound, so they can wait on that mount.

**With a root set**, this query lists the rows the policy would refuse. Pass the root exactly as configured, with no trailing slash. It uses only `substr`, `length`, `||` and `LIKE`, which both engines provide, and compares the root by length rather than with a `LIKE` prefix, because `_` and `%` in a root path would act as wildcards:

```sql
-- stored_local_rows.sql
-- SQLite (sqlite3 CLI):
--   sqlite3 "$VULTURE_DB_PATH" ".parameter set :root '/srv/vulture/sources'" ".read stored_local_rows.sql"
-- Postgres (psql): replace :root with :'root' and run
--   psql "$VULTURE_DB_DSN" -v root=/srv/vulture/sources -f stored_local_rows.sql
SELECT id, path, created_at
FROM sources
WHERE type = 'local'
  AND (   NOT (path = :root OR substr(path, 1, length(:root) + 1) = :root || '/')
       OR path LIKE '%/../%' OR path LIKE '%/..' OR path NOT LIKE '/%')
ORDER BY created_at;
```

**With no root in centralized mode**, every local row is refused: `SELECT id, path, created_at FROM sources WHERE type = 'local' ORDER BY created_at;`

What the query cannot see:

- It is lexical. A row whose path is under the root with no `..` segment, but runs through an in-root symlink that was planted or swapped to point outside after ingest, passes it. Only the re-check at dispatch, or the dry run below, finds those.
- If the root is itself a symlink, rows stored under its resolved spelling are listed as false positives. Run the query again with the resolved root (`realpath`) and keep the rows that both runs list.

**Recommended dry run before upgrading.** It has two halves, because no one place has both a database client and the backend's view of the paths. List the stored paths where a database client runs, then resolve them as the backend's user where those paths are valid, i.e. inside the backend container for compose paths such as `/mnt/source/…`. The backend image has neither `psql` nor `sqlite3`. With the compose `postgres` service (user, database and port as in Step 8):

```sh
docker compose exec -T postgres psql -U vulture -d vulture -p 25432 -At \
  -c "SELECT path FROM sources WHERE type='local'" |
docker compose exec -T backend sh -c '
R=$(realpath "$VULTURE_SOURCE_ROOT") || exit 1
n=0
while IFS= read -r p; do
  n=$((n+1))
  r=$(realpath "$p" 2>/dev/null) || { printf "UNRESOLVABLE %s\n" "$p"; continue; }
  case "$r/" in "$R"/*) ;; *) printf "OUTSIDE %s -> %s\n" "$p" "$r" ;; esac
done
echo "checked $n local sources"'
```

With a Neon database, run the same query with `psql "<your Neon connection string>" -At -c "…"` on any host that has `psql`, and pipe it into the same `docker compose exec -T backend sh -c '…'`. A backend that runs natively, not in a container, runs the loop on its own host as its own user, fed by `psql "$VULTURE_DB_DSN" -At -c "…"` or, for SQLite, `sqlite3 -noheader "$VULTURE_DB_PATH" "SELECT path FROM sources WHERE type='local'"`.

Read the last line before the rest: `checked 0 local sources` means the loop got no paths (no local rows, or the query failed or never reached it), not that every row passed. The loop stops with an error when `VULTURE_SOURCE_ROOT` is unset or does not resolve in the backend.

It approximates the re-check, which also resolves symlinks, with two differences: `realpath` reports a stored path as `UNRESOLVABLE` when more than its last component is missing, while the re-check judges any missing tail lexically; and the sketch does not handle paths that contain a newline. It passes paths to `realpath` without `--`, because the backend image's `realpath` (BusyBox) reads `--` as a path, which would make every row `UNRESOLVABLE`; a GNU `realpath` reports a stored path that starts with `-` as `UNRESOLVABLE` instead.

---

## Step 5: Start services

```bash
docker compose up -d --build
```

Verify all services are healthy:

```bash
docker compose ps
# All services should show "healthy" or "running"

curl -s http://localhost:28080/health
# {"status":"healthy"}
```

---

## Step 6: Opt out of local Postgres

Since you are using Neon as the database, disable the local Postgres container to avoid wasting resources. Create a `docker-compose.override.yml`:

```yaml
services:
  postgres:
    deploy:
      replicas: 0
  backend:
    depends_on: !reset []
```

Then restart:

```bash
docker compose down
docker compose up -d
```

The backend will connect directly to Neon via the `VULTURE_DB_DSN` in `.env`.

---

## Step 7: TLS termination

The Vulture backend listens on port 28080 (HTTP). You need a reverse proxy to terminate TLS and expose HTTPS on port 443.

### Option A: Caddy (recommended -- automatic HTTPS)

Install Caddy:

```bash
sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt-get update
sudo apt-get install -y caddy
```

Create `/etc/caddy/Caddyfile`:

```
vulture.example.com {
  reverse_proxy localhost:28080 {
    transport http {
      response_header_timeout 5m
    }
  }
}
```

The 5-minute `response_header_timeout` is required for SSE audit streams, which may take several minutes for large codebases.

Start Caddy:

```bash
sudo systemctl enable caddy
sudo systemctl start caddy
```

Caddy automatically obtains and renews Let's Encrypt certificates for the configured domain.

### Option B: nginx

If you prefer nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name vulture.example.com;

    ssl_certificate     /etc/letsencrypt/live/vulture.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vulture.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:28080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE support -- disable buffering and set long timeouts
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

Obtain certificates via certbot or your preferred ACME client.

---

## Step 8: Bootstrap admin user and first API key

With the server running and TLS configured, create the first admin user and generate an API key for CI.

> **Registration is disabled by default in Mode B (feature 0065).** `POST /api/auth/register` returns 403 unless `VULTURE_ALLOW_OPEN_REGISTRATION=true`. To bootstrap the **first** admin, enable registration just long enough to create it, then turn it back off. Every subsequent user is created by an admin via `POST /api/admin/users` — no need to re-enable open registration.

```bash
# 0. Temporarily allow self-registration to create the first user
echo 'VULTURE_ALLOW_OPEN_REGISTRATION=true' >> .env
docker compose up -d backend

# Register the admin user (interactive -- prompts for password)
vulture login --register --email admin@example.com

# Promote the new user to admin role.
# /api/auth/register sets role='member' by default (Postgres CHECK
# constraint on users.role). The /api/api-keys endpoint requires
# role='admin'. Until a "promote first user" CLI command exists, run
# this against the running Postgres container:
docker compose exec postgres psql -U vulture -d vulture -p 25432 \
  -c "UPDATE users SET role='admin' WHERE email='admin@example.com';"

# Disable self-registration again now that the admin exists; add any further
# users via the admin-only POST /api/admin/users endpoint.
sed -i '/VULTURE_ALLOW_OPEN_REGISTRATION=true/d' .env
docker compose up -d backend

# Create an API key for CI (now succeeds because the user is admin)
vulture api-key create ci-github-actions
# Output:
#   API Key created successfully.
#   Key: vk_XXXX...
#   SAVE THIS NOW -- you will not see it again.
#   Name:   ci-github-actions
#   Prefix: vk_XXXX
```

Copy the full key (`vk_...`) and store it in your CI system's secrets. You will never be able to retrieve it again -- only the prefix is stored.

If you use multiple CI systems, create a separate key for each:

```bash
vulture api-key create ci-gitlab
vulture api-key create ci-jenkins
```

---

## Step 9: Configure CI pipelines

Follow [ci_integration.md](ci_integration.md) for per-CI-system setup:

- **GitHub Actions** -- copy the template from `.github/workflow-examples/vulture-audit.yml`
- **GitLab CI** -- `.gitlab-ci.yml` example
- **Jenkins** -- declarative Pipeline example

Each guide covers secrets setup, workflow configuration, and the `vulture scan` flags.

---

## Optional Step 10: Set up a read-only viewer VM

If you want a separate VM for end users to browse audit results (without exposing the central server's agents and LLM keys), deploy a read-only viewer per feature 0030:

```bash
# On a separate VM
git clone https://github.com/bobinson/vulture.git /opt/vulture
cd /opt/vulture

cat > .env <<'EOF'
VULTURE_DB_DSN=postgres://USER:PASSWORD@ep-xxx-xxxxxx-pooler.REGION.aws.neon.tech/vulture?sslmode=require
VULTURE_JWT_SECRET=<same-as-central-server>
VULTURE_READONLY=true
VULTURE_EMBEDDING_URL=https://api.openai.com/v1
VULTURE_EMBEDDING_MODEL=text-embedding-3-small
OPENAI_API_KEY=sk-...
EOF

docker compose -f docker-compose.readonly.yml up -d --build
```

The viewer connects to the same Neon database (read-only) and shares the JWT secret so auth tokens validate on both servers. See [neon_deployment.md](neon_deployment.md) for full details.

---

## Operations

### Viewing logs

```bash
# All services
docker compose logs -f

# Specific services
docker compose logs -f backend
docker compose logs -f agent-cwe agent-owasp

# Search for errors
docker compose logs backend 2>&1 | grep -i error
```

**Tracing an error to its cause (feature 0102).** No `500` and no curated
`400` carries internal detail. An unexpected failure answers `500` with only
`{"error":"internal error","request_id":"<id>"}`. That includes a clone the
server could not run or that stopped with its request: git missing from
`PATH`, the client gone, or the ingest time limit reached. A refusal whose
cause names something of the server's, such as a git or webhook host that
resolves to an internal address, or a `git clone` that git itself fails,
answers `400` with a fixed message and the same `request_id`. The id is also
the `X-Request-ID` response header. A client may send its own id (1-64
characters of `A-Z a-z 0-9 . _ -`); any other value is replaced by a
server-generated one. The cause is logged once under that id
(`http_internal_error` at ERROR for a 500, `http_caller_error` at WARN for a
400), with the operation, method and path. The path and the cause are each
cut to 2048 bytes, and `err_bytes` gives the cause's full length. Grep the
backend log for the id a user reports:

```bash
docker compose logs backend 2>&1 | grep '<request_id>'
```

Some responses carry server detail by design:

- The LLM health message names the LLM endpoint and the probe's error.
  `GET /api/llm/health` reports it, and `POST /api/audits` answers it as a
  `503` when `VULTURE_REQUIRE_LLM=true` and the LLM is unreachable.
- When no agent answers, `GET /api/llm/health` answers `502`
  `could not reach any agent: …`, with an agent's address and its dial error.
- An audit's `degraded_reason` can hold the LLM health message, an agent's
  error text, or the text of a panic that ended the run.
- In local mode with no `VULTURE_SOURCE_ROOT`, a local path that fails for a
  reason the server does not classify is answered `400` `validate path: …`,
  with its cause.

### Updating Vulture

```bash
cd /opt/vulture
git pull
docker compose up -d --build
```

Migrations run automatically at backend startup. Neon schema changes are idempotent (`CREATE ... IF NOT EXISTS`).

### Backup

With Neon, point-in-time recovery (PITR) is handled by the Neon platform. There is nothing local to back up beyond the `.env` file.

Keep a copy of your `.env` in a secure location (password manager, Vault, encrypted backup). Do not commit it to source control.

### Monitoring

The backend exposes health endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Basic liveness check. Returns `{"status":"healthy"}` when the backend is running. |

Set up basic alerting with a cron job:

```bash
# /etc/cron.d/vulture-health
*/5 * * * * root curl -sf https://vulture.example.com/health > /dev/null || \
  echo "Vulture health check failed" | mail -s "ALERT: Vulture down" ops@example.com
```

For more comprehensive monitoring, point Prometheus or your preferred monitoring system at the health endpoint.

### API key rotation

1. Create a new key: `vulture api-key create ci-github-actions-2026q3`
2. Update the `VULTURE_API_KEY` secret in your CI system with the new key value.
3. Verify a CI run succeeds with the new key.
4. Revoke the old key: `vulture api-key revoke <old-key-id>`
5. Confirm revocation: `vulture api-key list` should show the old key as revoked.

Rotate keys every 90 days. Use separate keys per CI system so revocation of one does not affect others.

### Scaling considerations

A single VM (2 vCPU / 4 GB RAM) handles approximately 20-50 audits per day, depending on codebase size, audit types selected, and LLM model performance.

If you exceed this capacity:
- **Vertical scaling:** Increase VM resources (4 vCPU / 8 GB RAM handles ~100 audits/day).
- **Horizontal scaling:** Not yet supported. Adding a job queue and multiple worker VMs is planned as a future feature.

Signs of capacity pressure:
- Audit queue times increasing (audits waiting for agent availability).
- Backend memory usage consistently above 80%.
- SSE stream timeouts during peak hours.
