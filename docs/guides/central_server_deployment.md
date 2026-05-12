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

# Create the source directory for per-run git clones
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
EOF
```

Generate the secrets inline:

```bash
sed -i "s/VULTURE_JWT_SECRET=CHANGE_ME/VULTURE_JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/VULTURE_WEBHOOK_SECRET=CHANGE_ME/VULTURE_WEBHOOK_SECRET=$(openssl rand -hex 32)/" .env
```

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

With the server running and TLS configured, create the first admin user and generate an API key for CI:

```bash
# Register the admin user (interactive -- prompts for password)
vulture login --register --email admin@example.com

# Promote the new user to admin role.
# /api/auth/register sets role='member' by default (Postgres CHECK
# constraint on users.role). The /api/api-keys endpoint requires
# role='admin'. Until a "promote first user" CLI command exists, run
# this against the running Postgres container:
docker compose exec postgres psql -U vulture -d vulture -p 25432 \
  -c "UPDATE users SET role='admin' WHERE email='admin@example.com';"

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
