# Neon + Split Deployment Guide

Deploy Vulture with:

- **Neon Postgres** hosting the DB remotely (pgvector enabled).
- **Desktop / server** running the backend + 9 scan agents + LLM. This is the **writer** — it has access to your source code, runs audits, and publishes findings to Neon.
- **Small VM** running a read-only backend + frontend. This is the **viewer** — end users hit this for the UI, which reads audit results from Neon.

```
                    ┌────────────────────┐
                    │   Neon Postgres    │
                    │   (pgvector)       │
                    └──▲──────────▲──────┘
            WRITE+READ │          │ READ only
        ┌──────────────┘          └──────────────┐
        │                                        │
┌───────┴────────────┐              ┌────────────┴───────┐
│ DESKTOP / SERVER   │              │ SMALL VM           │
│ ─────────────────  │              │ ────────────────── │
│ backend (writer)   │              │ backend (readonly) │
│ + 9 agents         │              │ + nginx + SPA      │
│ + LM Studio / GPU  │              │ public URL         │
│ source code access │              │ end users          │
└────────────────────┘              └────────────────────┘
```

Both backends share the same JWT secret so auth tokens validate everywhere.

---

## 1. Provision Neon

1. Sign up at <https://neon.tech>.
2. Create a project. Pick a region close to your desktop (writes dominate, and writes come from the desktop).
3. Enable pgvector. In the Neon SQL editor:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
   CREATE EXTENSION IF NOT EXISTS pg_trgm;
   ```
4. Copy the **pooled** connection string. It looks like:
   ```
   postgres://USER:PASSWORD@ep-xxx-xxxxxx-pooler.REGION.aws.neon.tech/vulture?sslmode=require
   ```
   The `-pooler` suffix routes through Neon's PgBouncer — recommended for the many short-lived connections Vulture opens.

---

## 2. Desktop / server (writer): backend + agents

```bash
git clone https://github.com/bobinson/vulture && cd vulture

# Writer .env
cat > .env <<'EOF'
# Remote DB
VULTURE_DB_DSN=postgres://USER:PASSWORD@ep-xxx-xxxxxx-pooler.REGION.aws.neon.tech/vulture?sslmode=require
VULTURE_JWT_SECRET=CHANGE-ME-TO-A-64-CHAR-HEX   # openssl rand -hex 32
VULTURE_LOCAL_MODE=true

# LLM (LM Studio + qwen 3.5 example)
VULTURE_USE_LLM=true
VULTURE_LLM_MODEL=openai/qwen/qwen3.5-35b-a3b
OPENAI_BASE_URL=http://host.docker.internal:1234/v1
OPENAI_API_KEY=lm-studio

# Embeddings (same model must be used on BOTH sides)
VULTURE_EMBEDDING_URL=http://host.docker.internal:1234/v1
VULTURE_EMBEDDING_MODEL=text-embedding-nomic-embed-text-v1.5

# Mount your source tree (broad enough to cover projects you'll scan)
VULTURE_SOURCE_DIR=/home/user/src
EOF

# Opt-out of the local postgres container since we're using Neon
cat > docker-compose.override.yml <<'EOF'
services:
  postgres:
    deploy:
      replicas: 0
  backend:
    depends_on: !reset []
EOF

docker compose up -d --build
```

Trigger scans from the same desktop:

```bash
./cli/vulture scan ~/src/myproject
```

Findings, memories, and embeddings land in Neon.

---

## 3. Small VM (viewer): read-only backend + frontend

```bash
git clone https://github.com/bobinson/vulture && cd vulture

# Viewer .env
cat > .env <<'EOF'
# Same Neon DSN the writer uses
VULTURE_DB_DSN=postgres://USER:PASSWORD@ep-xxx-xxxxxx-pooler.REGION.aws.neon.tech/vulture?sslmode=require

# MUST match the writer's secret so JWTs validate
VULTURE_JWT_SECRET=CHANGE-ME-TO-A-64-CHAR-HEX

# The viewer has no agents and no LLM. Embedding is only needed for user
# search queries — point it at a reachable provider.
VULTURE_EMBEDDING_URL=https://api.openai.com/v1
VULTURE_EMBEDDING_MODEL=text-embedding-3-small
OPENAI_API_KEY=sk-...

# No local mode — use real auth on the public viewer
VULTURE_LOCAL_MODE=false
EOF

docker compose -f docker-compose.readonly.yml up -d --build
```

The frontend is available on port 23001. Reverse-proxy it with your preferred TLS fronting (nginx, Caddy, Cloudflare Tunnel, etc.).

---

## 4. Embedding consistency (important)

The writer uses its LM Studio embedding model (`text-embedding-nomic-embed-text-v1.5`). The viewer uses OpenAI (`text-embedding-3-small`). These produce different vector dimensions — semantic search from the viewer WILL produce wrong results because the query vector and stored vectors won't be in the same space.

**Pick one of:**

1. **Recommended:** use the same embedding provider on both sides (e.g. OpenAI on both, or run LM Studio on the VM too).
2. Accept that semantic-search on the viewer is degraded; keep-text-based fallback paths work.
3. Re-embed everything when the writer's model changes (not implemented in this release).

---

## 5. Operational notes

| Concern | Mitigation |
|---------|-----------|
| Network latency (desktop → Neon) | Pick Neon region close to desktop. Inserts are already batched via multi-value `INSERT`. Pooled connection string reduces handshake overhead. |
| First-query cold start on Neon free tier | ~1-2 s after idle. Use Neon Pro or disable autosuspend if this matters. |
| Concurrent migrations | The writer backend applies pending migrations at startup via the in-Go runner (feature 0040), serialized across instances by a Postgres advisory lock (`0x564C545F4D49475F`). The read-only viewer (mode C) opens via `NewPostgresRepoReadOnly` and skips migration application entirely — the writer owns the schema. See `docs/guides/migration_authoring.md` for the runner contract. |
| Live streams across instances | SSE stream tokens are in-memory per backend. The viewer cannot stream a live audit running on the desktop — it sees only completed results. For live viewing, point your browser at the desktop backend URL directly. |
| Secrets management | Don't commit `.env`. Use your deployment's secrets mechanism (Docker secrets, systemd credentials, Vault, etc.). |
| TLS termination | Neon enforces TLS. For the public VM, add a reverse proxy that terminates HTTPS in front of the frontend container. |
| DB backups | Neon provides PITR. No local backup needed. |
| Writer <> viewer version skew | Keep both on the same image tag — the DB schema is shared. |

---

## 6. Verifying the deployment

From your laptop:

```bash
# Writer health
curl https://desktop.example.com:28080/health
# → {"status":"healthy"}

# Viewer health
curl https://vulture.example.com:28080/health
# → {"status":"healthy"}

# Writer accepts audits
curl -X POST https://desktop.example.com:28080/api/audits \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"source_id":"...","types":["do178c"]}'
# → 200 OK

# Viewer rejects audits (the whole point of readonly)
curl -X POST https://vulture.example.com:28080/api/audits \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"source_id":"...","types":["do178c"]}'
# → 503 {"error":"read-only mode: ..."}

# Viewer lists completed audits from Neon
curl https://vulture.example.com:28080/api/audits -H "Authorization: Bearer $TOKEN"
# → [ { "id": "...", ... } ]
```

---

## 7. Going back to single-host

```bash
# Stop viewer
ssh vm "cd vulture && docker compose -f docker-compose.readonly.yml down"

# Stop writer
docker compose down

# Restore local postgres and remove override
rm docker-compose.override.yml

# Point .env at local postgres (or remove the DSN to use SQLite fallback)
# Edit .env: set VULTURE_DB_DSN=postgres://vulture:...@postgres:25432/vulture?sslmode=disable
#        or: delete VULTURE_DB_DSN entirely to use SQLite

docker compose up -d
```

Migrating data off Neon is a separate `pg_dump` / `pg_restore` operation; not required for the rollback itself.
