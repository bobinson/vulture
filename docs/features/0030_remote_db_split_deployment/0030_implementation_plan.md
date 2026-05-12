# 0030 Remote DB Split Deployment Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Support a split deployment where the DB lives remotely (e.g. Neon Postgres with pgvector), the backend + 9 scan agents + LLM run on a desktop/server, and the frontend runs on a small VM that displays results from the shared DB.

**Architecture:**

```
                    ┌─────────────────────┐
                    │   Neon Postgres     │
                    │   (pgvector)        │
                    └─────▲──────▲────────┘
                WRITE+READ│      │READ only
                          │      │
        ┌─────────────────┴─┐  ┌─┴──────────────────┐
        │ DESKTOP / SERVER  │  │ SMALL VM           │
        │ ───────────────── │  │ ────────────────── │
        │ backend (writer)  │  │ backend (readonly) │
        │ + 9 agents        │  │ + nginx + SPA      │
        │ + LM Studio / GPU │  │ public URL         │
        │ holds source code │  │ end users          │
        └───────────────────┘  └────────────────────┘
```

**Tech Stack:** Existing Go backend (`lib/pq`), React+Vite SPA, Neon Postgres, Docker Compose.

**Key Insight:** The Vulture backend is the only component that touches Postgres. Agents and frontend both go through HTTP. So running two backend instances against the same remote DB is sufficient — the read-only one just needs to reject write endpoints and skip agent orchestration.

---

## File Structure

```
backend/
  internal/
    server/
      server.go              # (modify) add readonlyGuard middleware + VULTURE_READONLY branch
      readonly.go            # (new)    ReadOnlyMiddleware + tests
      readonly_test.go       # (new)
    handler/
      agent_handler.go       # (modify) skip health checks in readonly
docker-compose.readonly.yml  # (new)    VM-side minimal compose
docs/
  features/0030_remote_db_split_deployment/
    0030_implementation_plan.md     # this file
    0030_implementation_status.md   # tracking
    0030_rollback_plan.md            # revert steps
  guides/
    neon_deployment.md       # (new)    step-by-step Neon setup
```

---

## Task 1: Backend `VULTURE_READONLY` middleware

**Files:**
- Create: `backend/internal/server/readonly.go`
- Create: `backend/internal/server/readonly_test.go`
- Modify: `backend/internal/server/server.go`

- [ ] **Step 1: Write failing test**

```go
// backend/internal/server/readonly_test.go
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadOnlyGuard_AllowsGET(t *testing.T) {
	h := ReadOnlyGuard(true, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/audits", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestReadOnlyGuard_BlocksPOST(t *testing.T) {
	h := ReadOnlyGuard(true, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})
	req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestReadOnlyGuard_PassthroughWhenDisabled(t *testing.T) {
	called := false
	h := ReadOnlyGuard(false, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/audits", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if !called {
		t.Fatal("expected handler to be called")
	}
}

func TestReadOnlyGuard_BlocksPUTPATCHDELETE(t *testing.T) {
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		h := ReadOnlyGuard(true, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("%s should have been blocked", m)
		})
		req := httptest.NewRequest(m, "/api/memories/abc", nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: expected 503, got %d", m, rec.Code)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/server/ -run TestReadOnlyGuard -v`
Expected: FAIL with "undefined: ReadOnlyGuard"

- [ ] **Step 3: Implement `readonly.go`**

```go
// backend/internal/server/readonly.go
package server

import (
	"encoding/json"
	"net/http"
)

// ReadOnlyGuard wraps a handler so that when readOnly is true, only GET
// and HEAD requests are allowed. Mutating methods return 503 Service
// Unavailable with a clear error body.
func ReadOnlyGuard(readOnly bool, next http.HandlerFunc) http.HandlerFunc {
	if !readOnly {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "read-only mode: this Vulture instance does not accept writes",
				"hint":  "run audits on the writer backend; this instance only serves stored results",
			})
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/server/ -run TestReadOnlyGuard -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Wire into `server.go`**

In `backend/internal/server/server.go`, near the top of route registration:

```go
readOnly := cfg.ReadOnly
```

And wrap all write-capable routes. Concrete diff at line ~180:

```go
// Write-capable routes (wrapped with readonly guard)
sourceHandler := ReadOnlyGuard(readOnly, sourceH.Create)
auditsHandler := ReadOnlyGuard(readOnly, auditsH)
// ... etc for audits/, memories/, lineage/, prove-results, pipelines

// GET-only routes are never guarded
// /api/stats, /api/agents, /api/memories/search, etc. pass through
```

Also at line ~186 (`/api/agents`): in readonly mode, skip the health check ping loop so the VM doesn't probe agents that aren't on its network. Handled inside `agentH.List` — add a readonly check.

- [ ] **Step 6: Add `ReadOnly` to config**

In `backend/internal/config/config.go`, add `ReadOnly bool` to the `Config` struct and load from `VULTURE_READONLY`:

```go
ReadOnly: os.Getenv("VULTURE_READONLY") == "true",
```

- [ ] **Step 7: Skip agent health checks in readonly mode**

In `backend/internal/handler/agent_handler.go` `List()`:

```go
func (h *AgentHandler) List(w http.ResponseWriter, r *http.Request) {
    if h.readOnly {
        // Return empty list — this backend doesn't orchestrate agents
        writeJSON(w, http.StatusOK, []model.AgentInfo{})
        return
    }
    // ... existing health-check logic
}
```

Add `readOnly bool` field to `AgentHandler` and a setter. Wire in `server.go`.

- [ ] **Step 8: Run full backend tests**

Run: `cd backend && go test ./... 2>&1 | tail -20`
Expected: all passing, no regressions.

- [ ] **Step 9: Commit**

```bash
git add backend/internal/server/readonly.go backend/internal/server/readonly_test.go \
        backend/internal/server/server.go backend/internal/config/config.go \
        backend/internal/handler/agent_handler.go
git commit -m "feat(backend): add VULTURE_READONLY mode for read-only FE-side deployments"
```

---

## Task 2: `docker-compose.readonly.yml` for the VM

**Files:**
- Create: `docker-compose.readonly.yml`

- [ ] **Step 1: Write the file**

```yaml
# Minimal compose for the VM-side read-only deployment.
# Connects to a REMOTE Postgres (Neon) and reads everything from there.
# No agents, no local postgres, no writer backend.

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "${VULTURE_BACKEND_PORT:-28080}:${VULTURE_BACKEND_PORT:-28080}"
    environment:
      - VULTURE_PORT=${VULTURE_BACKEND_PORT:-28080}
      - VULTURE_READONLY=true
      - VULTURE_LOCAL_MODE=${VULTURE_LOCAL_MODE:-false}
      - "VULTURE_DB_DSN=${VULTURE_DB_DSN:?Remote DB DSN required — e.g. postgres://user:pass@ep-xxx-pooler.region.neon.tech/vulture?sslmode=require}"
      - "VULTURE_JWT_SECRET=${VULTURE_JWT_SECRET:?JWT secret required}"
      # Embeddings: must match the writer's config for consistent vectors
      - VULTURE_EMBEDDING_URL=${VULTURE_EMBEDDING_URL}
      - VULTURE_EMBEDDING_MODEL=${VULTURE_EMBEDDING_MODEL:-text-embedding-3-small}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:${VULTURE_BACKEND_PORT:-28080}/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 15s
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
    restart: unless-stopped

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "${VULTURE_FRONTEND_HOST:-23001}:${VULTURE_FRONTEND_INTERNAL:-23000}"
    environment:
      - NGINX_ENVSUBST_FILTER=VULTURE_
      - VULTURE_FRONTEND_INTERNAL=${VULTURE_FRONTEND_INTERNAL:-23000}
      - VULTURE_BACKEND_PORT=${VULTURE_BACKEND_PORT:-28080}
    depends_on:
      backend:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:${VULTURE_FRONTEND_INTERNAL:-23000}/ || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 15s
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
    restart: unless-stopped
```

- [ ] **Step 2: Validate**

Run: `VULTURE_DB_DSN=postgres://u:p@host/db?sslmode=require VULTURE_JWT_SECRET=x docker compose -f docker-compose.readonly.yml config --quiet`
Expected: exit 0, no errors.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.readonly.yml
git commit -m "feat(infra): add docker-compose.readonly.yml for VM-side FE deployment"
```

---

## Task 3: Neon deployment guide

**Files:**
- Create: `docs/guides/neon_deployment.md`

- [ ] **Step 1: Write the guide**

```markdown
# Neon + Split Deployment Guide

Deploy Vulture with:
- **Neon Postgres** hosting the DB remotely (pgvector enabled)
- **Desktop/server** running backend + 9 agents (writer)
- **Small VM** running read-only backend + frontend (viewer)

## 1. Provision Neon

1. Sign up at <https://neon.tech>
2. Create a project (pick region close to your desktop)
3. Enable pgvector in SQL editor:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
   CREATE EXTENSION IF NOT EXISTS pg_trgm;
   ```
4. Copy the **pooled** connection string (ends in `-pooler.region.neon.tech`)

## 2. Desktop (writer): backend + agents

```bash
git clone https://github.com/bobinson/vulture
cd vulture

# Configure
cat > .env <<EOF
VULTURE_DB_DSN=postgres://USER:PASS@ep-xxx-pooler.us-east-2.aws.neon.tech/vulture?sslmode=require
VULTURE_JWT_SECRET=$(openssl rand -hex 32)
VULTURE_LOCAL_MODE=true
VULTURE_USE_LLM=true
VULTURE_LLM_MODEL=openai/qwen/qwen3.5-35b-a3b
OPENAI_BASE_URL=http://host.docker.internal:1234/v1
OPENAI_API_KEY=lm-studio
VULTURE_EMBEDDING_URL=http://host.docker.internal:1234/v1
VULTURE_EMBEDDING_MODEL=text-embedding-nomic-embed-text-v1.5
EOF

# Start. Use docker-compose.override.yml to remove the local postgres service
# since we're using Neon.
cat > docker-compose.override.yml <<EOF
services:
  postgres:
    deploy: { replicas: 0 }
  backend:
    depends_on: !reset []
EOF

docker compose up -d --build
```

Trigger scans:
```bash
./cli/vulture scan /home/you/src/myproject
```

Findings, memories, embeddings all land in Neon.

## 3. VM (viewer): read-only FE + backend

```bash
git clone https://github.com/bobinson/vulture
cd vulture

cat > .env <<EOF
VULTURE_DB_DSN=postgres://USER:PASS@ep-xxx-pooler.us-east-2.aws.neon.tech/vulture?sslmode=require
VULTURE_JWT_SECRET=same-secret-as-desktop
VULTURE_LOCAL_MODE=false
VULTURE_EMBEDDING_URL=https://api.openai.com/v1
VULTURE_EMBEDDING_MODEL=text-embedding-3-small
OPENAI_API_KEY=sk-...
EOF

docker compose -f docker-compose.readonly.yml up -d --build
```

Frontend at `http://VM-IP:23001`. Reads from Neon.

## 4. Operational notes

- **Embedding consistency:** the viewer needs the same embedding model as the writer for semantic search to return sensible results. The viewer embeds only user queries (not documents), so vector dimension must match.
- **JWT secret:** must match between writer and viewer for cross-instance auth token verification.
- **Write attempts from FE:** the readonly backend returns 503 with a clear error. Frontend should degrade gracefully (future: hide "New Audit" button when `readonly` flag is set).
- **Live streams:** SSE live-streams are not shared across instances. The viewer can display completed audits but can't stream one running on the desktop. For live viewing, point your browser at the desktop directly.
- **Migrations:** both backends run migrations at startup. Postgres `CREATE ... IF NOT EXISTS` is idempotent, so double-run is safe. Advisory locks can be added later if this becomes an issue.
```

- [ ] **Step 2: Commit**

```bash
git add docs/guides/neon_deployment.md
git commit -m "docs: Neon + split deployment guide"
```

---

## Task 4: Update CLAUDE.md architecture section

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add to Architecture section**

Insert after the existing deployment line (~line 27):

```markdown
### Deployment Topologies

1. **Single-host (default)** — everything via `docker compose up`. Postgres, backend, agents, frontend on one machine. Best for dev.
2. **Split deployment** — remote DB (e.g. Neon), writer backend + agents on a desktop/server, read-only backend + frontend on a small VM. See `docs/guides/neon_deployment.md`. Use `docker-compose.readonly.yml` on the VM side.

Environment flag: set `VULTURE_READONLY=true` on the VM backend to reject write endpoints.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(CLAUDE.md): document split deployment topology"
```

---

## Self-review checklist

- [ ] `VULTURE_READONLY=true` rejects POST/PUT/PATCH/DELETE with 503
- [ ] `VULTURE_READONLY=true` still allows all GET endpoints
- [ ] `/api/agents` returns empty list in readonly (no probe attempts to agents that aren't there)
- [ ] Migrations still run at startup (idempotent)
- [ ] JWT secret consistency documented
- [ ] Embedding model consistency documented
- [ ] Live-stream limitation documented
