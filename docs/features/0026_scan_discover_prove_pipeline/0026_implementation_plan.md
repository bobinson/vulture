# 0026 Three-Stage Audit Pipeline: Scan → Discover → Prove

## Overview

Restructure the audit system into a 3-stage pipeline where each stage builds on the previous:
- **Scan** (static analysis): existing agents (chaos, owasp, soc2, cwe, xss, ssdf) analyze source code
- **Discover** (dynamic discovery): new agent crawls a target URL, maps attack surface, produces SiteMap + security findings
- **Prove** (verification): existing prove agent verifies findings against staging using pre-built SiteMap

Key behaviors:
- Each stage can run independently or cascade automatically
- Discover can run standalone with just a target URL (no source code required)
- Backend manages pipeline orchestration with auto-triggering of prerequisites
- No-cache mode does full rediscovery but filters out already-known results

## Architecture Decisions

1. **Extract discovery into shared**: Move prove agent's discovery pipeline (discovery.py, plugins/, source_analyzer.py, deep_discovery.py) into `agents/shared/shared/discovery/`. Both discover and prove agents import from shared.
2. **Discover agent**: New standalone Python agent microservice using the shared discovery package.
3. **Pipeline as first-class entity**: New `pipelines` table with state machine, linking ordered sub-audits. New `discover_results` table for structured discover output.
4. **Mixed orchestration**: Backend provides `POST /api/pipelines` with auto-cascading; clients explicitly choose which stage to invoke. Existing single-stage APIs remain backward-compatible.
5. **Full rediscovery, filter output**: Discover always runs full plugin stack; output marks findings that match prior results so consumers can filter.

---

## Phase 1: Extract Shared Discovery Package (Python)

No behavior changes — pure refactoring. Prove agent continues to work identically.

### New files

| File | Contents |
|------|----------|
| `agents/shared/shared/discovery/__init__.py` | Re-exports: `SiteMap`, `DiscoveryPlugin`, `DiscoveryContext`, `DiscoveryResult`, `run_discovery`, `register_plugin` |
| `agents/shared/shared/discovery/sitemap.py` | `SiteMap` dataclass moved from `prove_agent/discovery.py` (lines 38-80) + `merge()`, `deduplicate()`, `to_json()`, `from_json()` |
| `agents/shared/shared/discovery/helpers.py` | Crawl helpers moved from `prove_agent/discovery.py`: `_extract_links`, `_extract_forms`, `_extract_headers`, `_extract_technologies`, `_is_static_path`, `_COMMON_PATHS`, `_STATIC_EXTENSIONS` |
| `agents/shared/shared/discovery/cache.py` | Cache functions moved from `prove_agent/discovery.py`: `load_cached_discovery`, `save_discovery_cache`, `is_cache_fresh`, `_cache_path` |
| `agents/shared/shared/discovery/plugin_base.py` | `DiscoveryPlugin` ABC, `DiscoveryContext`, `DiscoveryResult` dataclasses, `register_plugin` decorator — moved from `prove_agent/plugins/__init__.py` |
| `agents/shared/shared/discovery/runner.py` | `run_discovery()` orchestrator — moved from `prove_agent/plugins/__init__.py` |
| `agents/shared/tests/unit/test_discovery_shared.py` | Unit tests for SiteMap, plugin registration, runner |

### Modified files

| File | Change |
|------|--------|
| `agents/shared/pyproject.toml` | Add `shared.discovery` package |
| `agents/prove/prove_agent/discovery.py` | Replace implementation with shim re-exporting from `shared.discovery` |
| `agents/prove/prove_agent/plugins/__init__.py` | Update imports to `from shared.discovery.plugin_base import ...` |
| Each plugin in `agents/prove/prove_agent/plugins/*.py` | Update imports from `prove_agent.discovery` to `shared.discovery.helpers` / `shared.discovery.sitemap` |

### Verification

```bash
cd agents/shared && python -m pytest tests/ -v
cd agents/prove && python -m pytest tests/ -v
```

---

## Phase 2: New Discover Agent (Python)

### New files

| File | Contents |
|------|----------|
| `agents/discover/pyproject.toml` | Package config, deps: shared, httpx, playwright |
| `agents/discover/Dockerfile` | Based on `agents/prove/Dockerfile`; installs both discover and prove packages (prove_agent plugins are imported via shared.discovery) |
| `agents/discover/SKILLS.md` | Documents 22 inherited discovery plugins + security exposure analysis |
| `agents/discover/discover_agent/__init__.py` | Package marker |
| `agents/discover/discover_agent/main.py` | `create_sse_app("discover", AGENT_INFO, run_discover)` |
| `agents/discover/discover_agent/config.py` | `AGENT_INFO`, `CONFIG_SCHEMA` with fields: `target_url` (required), `source_path` (optional), `schemas` (optional), `no_cache` (bool) |
| `agents/discover/discover_agent/agent.py` | `run_discover()` generator — main /run handler |
| `agents/discover/discover_agent/findings.py` | Security finding generators: missing HSTS, exposed .env, directory listing, server version, GraphQL introspection enabled, debug endpoints |
| `agents/discover/tests/__init__.py` | |
| `agents/discover/tests/unit/__init__.py` | |
| `agents/discover/tests/unit/test_agent.py` | Unit tests for run_discover |
| `agents/discover/tests/e2e/__init__.py` | |
| `agents/discover/tests/e2e/test_discover_audit.py` | E2E tests with mock HTTP server |

### Modified files

| File | Change |
|------|--------|
| `agents/shared/shared/transport/event_emitter.py` | Add `discover_result_event()` method |
| `agents/shared/shared/models/discover_request.py` | New `DiscoverRequest` model (target_url, source_path, config, known_endpoints) |
| `agents/prove/prove_agent/agent.py` | Accept `config["site_map"]` to skip rediscovery when present (~15 lines at top of `_run_prove_pipeline`) |

### `run_discover()` Logic

```python
def run_discover(run_id, source_path, config, prior_findings):
    emitter = AgUiEventEmitter(run_id)
    yield emitter.run_started()

    target_url = config["target_url"]
    # 1. Validate URL (reuse validate_staging_url from shared)
    # 2. Detect capabilities (HTTP, WS, JSON-RPC)
    # 3. Optional: analyze_source(source_path) for route extraction
    # 4. Run discover_site(target_url, ...) with all 22 plugins
    # 5. Emit security findings (exposed endpoints, missing headers, etc.)
    # 6. Emit discover_result event with SiteMap JSON
    # 7. Emit result event with all findings + score

    yield emitter.run_finished()
```

### Verification

```bash
cd agents/discover && python -m pytest tests/ -v
cd agents/prove && python -m pytest tests/ -v  # ensure no regression
```

---

## Phase 3: Go Data Model & Database Migration

### New files

| File | Contents |
|------|----------|
| `backend/internal/model/pipeline.go` | `Pipeline` struct, `PipelineStatus` constants (pending, scan_running, discover_running, prove_running, completed, failed), `PipelineRequest` |
| `backend/internal/model/discover.go` | `DiscoverResult` struct (id, audit_id, target_url, site_map_json, url_count, api_count, form_count, technologies, created_at) |
| `backend/migrations/010_pipeline_stages.sql` | CREATE TABLE `pipelines` + `discover_results` with indexes |

### Migration SQL

```sql
CREATE TABLE IF NOT EXISTS pipelines (
    id                TEXT PRIMARY KEY,
    target_url        TEXT NOT NULL,
    source_id         TEXT NOT NULL,
    scan_audit_id     TEXT,
    discover_audit_id TEXT,
    prove_audit_id    TEXT,
    status            TEXT NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ
);

CREATE INDEX idx_pipelines_source ON pipelines (source_id);
CREATE INDEX idx_pipelines_status ON pipelines (status);

CREATE TABLE IF NOT EXISTS discover_results (
    id            TEXT PRIMARY KEY,
    audit_id      TEXT NOT NULL UNIQUE,
    target_url    TEXT NOT NULL,
    site_map_json TEXT NOT NULL DEFAULT '{}',
    url_count     INTEGER NOT NULL DEFAULT 0,
    api_count     INTEGER NOT NULL DEFAULT 0,
    form_count    INTEGER NOT NULL DEFAULT 0,
    technologies  TEXT NOT NULL DEFAULT '[]',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_discover_results_target ON discover_results (target_url);
```

---

## Phase 4: Go Repositories

### New files

| File | Contents |
|------|----------|
| `backend/internal/repository/pipeline_repo.go` | `PipelineRepository` interface: Create, Get, Update, List, GetByAuditID |
| `backend/internal/repository/sqlite_pipeline_repo.go` | SQLite implementation |
| `backend/internal/repository/postgres_pipeline_repo.go` | PostgreSQL implementation |
| `backend/internal/repository/discover_repo.go` | `DiscoverRepository` interface: SaveResult, GetResult, GetResultByTarget |
| `backend/internal/repository/sqlite_discover_repo.go` | SQLite implementation |
| `backend/internal/repository/postgres_discover_repo.go` | PostgreSQL implementation |
| `backend/internal/repository/mock_pipeline_repo.go` | Mock for testing |
| `backend/internal/repository/mock_discover_repo.go` | Mock for testing |

---

## Phase 5: Go Services

### New files

| File | Contents |
|------|----------|
| `backend/internal/service/discover_service.go` | `DiscoverService` interface + implementation: SaveResult, GetResult, GetResultByTarget |
| `backend/internal/service/discover_service_test.go` | Unit tests with mock repo |
| `backend/internal/service/pipeline_service.go` | `PipelineService` with state machine: CreatePipeline, GetPipeline, ListPipelines, AdvanceStage, GetStageAuditConfig |
| `backend/internal/service/pipeline_service_test.go` | Tests for all state transitions, auto-cascade, SiteMap injection |

### Pipeline State Machine

```
pending → scan_running → discover_running → prove_running → completed
                    ↘          ↘               ↘
                   failed      failed          failed
```

### Auto-cascade logic in `CreatePipeline()`

```go
func (s *pipelineService) expandStages(requested []string) []string {
    // Map of stage → prerequisites
    prereqs := map[string][]string{
        "scan":     {},
        "discover": {"scan"},  // scan is optional for discover-only (URL mode)
        "prove":    {"scan", "discover"},
    }
    // Build ordered unique stage list
    // If only ["prove"] requested → expand to ["scan", "discover", "prove"]
    // If only ["discover"] requested with source_path → expand to ["scan", "discover"]
    // If only ["discover"] requested without source_path → just ["discover"] (URL-only)
}
```

### `AdvanceStage()` — idempotent stage transitions

When a sub-audit completes:
1. Check if audit belongs to a pipeline (via `GetByAuditID`)
2. If pipeline status already past expected stage, no-op (idempotent)
3. Collect output from completed stage (findings for scan, DiscoverResult for discover)
4. Create next stage's audit with prior stage output injected into config
5. Update pipeline status

---

## Phase 6: Go Handlers & SSE Events

### New files

| File | Contents |
|------|----------|
| `backend/internal/handler/pipeline_handler.go` | `POST /api/pipelines`, `GET /api/pipelines`, `GET /api/pipelines/:id`, `GET /api/pipelines/:id/stream` |
| `backend/internal/handler/pipeline_handler_test.go` | Handler tests |
| `backend/internal/handler/discover_handler.go` | `GET /api/audits/:id/discover-result`, `GET /api/discover-results?target_url=...` |
| `backend/internal/handler/discover_handler_test.go` | Handler tests |

### Modified files

| File | Change |
|------|--------|
| `backend/internal/agui/translator.go` | Handle `discover_result` SSE event → `EventStateDelta` with `{"discover_result": {...}}` |
| `backend/internal/handler/stream_handler.go` | Add `SetDiscoverService()`, `SetPipelineService()`. In event processing: extract `discover_result` events → `discoverSvc.SaveResult()`. On audit completion: check if part of pipeline → `pipelineSvc.AdvanceStage()` |
| `backend/internal/server/server.go` | Add `registerDiscoverRoutes()`, `registerPipelineRoutes()`. Wire discover handler into `auditDetailRouter` for `/api/audits/:id/discover-result` |
| `backend/internal/config/config.go` | Add discover to `AllAgents`, update `ScanAgentTypes()` to exclude both "prove" and "discover" |

### API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/pipelines` | Create pipeline (auto-cascade) |
| GET | `/api/pipelines` | List pipelines |
| GET | `/api/pipelines/:id` | Get pipeline status + sub-audit IDs |
| GET | `/api/pipelines/:id/stream` | SSE stream for all pipeline stages |
| GET | `/api/audits/:id/discover-result` | Get discover result for an audit |
| GET | `/api/discover-results?target_url=...` | Get latest discover result for a target |

---

## Phase 7: CLI Updates

### Modified files

| File | Change |
|------|--------|
| `cli/main.go` | Add `discover` command with `--target-url`, `--types`, `--no-cache` flags. Update `printUsage()`. Add `cmdDiscover()` function. Update `cmdProve()` to optionally use pipeline API. |

### CLI Commands

```bash
# Scan only (unchanged)
vulture scan /path/to/code --types owasp,cwe

# Discover only (URL mode — no source code)
vulture discover --target-url https://staging.example.com

# Discover with source (auto-triggers scan first)
vulture discover /path/to/code --target-url https://staging.example.com

# Prove (auto-triggers scan + discover)
vulture prove /path/to/code --staging-url https://staging.example.com

# Full pipeline explicitly
vulture pipeline /path/to/code --staging-url https://staging.example.com --types owasp,cwe
```

---

## Phase 8: Docker & Infrastructure

### Modified files

| File | Change |
|------|--------|
| `docker-compose.yml` | Add `agent-discover` service block (port 28008), add `VULTURE_AGENT_DISCOVER_URL` to backend env |

### New docker-compose service

```yaml
agent-discover:
  build:
    context: ./agents
    dockerfile: discover/Dockerfile
  environment:
    - VULTURE_AGENT_PORT=28008
    - VULTURE_BACKEND_URL=http://backend:28080
    - VULTURE_LLM_MODEL=${VULTURE_LLM_MODEL:-}
    - OPENAI_API_KEY=${OPENAI_API_KEY:-}
  ports:
    - "28008:28008"
  depends_on:
    - backend
```

---

## Phase 9: Frontend (Optional Follow-up)

| File | Change |
|------|--------|
| `frontend/src/lib/types.ts` | Add `Pipeline`, `DiscoverResult`, `PipelineRequest` interfaces |
| `frontend/src/lib/api.ts` | Add `createPipeline()`, `getPipeline()`, `listPipelines()` API methods |
| `frontend/src/pages/AuditNew.tsx` | Add pipeline mode selector (scan-only vs full pipeline) |
| `frontend/src/pages/AuditResults.tsx` | Display discover results section (SiteMap visualization) |
| `frontend/src/components/results/DiscoverResults.tsx` | New component: endpoint list, technology badges, SiteMap summary |
| `frontend/src/hooks/usePipeline.ts` | Pipeline state tracking hook |

---

## Complete File Summary

### New files (35)

**Python** (14):
- `agents/shared/shared/discovery/__init__.py`
- `agents/shared/shared/discovery/sitemap.py`
- `agents/shared/shared/discovery/helpers.py`
- `agents/shared/shared/discovery/cache.py`
- `agents/shared/shared/discovery/plugin_base.py`
- `agents/shared/shared/discovery/runner.py`
- `agents/shared/shared/models/discover_request.py`
- `agents/shared/tests/unit/test_discovery_shared.py`
- `agents/discover/` (pyproject.toml, Dockerfile, SKILLS.md)
- `agents/discover/discover_agent/` (__init__.py, main.py, agent.py, config.py, findings.py)
- `agents/discover/tests/` (unit + e2e)

**Go** (16):
- `backend/internal/model/pipeline.go`
- `backend/internal/model/discover.go`
- `backend/migrations/010_pipeline_stages.sql`
- `backend/internal/repository/` (pipeline_repo, discover_repo, sqlite/postgres/mock implementations — 8 files)
- `backend/internal/service/` (pipeline_service, discover_service + tests — 4 files)
- `backend/internal/handler/` (pipeline_handler, discover_handler + tests — 4 files)

**Docs** (3):
- `docs/features/0026_scan_discover_prove_pipeline/` (plan, status, rollback)

### Modified files (15)

**Python** (6):
- `agents/shared/pyproject.toml`
- `agents/shared/shared/transport/event_emitter.py`
- `agents/prove/prove_agent/discovery.py` (shim)
- `agents/prove/prove_agent/plugins/__init__.py` (imports)
- `agents/prove/prove_agent/plugins/*.py` (import updates)
- `agents/prove/prove_agent/agent.py` (accept site_map)

**Go** (7):
- `backend/internal/config/config.go`
- `backend/internal/agui/translator.go`
- `backend/internal/handler/stream_handler.go`
- `backend/internal/server/server.go`
- `backend/internal/repository/sqlite_repo.go` (run migration)
- `backend/internal/repository/postgres_repo.go` (run migration)
- `cli/main.go`

**Infra** (1):
- `docker-compose.yml`

**Frontend** (1, optional follow-up):
- `frontend/src/lib/types.ts`

---

## Verification

```bash
# Phase 1: shared discovery extraction
cd agents/shared && python -m pytest tests/ -v
cd agents/prove && python -m pytest tests/ -v

# Phase 2: discover agent
cd agents/discover && python -m pytest tests/ -v

# Phases 3-6: Go backend
cd backend && go test ./internal/model/... ./internal/repository/... ./internal/service/... ./internal/handler/... ./internal/server/...

# Phase 7: CLI
cd cli && go build . && ./cli discover --help

# Full stack
make test
```

---

## Backward Compatibility

- `POST /api/audits` with scan types: unchanged
- `POST /api/audits` with `types: ["prove"]`: unchanged — prove auto-discovers if no site_map in config
- `vulture scan`: unchanged
- `vulture prove`: unchanged (client-side cascade preserved)
- All existing SSE events: unchanged
- Discover agent is additive — registered in AllAgents but only invoked when explicitly requested or via pipeline
