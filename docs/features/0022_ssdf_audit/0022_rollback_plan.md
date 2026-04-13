# 0022 - SSDF Audit Rollback Plan

## Rollback Steps

If the SSDF agent needs to be removed:

### 1. Remove Agent Directory
```bash
rm -rf agents/ssdf/
```

### 2. Remove Prove Strategy
```bash
rm agents/prove/prove_agent/strategies/ssdf.py
```
Remove `ssdf` import and entry from `agents/prove/prove_agent/strategies/__init__.py`.

### 3. Revert Backend Config
In `backend/internal/config/config.go`:
- Remove `ssdfPort` variable
- Remove `"ssdf"` entry from `defaultAgents()` map

### 4. Revert Local Dev Launcher
In `backend/internal/localdev/launcher.go`:
- Remove `"ssdf"` from `AgentPorts` map in `DefaultConfig()`
- Remove `"ssdf"` entry from `startAgents()` agents slice
- Remove `"ssdf"` from `installAgentDeps()` agent list
- Remove `VULTURE_AGENT_SSDF_URL` from `startBackend()` env
- Revert `printBanner()` to exclude ssdf

### 5. Revert Tests
In `backend/internal/config/config_test.go`: Change agent count back to 6.
In `backend/internal/localdev/process_test.go`: Change agent count back to 6.

### 6. Revert Infrastructure
- Remove `agent-ssdf` service from `docker-compose.yml`
- Remove `VULTURE_AGENT_SSDF_URL` from backend environment in `docker-compose.yml`
- Remove `agent-ssdf` from backend `depends_on` in `docker-compose.yml`
- Remove `agent_ssdf` from `config.ini`
- Remove ssdf test line from `Makefile`

### 7. Remove Feature Docs
```bash
rm -rf docs/features/0022_ssdf_audit/
```

## Risk Assessment

- **Low risk**: SSDF agent is independently deployable and does not affect other agents.
- **No database migrations**: SSDF findings use existing `findings` table schema.
- **Frontend**: Auto-discovers agents via `/api/agents` — removal is transparent.
