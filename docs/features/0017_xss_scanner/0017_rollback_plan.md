# 0017 — XSS Scanner Agent Rollback Plan

## Rollback Steps

To fully remove the XSS scanner agent:

### 1. Remove Agent Code
```bash
rm -rf agents/xss/
```

### 2. Backend Registration
- `backend/internal/config/config.go`: Remove `xssPort` variable and `"xss"` entry from agents map
- `backend/internal/localdev/launcher.go`: Remove `"xss"` from AgentPorts, installAgentDeps list, startAgents list, backend env vars, and printBanner

### 3. Docker Compose
- `docker-compose.yml`: Remove `agent-xss` service block, backend `VULTURE_AGENT_XSS_URL` env var, and `agent-xss` dependency

### 4. Frontend i18n
- Remove `"xss": "XSS"` from agents section in all 6 locale files
- Remove `"xssDesc"` from audit section in all 6 locale files

### 5. Rebuild
```bash
cd backend && go build ./cmd/vulture/
docker compose build
```

## Risk Assessment

- **Low risk**: XSS agent is fully independent — no shared state, no schema changes, no frontend component changes
- **No data migration needed**: Agent produces standard findings that use existing DB schema
- **Frontend auto-discovery**: Removing the agent from backend config automatically removes it from the UI
