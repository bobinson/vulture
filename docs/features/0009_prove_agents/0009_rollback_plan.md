# 0009 - Prove Companion Agents Rollback Plan

## Rollback Steps

### 1. Remove Prove Agent Service
```bash
rm -rf agents/prove/
```

### 2. Revert Shared Event Emitter
Remove the 5 `proof_*_event()` methods from `agents/shared/shared/transport/event_emitter.py`.

### 3. Revert Backend Changes
- Remove `"prove"` entry from `defaultAgents()` in `backend/internal/config/config.go`
- Remove `EventProof*` constants from `backend/internal/model/event.go`
- Remove `proof_*` translator entries and `translateProofEvent()` from `backend/internal/agui/translator.go`
- Remove prove entries from `backend/internal/localdev/launcher.go`:
  - Remove `"prove": "28005"` from `AgentPorts`
  - Remove prove agent from `startAgents()` agents list
  - Remove prove from `installAgentDeps()` loop
  - Remove `VULTURE_AGENT_PROVE_URL` from `startBackend()` env
  - Revert banner `Agents:` line

### 4. Revert CLI
Remove `cmdProve()`, `streamProve()`, `printProveEvent()`, `printProveDelta()`, `parseProveFlags()`, and `proveFlags` struct from `cli/main.go`. Remove `prove` case from switch.

### 5. Revert Infrastructure
- Remove `agent-prove` service from `docker-compose.yml`
- Remove `agent-prove` dependency from backend service
- Remove `VULTURE_AGENT_PROVE_URL` from backend environment
- Remove prove agent test target from `Makefile`

### 6. Remove Documentation
```bash
rm -rf docs/features/0009_prove_agents/
```

## Verification After Rollback
```bash
cd backend && go test ./... -count=1
cd agents && python -m pytest tests/ -v
cd frontend && npx playwright test
```

## Risk Assessment
- **Low risk**: Prove agent is a standalone addition with no dependencies from existing components
- **No data migration**: No database schema changes
- **No breaking changes**: Existing scanner agents are unaffected
