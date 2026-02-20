# SOC2 Audit - Rollback Plan

## Triggers

Rollback should be initiated if any of the following occur:

- SOC2 agent returns errors on valid source code
- Sub-agent delegation fails (orchestrator cannot hand off to clause agents)
- Agent produces findings referencing incorrect SOC2 clauses
- Compliance scores are inconsistent or unreliable
- SSE streaming produces malformed or out-of-order events
- Agent causes excessive LLM API costs (sub-agents multiply token usage)
- Container instability or memory leaks

## Rollback Steps

### 1. Disable the Agent

Comment out the SOC2 agent from the Go registry:

```go
// backend/internal/config/agents.go
// "soc2": {Name: "SOC2", URLEnv: "VULTURE_AGENT_SOC2_URL", DefaultPort: 8003},
```

### 2. Stop the Container

```bash
docker-compose stop agent-soc2
docker-compose rm agent-soc2
```

### 3. Revert Code (if needed)

```bash
git revert <commit-hash>
make build
make docker-up
```

### 4. Handle In-Flight Audits

Running audits with SOC2 type will receive a `StepFinished` error event. Other agent types in the same audit continue unaffected.

### 5. Clean Up

```sql
DELETE FROM findings WHERE agent_type = 'soc2' AND audit_id IN (
  SELECT id FROM audits WHERE created_at > '<deployment_timestamp>'
);
```

## Verification

- [ ] `GET /api/agents` no longer lists SOC2 agent
- [ ] New audits without SOC2 type work correctly
- [ ] Historical SOC2 results remain viewable
- [ ] Go backend health check passes
- [ ] E2E test suite passes (SOC2 tests expected to skip/fail)
