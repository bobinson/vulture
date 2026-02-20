# OWASP Audit - Rollback Plan

## Triggers

Rollback should be initiated if any of the following occur:

- OWASP agent returns errors on valid source code
- Agent produces excessive false positives (> 30% false positive rate)
- Agent misses known critical vulnerabilities (false negatives on test fixtures)
- SSE streaming produces malformed events
- Agent causes excessive LLM API costs
- Container instability (OOM kills, crash loops)
- Security issue in the agent's own code (ironic but possible)

## Rollback Steps

### 1. Disable the Agent

Comment out the OWASP agent from the Go registry:

```go
// backend/internal/config/agents.go
// "owasp": {Name: "OWASP", URLEnv: "VULTURE_AGENT_OWASP_URL", DefaultPort: 8002},
```

### 2. Stop the Container

```bash
docker-compose stop agent-owasp
docker-compose rm agent-owasp
```

### 3. Revert Code (if needed)

```bash
git revert <commit-hash>
make build
make docker-up
```

### 4. Handle In-Flight Audits

Running audits with OWASP type will receive a `StepFinished` error event. Other agent types in the same audit continue unaffected.

### 5. Clean Up

```sql
DELETE FROM findings WHERE agent_type = 'owasp' AND audit_id IN (
  SELECT id FROM audits WHERE created_at > '<deployment_timestamp>'
);
```

## Verification

- [ ] `GET /api/agents` no longer lists OWASP agent
- [ ] New audits without OWASP type work correctly
- [ ] Historical OWASP results remain viewable
- [ ] Go backend health check passes
- [ ] E2E test suite passes (OWASP tests expected to skip/fail)
