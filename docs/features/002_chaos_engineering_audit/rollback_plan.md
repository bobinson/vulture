# Chaos Engineering Audit - Rollback Plan

## Triggers

Rollback should be initiated if any of the following occur:

- Chaos agent consistently returns errors on valid source code
- Agent produces incorrect or misleading findings (false positive rate > 30%)
- SSE streaming fails or produces malformed events
- Agent causes excessive LLM API costs due to runaway token usage
- Agent container crashes repeatedly or leaks memory
- Security vulnerability discovered in file access patterns

## Rollback Steps

### 1. Disable the Agent

Remove or comment out the chaos agent from the Go registry:

```go
// backend/internal/config/agents.go
// "chaos": {Name: "Chaos Engineering", URLEnv: "VULTURE_AGENT_CHAOS_URL", DefaultPort: 8001},
```

### 2. Stop the Container

```bash
docker-compose stop agent-chaos
docker-compose rm agent-chaos
```

### 3. Revert Code (if needed)

```bash
git revert <commit-hash>
make build
make docker-up
```

### 4. Handle In-Flight Audits

Audits that included `chaos` as an audit type and are still running will receive a `StepFinished` event with error status from the Go backend when the agent becomes unreachable. The frontend handles partial results gracefully.

### 5. Clean Up Audit Records

If audit records reference chaos findings that are now invalid:

```sql
DELETE FROM findings WHERE agent_type = 'chaos' AND audit_id IN (
  SELECT id FROM audits WHERE created_at > '<deployment_timestamp>'
);
```

## Verification

- [ ] `GET /api/agents` no longer lists chaos engineering agent
- [ ] New audits without chaos type proceed normally
- [ ] Existing completed audits with chaos results are still viewable
- [ ] Go backend health check passes
- [ ] No orphaned containers or volumes
- [ ] E2E test suite passes (chaos-specific tests expected to skip/fail)
