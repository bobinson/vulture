# 0029 DO-178C Audit Rollback Plan

## Strategy
The DO-178C agent is fully self-contained. Rollback requires 3 changes:

1. Remove `agents/do178c/` directory
2. Remove the registry entry from `backend/pkg/agentregistry/registry.go`
3. Remove the `agent-do178c` service block and backend env var from `docker-compose.yml`

## Commands
```
rm -rf agents/do178c/
# Edit registry.go: remove the {"do178c", ...} line
# Edit docker-compose.yml: remove agent-do178c block + backend env var + depends_on entry
git add -A && git commit -m "revert: remove DO-178C audit agent (0029)"
```

No database migration rollback needed. No frontend changes to revert.
Frontend auto-discovers agents via GET /api/agents — removing the agent makes it disappear.
