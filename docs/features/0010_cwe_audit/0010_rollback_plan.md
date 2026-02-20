# 0010 CWE Audit - Rollback Plan

## Rollback Steps

1. **Backend config**: Remove `"cwe"` entry from `defaultAgents()` in `backend/internal/config/config.go`
2. **Docker Compose**: Remove `agent-cwe` service block, remove `VULTURE_AGENT_CWE_URL` from backend environment, remove `agent-cwe` from backend `depends_on`
3. **Agent code**: Delete `agents/cwe/` directory
4. **Docs**: Delete `docs/features/0010_cwe_audit/` directory

## Risk Assessment
- **Low risk**: CWE agent is additive; removing it does not affect existing chaos, owasp, or soc2 agents
- **No database migrations**: No schema changes required for this feature
- **Frontend**: Auto-discovery means no frontend rollback needed
