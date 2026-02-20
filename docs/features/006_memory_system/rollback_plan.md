# Memory System - Rollback Plan

## Risk Assessment
- **Severity**: Low - Memory system is additive, not blocking
- **Blast radius**: Memory search and token optimization
- **Data loss risk**: None - memories are stored in PostgreSQL

## Rollback Steps

### 1. Disable Memory Storage
In `stream_handler.go`, comment out the `StoreFindingsAsMemories` call:
```go
// go svc.memoryService.StoreFindingsAsMemories(audit, findings)
```

### 2. Disable Token Optimization
In `agents/shared/shared/audit_runner.py`, set prior context to empty:
```python
prior_context = ""  # was: build_prior_context(codebase_path, agent_type)
```

### 3. Remove Memory UI (if needed)
In `App.tsx`, remove the `/memories` route. In `Sidebar.tsx`, remove the memories nav item.

### 4. Database Cleanup (if needed)
```sql
DROP TABLE IF EXISTS memory_edges;
DROP TABLE IF EXISTS audit_memories;
```

## Verification
1. Run existing audits - should work without memory context
2. Dashboard and audit results should be unaffected
3. SSE streaming should continue without token_savings events

## Recovery Time
- Disable: 2 minutes (comment out 2 lines)
- Full rollback: 10 minutes (remove routes + DB tables)
