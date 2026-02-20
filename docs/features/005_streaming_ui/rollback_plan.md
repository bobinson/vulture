# Streaming UI - Rollback Plan

## Triggers

Rollback should be initiated if any of the following occur:

- SSE connection fails to establish or drops repeatedly
- ag-ui events are not rendered correctly (missing findings, broken timeline)
- UI becomes unresponsive during streaming (memory leak, excessive re-renders)
- CopilotKit integration causes runtime errors
- Layout breaks on supported browsers (Chrome, Firefox, Safari, Edge)
- Accessibility violations that block user interaction

## Rollback Steps

### 1. Revert Frontend Code

```bash
git revert <commit-hash>
cd frontend && npm run build
make docker-up
```

### 2. Fallback to Polling (if streaming is broken)

If only SSE streaming is broken, a temporary fallback can poll `GET /api/audits/:id` at intervals:

```typescript
// Temporary polling fallback
useEffect(() => {
  const interval = setInterval(async () => {
    const audit = await fetchAudit(auditId);
    setState(audit);
  }, 2000);
  return () => clearInterval(interval);
}, [auditId]);
```

This loses real-time streaming but provides functional audit results.

### 3. Clear Browser Cache

If users experience stale UI after rollback, instruct them to hard-refresh (`Ctrl+Shift+R`) or clear the site cache.

## Verification

- [ ] Frontend loads without JavaScript errors
- [ ] Audit results page displays completed audit data
- [ ] SSE connection establishes (or polling fallback works)
- [ ] Findings table renders correctly
- [ ] No console errors in browser developer tools
- [ ] Playwright E2E tests pass on rolled-back code
