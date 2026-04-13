# 0024 - Audit Report Traceability — Rollback Plan

## Risk Assessment

Low risk — all changes are additive. No existing functionality is removed or changed in behavior.

## Rollback Steps

### Backend

1. Remove comparison route from `server.go` (`isComparisonPath` check)
2. Remove `Compare()` and helper functions from `audit_handler.go`
3. Remove source path filter from `List()` in `audit_handler.go`
4. Remove `CrossAgentOrigins` field from `finding.go`
5. Remove `AuditComparison` structs from `audit.go`
6. Revert `deduplicateCrossAgent` changes in `stream_handler.go`
7. Remove new methods from `audit_repo.go`, `postgres_repo.go`, `sqlite_repo.go`, `mock_repo.go`
8. Remove `audit_comparison_test.go`

### Frontend

1. Remove new components: `GitContextHeader`, `FindingLifecycleBadge`, `CrossAgentBadge`, `ProveSummaryCard`, `CrossAgentSummary`, `AuditComparisonView`, `FixedFindingsList`, `AuditHistoryTimeline`
2. Remove new hooks: `useAuditComparison`, `useAuditHistory`
3. Revert `AuditResults.tsx` to previous version
4. Revert `FindingsTable.tsx` to previous version
5. Revert `ProveResults.tsx` to previous version
6. Remove new type definitions from `types.ts`
7. Remove new API methods from `api.ts`
8. Remove new i18n keys from all 6 locale files
9. Remove `e2e/audit-traceability.spec.ts`

### Database

No database schema changes — no migration rollback needed.

## Verification

```bash
cd backend && go test ./...
cd frontend && npm run build
```
