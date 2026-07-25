# 0016 - Rollback Plan

## Database

The migration adds a column with a default value and an index. To rollback:

### PostgreSQL
```sql
DROP INDEX IF EXISTS idx_prove_fingerprint;
ALTER TABLE prove_results DROP COLUMN IF EXISTS fingerprint;
```

### SQLite
SQLite does not support `DROP COLUMN` in older versions. If rollback is needed, recreate the table without the column:
```sql
CREATE TABLE prove_results_backup AS SELECT id, audit_id, finding_id, status, evidence, iterations_used, staging_url, created_at FROM prove_results;
DROP TABLE prove_results;
ALTER TABLE prove_results_backup RENAME TO prove_results;
CREATE INDEX idx_prove_results_audit ON prove_results(audit_id);
CREATE INDEX idx_prove_results_finding ON prove_results(finding_id);
```

## Code

Revert changes to:
- `backend/internal/model/prove.go`
- `backend/internal/handler/stream_handler.go`
- `backend/internal/repository/audit_repo.go`
- `backend/internal/repository/postgres_prove_repo.go`
- `backend/internal/repository/sqlite_prove_repo.go`
- `backend/internal/repository/sqlite_repo.go`
- `backend/internal/service/prove_service.go`
- `backend/internal/handler/prove_handler.go`
- `backend/internal/server/server.go`
- `frontend/src/lib/types.ts`
- `frontend/src/lib/api.ts`
- `frontend/src/hooks/useLineage.ts`
- `frontend/src/components/results/ProveResults.tsx`
- All `frontend/src/i18n/locales/*.json` files

## Risk Assessment

- **Low risk**: The fingerprint column has a default empty string, so existing data is unaffected
- **No breaking changes**: The new API endpoint is additive; existing endpoints unchanged
- **Frontend graceful degradation**: The fingerprint field is optional; missing data shows "no history"
