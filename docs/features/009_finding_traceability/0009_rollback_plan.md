# 009 Finding Lifecycle Traceability — Rollback Plan

## Rollback Steps

### Database
1. Drop new tables: `DROP TABLE IF EXISTS lineage_events; DROP TABLE IF EXISTS finding_lineage;`
2. Remove columns: `ALTER TABLE findings DROP COLUMN fingerprint;`
3. Remove columns: `ALTER TABLE sources DROP COLUMN git_branch, DROP COLUMN git_commit_hash, DROP COLUMN git_commit_short, DROP COLUMN git_remote_url;`
4. Delete migration file: `backend/migrations/004_finding_traceability.sql`

### Backend
1. Revert `model/source.go` — remove git fields
2. Revert `model/finding.go` — remove fingerprint field
3. Delete `model/lineage.go`
4. Revert `repository/audit_repo.go` — remove UpdateSourceGitInfo
5. Revert `repository/postgres_repo.go` — remove git columns from source CRUD, revert findings to 12 cols
6. Revert `repository/sqlite_repo.go` — same reverts + remove migrateAddColumns
7. Delete `repository/lineage_repo.go`, `postgres_lineage_repo.go`, `sqlite_lineage_repo.go`, `mock_lineage_repo.go`
8. Delete `service/lineage_service.go`
9. Delete `handler/lineage_handler.go`
10. Revert `handler/stream_handler.go` — remove fingerprint generation, lineage service field
11. Revert `server/server.go` — remove registerLineageRoutes call
12. Delete `pkg/gitutil/info.go`
13. Revert `service/source_service.go` — remove git info capture

### Frontend
1. Revert `lib/types.ts` — remove lineage types, fingerprint, git fields
2. Revert `lib/api.ts` — remove lineage API methods
3. Delete `components/results/FindingTimeline.tsx`
4. Delete `components/results/LineageStatusBadge.tsx`
5. Revert `components/results/FindingsTable.tsx` — remove status column and traceability section
6. Revert `pages/AuditResults.tsx` — remove git context
7. Revert all 6 locale files — remove `lineage` section

## Risk Assessment
- **Low risk**: All changes are additive (new tables, new columns with NULL defaults, new files)
- **No data loss**: Existing findings/audits/sources are not modified
- **Backward compatible**: Frontend gracefully handles missing lineage data
