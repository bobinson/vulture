# 0033 Finding Reference Numbers — Rollback Plan

## When to roll back

- Duplicate `ref_number` values appear under concurrent inserts.
- `ref_number` is stable but a later rescan reassigns a different ref to the same fingerprint.
- UI or CLI crashes because a finding has no lineage row yet and the ref lookup returns undefined.

## Revert order

1. **Frontend** — revert the two UI-side changes (they are the riskiest in terms of UX regression):
   - `frontend/src/components/results/FindingsTable.tsx` — restore the plain `<span>` rendering of `VLT-NNNN` (no `<button>` wrapper).
   - Dashboard and `AuditResults` pages — restore the plain `<span>` that renders the truncated audit ID.
   - Rebuild: `docker compose up -d --build frontend`.

2. **CLI** — revert the `Ref` field and the `fetchRefsBySourcePath` helper:
   - `cli/main.go` — remove `Ref`, `Fingerprint` fields from `finding`, the `lineageRec` struct, `fetchRefsBySourcePath`, and roll `cmdResults` back to the `fmt.Printf("  %d. [%s] %s\n", i+1, sev, f.Title)` form.
   - Rebuild: `cd cli && go build -o bin/vulture .`.

3. **Backend repository** — **do NOT** drop the `ref_number` column unless absolutely necessary. If you must:
   - `ALTER TABLE finding_lineage DROP COLUMN ref_number;` (Postgres).
   - SQLite: requires table rewrite — `CREATE TABLE finding_lineage_new AS SELECT (all-columns-except-ref_number) FROM finding_lineage; DROP TABLE finding_lineage; ALTER TABLE finding_lineage_new RENAME TO finding_lineage;`.
   - Revert repo code in `backend/internal/repository/sqlite_lineage_repo.go` and `postgres_lineage_repo.go` (the `SELECT COALESCE(MAX(ref_number), 0) + 1 FROM finding_lineage` block inside the insert transaction and the `ref_number` in SELECT/scan lists).
   - Revert model changes in `backend/internal/model/lineage.go`.

4. **MCP server** — if needed, remove the `ref` parameter from `vulture_update_status` and the `ref` field from enriched finding responses in `mcp/server.py`.

5. **Docs** — update `0033_implementation_status.md` to mark the feature rolled back, but keep the plan and rollback files for history.

## Data considerations

- Rolling back the Frontend+CLI tasks is fully safe. It only hides the ref from users.
- Rolling back the **database column** loses historical ref assignments — once dropped, a re-apply would assign fresh numbers starting from 1, which breaks any Jira tickets already quoting old refs. Only do this if the data is known-bad.
- The backfill query in migration 013 is idempotent when the column exists but has NULLs; re-running it is safe.

## Verification after rollback

- `curl /api/lineage?source_path=... | jq '.[0]'` — `ref` and `ref_number` should still be present if the DB column is kept; absent if dropped.
- `go test ./internal/repository/ -run TestLineageRef` — passes if model + repo changes kept, fails (expected) if model reverted.
- Playwright: reload audit page, confirm VLT column absent (or displaying plain spans only).
