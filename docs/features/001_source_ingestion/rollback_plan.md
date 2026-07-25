# Source Ingestion - Rollback Plan

## Triggers

Rollback should be initiated if any of the following occur after deployment:

- Source submission endpoint returns 500 errors for valid inputs
- Git clone operations hang or cause resource exhaustion
- File walk causes excessive disk I/O or memory usage
- SQLite source records are corrupted or inconsistent
- Local path validation allows access to restricted directories (security issue)

## Rollback Steps

### 1. Revert Code

```bash
git revert <commit-hash>  # Revert the source ingestion commit(s)
make build                 # Rebuild the Go backend
make docker-up             # Redeploy
```

### 2. Clean Up Temporary Files

```bash
# Remove any cloned repositories from the temporary directory
rm -rf /tmp/sources/*
```

### 3. Clean Up Database Records

If source records were written to SQLite and must be removed:

```sql
DELETE FROM sources WHERE created_at > '<deployment_timestamp>';
```

### 4. Restore Previous API Behavior

If the `POST /api/sources` endpoint did not previously exist, reverting the code removes it entirely. Downstream features (audit creation) that depend on source IDs will need to be paused until the fix is deployed.

## Verification

After rollback, verify:

- [ ] `GET /health` returns 200
- [ ] `POST /api/sources` returns 404 (endpoint removed) or functions correctly (if fix-forward)
- [ ] No orphaned files in `/tmp/sources/`
- [ ] SQLite database is consistent (no orphaned source records)
- [ ] Backend memory and CPU usage return to baseline
- [ ] E2E test suite passes on the reverted code
