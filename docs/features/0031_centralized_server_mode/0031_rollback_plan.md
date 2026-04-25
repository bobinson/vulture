# 0031 Centralized Audit Server — Rollback Plan

## Design principle

Every capability in this feature is **opt-in via env flag or request body field**. Dev-local deployments are unaffected by default. This means rollback is low-risk per-task.

## Per-task rollback

### Task 1-5: API keys (migration + model + repo + service + handler + middleware)
```bash
git revert <commit-hash-task-5>..<commit-hash-task-1>
```
- Migration 011 stays in place (adds an empty `api_keys` table — harmless).
- `VULTURE_API_KEYS_ENABLED` becomes a no-op.
- Clients using API keys: stop working. JWT auth still works for humans.

### Task 6: Webhooks
```bash
git revert <commit-hash-task-6>
```
- Migration 012 stays (adds column + table — harmless).
- Audit POSTs with `webhook_url` field: silently ignored.
- No existing user impact.

### Task 7: Git credentials
```bash
git revert <commit-hash-task-7>
```
- POSTs with `git_credentials` field: silently ignored.
- Public repos still clone via default server-side credentials.
- Private-repo CI flows: stop working; redeploy writer or revert.

### Task 8: Per-run source dirs
```bash
git revert <commit-hash-task-8>
```
- Source dirs revert to `/tmp/sources/<source-id>` (shared).
- **Regression risk:** concurrent scans of same repo may collide. Avoid reverting if you have concurrent CI scans in flight.

### Task 9: Rate limiting
```bash
git revert <commit-hash-task-9>
```
- API keys no longer throttled. Risk: single key can exhaust server.

### Task 10-11: CLI flags + api-key subcommand
```bash
git revert <commit-hash-task-11>..<commit-hash-task-10>
```
- Flags removed from CLI. Invocations using new flags fail with "unknown flag".
- Existing invocations unaffected.

### Task 12-14: Docs + CLAUDE.md
Documentation-only. Revert has zero runtime impact.

### Task 15: E2E test
Test-only. Revert removes one test file.

## Emergency full rollback

```bash
git revert --no-commit <commit-hash-task-15>..<commit-hash-task-1>
git commit -m "revert: 0031 centralized server mode"
```

Post-revert:
- Migrations 011 + 012 remain in the DB (tables + columns exist, are empty/unused).
- Drop them later if desired:
  ```sql
  DROP TABLE audit_webhook_deliveries;
  ALTER TABLE audits DROP COLUMN webhook_url;  -- Postgres; SQLite needs table-rebuild
  DROP TABLE api_keys;
  ```

## Data implications

- **No destructive migrations.** All changes add columns/tables; nothing drops or alters existing data.
- **API keys table:** if you revert and later re-apply, old keys remain valid (hashes unchanged).
- **Webhook deliveries:** historical delivery log persists in the DB even after code revert.

## Viewer VM (feature 0030) interaction

The readonly viewer already wraps write endpoints with `ReadOnlyGuard`. New endpoints (`/api/api-keys`) inherit this wrap — viewer correctly returns 503 for API key mutations. No viewer-side rollback needed.
