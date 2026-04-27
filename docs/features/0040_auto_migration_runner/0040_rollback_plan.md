# 0040 — Rollback Plan

This document describes how to revert feature 0040 (auto-migration runner)
cleanly, partially or fully, depending on which phases have shipped at the
time of rollback.

The general principle: this feature changes *how* migrations are applied,
not *what* schema looks like. So rolling back the feature must not lose any
schema state — only switch the application path back to the previous
docker-entrypoint-based one.

## Pre-flight before rolling back

1. Identify which phases are live in the deployment you're rolling back.
   Read `0040_implementation_status.md` for the canonical state, and the
   binary's git SHA via `vulture version`.
2. Snapshot the live `schema_migrations` table:
   ```bash
   docker compose exec postgres pg_dump -U vulture -d vulture -t schema_migrations \
     > schema_migrations_backup_$(date +%Y%m%d_%H%M%S).sql
   ```
3. Snapshot the full Postgres data volume:
   ```bash
   docker run --rm -v vulture_pgdata:/data -v "$PWD":/backup alpine \
     tar czf /backup/pgdata_backup_$(date +%Y%m%d_%H%M%S).tgz /data
   ```

## Rollback by phase (newest first)

### Phase 6 — Authoring guide

- Delete `docs/guides/migration_authoring.md`.
- Revert any `CLAUDE.md` cross-link added in 6.1.t3.

No schema or runtime impact. Pure documentation.

### Phase 5 — Compose mount removal

This phase deletes the `./backend/migrations:/docker-entrypoint-initdb.d`
mount. Rolling it back means re-adding the mount.

- Restore the deleted lines in `docker-compose.yml`:
  ```yaml
  volumes:
    - ./backend/migrations:/docker-entrypoint-initdb.d
  ```
- Same for `docker-compose.readonly.yml` if it was modified.
- Keep `backend/migrations/` populated as a directory containing the embedded
  `.sql` files (a symlink to `backend/internal/repository/migrations/` works).

After the mount is restored, **fresh** Postgres volumes will be initialized
both via the entrypoint mount AND by the runner at backend startup. With
idempotent migrations (Phase 1.5), this is safe — the runner will see
already-applied schema and only record the versions in `schema_migrations`.

### Phase 4 — CI workflow

- Delete `.github/workflows/migrations.yml`.

No production impact. CI loses the migration-replay regression test.

### Phase 3 — Baseline detection

This is purely additive logic in the runner. Rolling it back leaves Phase 1+2
intact but means the runner can no longer adopt existing volumes.

- In `backend/internal/repository/migrations/runner.go`, remove the
  `detectBaseline()` call from `Apply()`.
- For deployments that need to roll back AND have an existing populated
  Postgres volume that was relying on baseline detection: manually populate
  `schema_migrations` from the snapshot taken in pre-flight, then proceed.

### Phase 2 — Wire into backend startup

This is the most invasive phase to roll back, because Phase 2 also deletes
the inline `CREATE TABLE`/`ALTER TABLE` block from `sqlite_repo.go`. Rolling
back Phase 2 without rolling back Phase 1 is unusual; typically you roll back
both together.

- Restore the inline DDL block in `sqlite_repo.go` (revert the deletion at
  lines ~222-242 from the Phase 2 commit).
- Remove the `migrations.Apply(...)` calls from `NewPostgresRepo` and
  `NewSQLiteRepo`.
- For Postgres: the only way migrations get applied is back to being the
  `docker-entrypoint-initdb.d` mount on fresh init. **Existing volumes that
  had Phase 2 active and then rolled back will still have the
  `schema_migrations` table — leave it; it's harmless.**

### Phase 1 — Runner core

If Phase 2 has already been rolled back, removing Phase 1 is a clean revert
of the package:

- Delete `backend/internal/repository/migrations/` entirely.
- Restore `backend/migrations/` (move the `.sql` files back, drop the new
  `015_schema_migrations_table.sql`).
- Drop the `schema_migrations` table from any DB that still has it (optional
  — dropping the table is non-destructive since no application code reads
  from it after Phase 1+2 are gone):
  ```sql
  DROP TABLE IF EXISTS schema_migrations;
  ```

### Phase 1.5 — Idempotency audit + 011/012 type fixes

The 011 and 012 type fixes (`TEXT → UUID`) are independent schema bug fixes
that were already needed regardless of feature 0040. **Do not roll those back.**

The idempotency conversions (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT
EXISTS`, etc.) are pure no-op refinements when applied against a fresh
Postgres — they don't change any schema, only make the migration files
re-runnable. Safe to leave applied.

If for some reason you need to revert Phase 1.5 specifically (e.g., a
migration was rewritten in a way that broke it on a particular Postgres
extension version):

- `git revert` the Phase 1.5 commit.
- Verify the live schema still matches the migrations after the revert.

## Full rollback (all phases)

The cleanest path:

1. `git revert` all feature 0040 commits in reverse order (Phase 6 → 5 → 4 → 3
   → 2 → 1 → 1.5).
2. Restore `docker-compose.yml`'s `docker-entrypoint-initdb.d` mount.
3. On each deployed Postgres:
   ```sql
   DROP TABLE IF EXISTS schema_migrations;
   ```
   (Optional — leaving the table is harmless.)
4. Run the previous-version backend binary against the existing volume. It
   should start cleanly because Postgres still has the schema applied; the
   only thing missing is the `schema_migrations` row history, which the old
   binary doesn't read.

## Schema-level rollback (separate concern)

Feature 0040 does **not** undo any schema changes from migrations 001..014.
Those are owned by their respective `<feature>_rollback_plan.md` documents
(e.g., 0031's rollback for migrations 011-013, 0039's for migration 014).

If a deployment needs to roll back the *schema* (not the *runner*), follow
the per-feature rollback plan, then pull a binary that doesn't know about
the rolled-back migrations. The auto-migration runner will refuse to start
if the binary is older than the live `schema_migrations` (per the design
note in `0040_implementation_plan.md`'s open questions: "DB is at v17 but
binary only knows v16; refusing to start to avoid corruption."). You'll
need to either:

- Drop the now-too-new rows from `schema_migrations` manually, OR
- Run the rollback DDL manually (per the feature rollback plan) and then
  also DELETE the corresponding rows from `schema_migrations`.

This is intentional — the runner's strictness here prevents accidental
schema corruption from version-skew during operator mistakes.

## Smoke checks after any rollback

```bash
# 1) Backend starts and accepts requests
curl -fsS http://localhost:28080/health

# 2) audits table has the columns the binary expects
docker compose exec postgres psql -U vulture -d vulture -p 25432 \
  -c "\d audits" | grep -E 'webhook_url|degraded_reason'

# 3) A trivial audit succeeds end-to-end
~/src/vulture/cli/bin/vulture scan . --exit-on critical
```

If any of these fails, restore from the pgdata snapshot taken in pre-flight.
