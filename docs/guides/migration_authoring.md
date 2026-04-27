# Authoring Postgres migrations

> **Audience**: anyone adding or modifying schema migrations under
> `backend/internal/repository/migrations/`.
>
> **Why this guide exists**: tonight's incident (2026-04-27) shipped two
> schema bugs (011 and 012) that broke fresh-Postgres deployments because
> SQLite — where they were tested — silently accepts type-mismatched FKs
> while Postgres rejects them. The bugs cost several hours of recovery on
> a fresh customer install. This guide encodes the rules that would have
> caught them at commit time.

## Filename grammar

```
NNN_descriptive_name.sql
```

- `NNN`: zero-padded integer ≥ 3 digits (`001`, `010`, `123`, `1234`). The
  runner sorts by parsed integer, not lexical order, so `100_x.sql`
  applies after `099_x.sql` regardless of how filenames sort.
- `descriptive_name`: lowercase ASCII, digits, underscores. No spaces, no
  uppercase, no hyphens.
- Extension must be exactly `.sql` (lowercase).

The runner rejects anything that doesn't match `^\d{3,}_[a-z0-9_]+\.sql$`
at startup with a descriptive error. Filenames like `012b_typo.sql` or
`015_BadName.sql` will abort the backend before any migration runs.

Two files with the same numeric version (e.g. `001_a.sql` + `001_b.sql`)
are also rejected — each version is unique.

## The migration runner

Migrations run automatically at backend startup, in version order, each
inside its own transaction:

1. Backend connects to Postgres (`NewPostgresRepo`).
2. Runner acquires the `0x564C545F4D49475F` advisory lock (serializes
   concurrent backend starts pointed at the same DB).
3. Runner ensures `schema_migrations` exists.
4. Runner verifies sha256 checksums of already-applied migrations match
   the embedded files (drift detection).
5. For each pending migration: BEGIN, exec the SQL, INSERT into
   `schema_migrations`, COMMIT. On failure, ROLLBACK and abort startup
   with `migration NNN_<name>: <underlying error>`.
6. Releases the advisory lock.

Implications for authors:

- **One transaction per file.** Don't author migrations that need
  multiple transactions — Postgres supports transactional DDL, use it.
  This means **no `CREATE INDEX CONCURRENTLY`** (it can't run inside a
  transaction). If you need concurrent index builds, do it via a manual
  ops procedure, not a migration.
- **Failure is loud.** A bad migration aborts backend startup with a
  named error; fix the SQL and redeploy.
- **Editing an applied migration is rejected.** Once a migration is
  applied to *any* deployed instance, it is frozen. Edit ⇒ checksum drift
  ⇒ backend refuses to start. To change schema, write a new migration
  with the next version number.

## Mandatory rule: idempotent DDL

Every statement must be safe to run twice. The runner skips already-applied
migrations via `schema_migrations`, but baseline-mode adoption of existing
volumes (and operational re-runs) depends on this.

| Bad | Good |
|---|---|
| `CREATE TABLE foo (...)` | `CREATE TABLE IF NOT EXISTS foo (...)` |
| `CREATE INDEX idx_x ON ...` | `CREATE INDEX IF NOT EXISTS idx_x ON ...` |
| `ALTER TABLE foo ADD COLUMN bar INT` | `ALTER TABLE foo ADD COLUMN IF NOT EXISTS bar INT` |
| `CREATE EXTENSION pgvector` | `CREATE EXTENSION IF NOT EXISTS pgvector` |

For statements that lack a native `IF NOT EXISTS`/`IF EXISTS` form (DROP
CONSTRAINT, ADD CONSTRAINT, etc.), wrap in a guarded `DO` block:

```sql
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'my_constraint') THEN
        ALTER TABLE my_table ADD CONSTRAINT my_constraint CHECK (...);
    END IF;
END $$;
```

For backfill `UPDATE` statements, guard with `WHERE col IS NULL` (or
similar) so a re-run doesn't overwrite operator-set values:

```sql
UPDATE my_table SET ref_number = ... WHERE ref_number IS NULL;
```

**Verify your migration is idempotent before committing.** Run it twice
against a fresh `pgvector/pgvector:pg17` container and confirm no errors
on the second run. The `migrations-replay` CI job does this automatically
on every PR — but local verification catches it 30 seconds earlier.

## Mandatory rule: FK column types must match referenced PK type

This is what bit us in 011 and 012. Postgres rejects `FOREIGN KEY` if the
column types don't match (`TEXT REFERENCES users(id)` where `users.id` is
`UUID` → `cannot be implemented`).

SQLite is permissive about this and won't error, so the migration looks
fine in dev. Postgres rejects it on first init.

**Rule**: when adding a column with `REFERENCES <table>(id)`, look up the
type of the referenced PK and use the same type:

| Referenced PK | FK column |
|---|---|
| `users.id UUID` | `created_by UUID NOT NULL REFERENCES users(id)` |
| `audits.id UUID` | `audit_id UUID NOT NULL REFERENCES audits(id)` |
| `findings.id TEXT` | `finding_id TEXT NOT NULL REFERENCES findings(id)` |

Look up the PK definition in `001_init.sql` (or wherever the table was
created) before authoring the FK.

## Recommended: authoring checklist

Before opening the PR:

- [ ] Filename matches `NNN_descriptive_name.sql` grammar.
- [ ] Version number is the next unused integer (no gaps, no duplicates).
- [ ] Every DDL statement uses `IF NOT EXISTS` / `IF EXISTS` or a guarded
      `DO` block.
- [ ] Every FK column type matches its referenced PK type.
- [ ] Backfill UPDATEs are guarded so re-running doesn't overwrite data.
- [ ] No `CREATE INDEX CONCURRENTLY` (transaction-incompatible).
- [ ] You ran the migration twice locally against
      `pgvector/pgvector:pg17` and confirmed no errors on the second run:
      ```bash
      docker run -d --name pg-test --rm -p 25439:5432 \
        -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test \
        pgvector/pgvector:pg17
      until docker exec pg-test pg_isready -U test >/dev/null 2>&1; do sleep 1; done
      cd backend/internal/repository/migrations
      for run in 1 2; do
        echo "=== run $run ==="
        for f in $(ls *.sql | sort); do
          docker exec -i pg-test psql -U test -d test -v ON_ERROR_STOP=1 < "$f" \
            2>&1 | grep -E "^ERROR|^FATAL" && echo "FAIL $f run $run"
        done
      done
      docker rm -f pg-test
      ```
- [ ] The integration test passes against your migration:
      ```bash
      POSTGRES_TEST_DSN='postgres://test:test@localhost:25439/test?sslmode=disable' \
        go test -tags=integration ./internal/repository/migrations/ -count=1
      ```

CI's `migrations-replay` workflow (`.github/workflows/migrations.yml`)
runs an equivalent pipeline on every PR.

## SQLite parity

Vulture supports SQLite as a local-dev fallback. The SQLite schema is
managed by the inline `migrate()` function in
`backend/internal/repository/sqlite_repo.go`, **not** by the migration
runner. This is intentional — the SQLite schema diverges from Postgres
in fundamental ways (`TEXT` IDs vs `UUID`, no `vector` columns, no
`uuid-ossp` / `pg_trgm` extensions), and unifying them would require
dialect-aware migrations.

When you add a Postgres migration, you typically also need to update
`migrate()` / `migrateAddColumns()` in `sqlite_repo.go` so SQLite has a
parallel column or table. There's no automated check for this parity —
review carefully.

A future feature (post-v1.1 of 0040) will unify the two paths, but for
now they're maintained separately.

## Rollback

The migration runner has no built-in down-migrations. To roll back a
schema change in production:

1. Author a new forward migration that reverses the change (e.g. `DROP
   COLUMN IF EXISTS`).
2. Or — for more invasive rollbacks — follow the per-feature
   `<NNNN>_rollback_plan.md` document that the feature owner authored.

Rollback by deleting an applied migration's row from `schema_migrations`
is **not** supported and will trigger checksum drift detection on the
next startup (the file checksum won't match a non-existent row, but if
you also delete the file the runner won't know it ever existed).

## Common patterns

### Adding a column

```sql
-- 0NN_add_widget_count.sql
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS count INTEGER NOT NULL DEFAULT 0;
```

### Adding an index

```sql
-- 0NN_widget_index.sql
CREATE INDEX IF NOT EXISTS idx_widgets_owner ON widgets (owner_id);
```

### Adding a table with FK

```sql
-- 0NN_widget_audits.sql
CREATE TABLE IF NOT EXISTS widget_audits (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    widget_id   UUID NOT NULL REFERENCES widgets(id) ON DELETE CASCADE,
    -- ^ widget.id is UUID — match it exactly
    event       VARCHAR(50) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_widget_audits_widget ON widget_audits (widget_id);
```

### Adding a constraint to an existing table

```sql
-- 0NN_widgets_check_count.sql
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'widgets_count_nonneg') THEN
        ALTER TABLE widgets ADD CONSTRAINT widgets_count_nonneg CHECK (count >= 0);
    END IF;
END $$;
```

### Backfill data

```sql
-- 0NN_widgets_backfill_status.sql
ALTER TABLE widgets ADD COLUMN IF NOT EXISTS status TEXT;

UPDATE widgets SET status = 'active' WHERE status IS NULL;
-- ^ guard with IS NULL so re-runs don't overwrite operator-set values
```

## Reference

- Runner source: `backend/internal/repository/migrations/runner.go`
- Migration files: `backend/internal/repository/migrations/*.sql`
- CI workflow: `.github/workflows/migrations.yml`
- Feature plan: `docs/features/0040_auto_migration_runner/`
