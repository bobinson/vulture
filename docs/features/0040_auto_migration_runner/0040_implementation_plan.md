# 0040 — Auto-Migration Runner (Postgres + SQLite)

**Author**: tbd
**Status**: PLANNED
**Created**: 2026-04-27

## Problem

Vulture's Postgres schema currently relies on the `pgvector/pgvector:pg17` Docker
image's standard entrypoint to apply migrations. The compose file mounts
`./backend/migrations` to `/docker-entrypoint-initdb.d`, and on container init
the entrypoint scans that directory and runs every `*.sql` file in alphabetical
order. There is no migration runner inside the Go backend itself.

This has three concrete failure modes that bit deployments tonight (2026-04-27):

1. **`docker-entrypoint-initdb.d` only runs on a fresh data volume.** Any schema
   bump applied after the volume is created is silently ignored — the container
   logs `PostgreSQL Database directory appears to contain a database; Skipping
   initialization` and starts up serving the old schema. The Go backend then
   issues queries referencing columns that don't exist and 500s with `pq: column
   "<x>" of relation "audits" does not exist`. (Hit twice tonight: `webhook_url`
   from migration 012, then `degraded_reason` from migration 014.)

2. **The entrypoint aborts mid-replay on the first error and leaves the data
   directory half-initialized.** Tonight's session caught two distinct schema
   bugs because of this:
   - `011_api_keys.sql` had `created_by TEXT REFERENCES users(id)` while
     `users.id` is `UUID` — Postgres rejects mismatched-type FKs.
   - `012_audit_webhooks.sql` had the same pattern: `audit_id TEXT REFERENCES
     audits(id)` against `audits.id UUID`.

   Each failure aborted init, leaving migrations 011-14 (then 013-14) unapplied.
   Worse: on next start, the entrypoint sees a non-empty data dir, prints
   `Skipping initialization`, and never retries. The only recovery is `docker
   compose down -v` (drop the volume), which is unsafe in production.

3. **SQLite has its own divergent path.** `backend/internal/repository/sqlite_repo.go:222-242`
   contains hand-written, idempotent `CREATE TABLE IF NOT EXISTS` and `ALTER
   TABLE ADD COLUMN` statements that mirror — but don't strictly equal — the
   Postgres migrations. The two paths drift independently. SQLite is permissive
   about FK column types, so 011 and 012 silently worked on SQLite while
   silently failing on Postgres. The same kind of drift will recur every time a
   migration adds a non-trivial constraint.

The fix is to add a real migration runner inside the Go backend that applies
schema changes deterministically at startup, tracks applied versions in a
`schema_migrations` table, and works identically against Postgres and SQLite.

## Goals

1. **Single source of truth for Postgres**: schema changes live in
   `backend/internal/repository/migrations/*.sql`; the runner applies
   them at startup. Read-only viewer mode (feature 0030 / mode C) opens
   via `NewPostgresRepoReadOnly` and skips migration application —
   writers own the schema.
   *(SQLite unification was descoped from v1.0 — see decision log entry
   2026-04-28. The SQLite schema in `sqlite_repo.go::migrate()` diverges
   fundamentally from Postgres (TEXT vs UUID, no `vector`, no
   `uuid-ossp`/`pg_trgm`), and unifying would require dialect-aware
   migrations. Tracked as a follow-up feature.)*
2. **Idempotent + safe at startup**: backend startup blocks on migrations.
   Concurrent backends serialize via an advisory lock pinned to a single
   connection.
3. **Compatible with existing deployments**: existing Postgres volumes that
   already have N migrations applied via `docker-entrypoint-initdb.d` keep
   working. The runner detects "already applied" and writes the historical
   versions to `schema_migrations` once, then takes over for future versions.
4. **Fail loud, not silent**: a migration failure aborts startup with a clear
   error message naming the file and the underlying SQL error. No more silent
   "skipping initialization" with the backend serving a half-applied schema.
5. **CI catches schema bugs before they ship**: a CI job spins up a fresh
   Postgres container, runs the backend against it, and asserts every migration
   applies cleanly. Tonight's 011/012 type-mismatch bugs would have been caught
   the first time they were committed.

## Non-goals

- **Down-migrations / migration rollback.** Vulture already maintains
  `<feature>_rollback_plan.md` per feature; that's the right granularity for
  reverting schema changes. A generic `migrate down` system invites footguns
  (data loss on `DROP COLUMN`) without solving anything we currently lack.
- **Migration squashing.** Useful eventually but not load-bearing for fixing
  tonight's failure mode.
- **Schema diffing / drift detection.** A migration runner verifies migrations
  ran; it does not verify the live DB matches what the migrations describe.
  Out of scope.
- **Online schema change tools (gh-ost / pt-osc style).** Vulture's tables are
  small (single-tenant per deployment); plain `ALTER TABLE` is fine. If we
  outgrow this, revisit.

## Design

### Embedded migration files

Migration `.sql` files are embedded into the Go binary via `//go:embed`:

```go
// backend/internal/repository/migrations/migrations.go
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
```

Files move from `backend/migrations/` into `backend/internal/repository/migrations/`
so they're co-located with the runner and naturally embedded. The compose
`docker-entrypoint-initdb.d` mount becomes redundant and is removed in Phase 5.

Filename grammar: `NNN_<description>.sql` where `NNN` is a zero-padded integer
version (e.g., `015_my_change.sql`). The runner sorts by version, not by
filename. Files that don't match the grammar are rejected at startup.

### `schema_migrations` table

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    checksum    VARCHAR(64) NOT NULL,           -- sha256 of file content
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

(Adapt `TIMESTAMPTZ` → `TEXT NOT NULL` for SQLite, same way `sqlite_repo.go`
already does.)

The `checksum` field detects "someone edited an already-applied migration"
silently — at startup, the runner verifies that the checksum of each applied
version still matches the file on disk. Mismatch = abort with a clear error.
This catches the foot-shape where a developer edits `001_init.sql` to fix a
typo and ships it; existing deployments would silently disagree about what
"version 1" means.

### Runner algorithm

```
ApplyMigrations(db, fs):
    LOCK:
        Postgres: SELECT pg_advisory_lock(0x564C545F4D49475F)  // 'VLT_MIG_'
        SQLite:   no lock needed (single-process)
    DEFER UNLOCK

    EXEC: CREATE TABLE IF NOT EXISTS schema_migrations (...)

    discovered = parse(fs.ReadDir())            // sorted by version
    applied    = SELECT version, checksum FROM schema_migrations

    for m in discovered:
        if m.version in applied:
            if applied[m.version].checksum != m.checksum:
                ABORT: "migration %d checksum drift: file=%s db=%s" % (m.version, m.checksum, applied[m.version].checksum)
            continue

        BEGIN TRANSACTION
        try:
            EXEC m.sql
            INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (...)
            COMMIT
            log("applied migration %d: %s" % (m.version, m.name))
        except E:
            ROLLBACK
            ABORT: "migration %d (%s) failed: %s" % (m.version, m.name, E)
```

Notes:

- **Postgres advisory lock**: a 64-bit constant chosen so two backend instances
  can't apply migrations concurrently. Released on disconnect (defer + connection
  cleanup). One backend wins; others wait, then no-op when they see the
  migrations are already applied.
- **SQLite locking**: SQLite's WAL mode + `BEGIN IMMEDIATE` gives us exclusive
  write, but local-mode is single-process anyway. No advisory lock needed.
- **Transaction granularity**: one transaction per migration. If migration N
  errors mid-statement, only that migration rolls back; migrations 1..N-1 stay
  applied. Migration N+1 is not attempted. Operator fixes the SQL, restarts,
  runner picks up where it left off.
- **DDL transactions caveat**: Postgres supports transactional DDL; SQLite
  mostly does. A migration that mixes DDL with seed data is fine. A migration
  that runs `CREATE INDEX CONCURRENTLY` (no transaction allowed) is not — flag
  that in `docs/guides/migration_authoring.md` and don't use it for a while.

### Baseline for existing deployments

Existing Postgres volumes have migrations 001-N already applied via the old
entrypoint mount, but no `schema_migrations` table to record that. On first
startup of the new runner against such a DB:

1. Check whether `schema_migrations` exists. If yes → take the normal path.
2. If no → enter "baseline mode":
   - Probe the live schema for marker columns (e.g., presence of
     `audits.degraded_reason` indicates ≥014 was applied; presence of
     `audit_webhook_deliveries` indicates ≥012; etc.).
   - For each migration, ask: "could this migration be re-applied without
     error?". If yes, just run it (the `IF NOT EXISTS` clauses make it a
     no-op). If no — i.e., the migration uses non-idempotent DDL like plain
     `CREATE TABLE foo` — fall back to marker probing.
   - Insert one row per detected version into `schema_migrations`.
3. Then proceed normally.

Phase 1.5 (audit + idempotify migrations) makes this strategy reliable. After
that audit, every existing migration is safe to re-run, and baseline mode
collapses to "run them all, no-op on already-applied state, record in
`schema_migrations`."

Forward-only migrations after Phase 1.5 must be authored idempotently per the
new authoring guide.

### File reorganization

```
backend/
  migrations/                                  # DELETED (moved)
  internal/
    repository/
      migrations/                              # NEW
        migrations.go                          # //go:embed *.sql + parser
        runner.go                              # ApplyMigrations()
        runner_test.go                         # unit tests
        001_init.sql                           # moved
        002_flexible_embeddings.sql            # moved
        ...
        014_audit_degraded_reason.sql          # moved
        015_schema_migrations_table.sql        # NEW (bootstrap)
      postgres_repo.go                         # NewPostgresRepo() calls ApplyMigrations
      sqlite_repo.go                           # NewSQLiteRepo() calls ApplyMigrations;
                                               # delete the inline CREATE TABLE block
docker-compose.yml                             # remove migrations volume mount (Phase 5)
docker-compose.readonly.yml                    # ditto
.github/workflows/migrations.yml               # NEW (Phase 4 CI)
docs/guides/migration_authoring.md             # NEW
```

### Public API

```go
// backend/internal/repository/migrations/runner.go
package migrations

// Apply runs all pending migrations against db, recording results in
// schema_migrations. Idempotent: re-running with no pending migrations is
// a no-op. Returns nil on success; any non-nil error means startup must
// abort.
func Apply(ctx context.Context, db *sql.DB, dialect Dialect) error

type Dialect int
const (
    Postgres Dialect = iota
    SQLite
)
```

Called from:

```go
// backend/internal/repository/postgres_repo.go
func NewPostgresRepo(dsn string) (*PostgresRepo, error) {
    db, err := sql.Open("postgres", dsn)
    if err != nil { return nil, err }
    if err := db.Ping(); err != nil { return nil, err }
    if err := migrations.Apply(context.Background(), db, migrations.Postgres); err != nil {
        return nil, fmt.Errorf("apply migrations: %w", err)
    }
    return &PostgresRepo{db: db}, nil
}
```

(Same for `NewSQLiteRepo`.)

### Configuration

No environment variables. The auto-apply-on-startup behavior is correct for
every deployment mode (A/B/C/D), and there is intentionally no escape hatch.

Why no skip flag: the feature exists to eliminate "did someone remember to run
migrations?" as a failure mode. An env var that disables the runner re-creates
that exact bug pattern (operator sets it for a 10-minute hot fix, forgets to
unset, schema drift accumulates silently, future binary 500s in production).

CI / test scenarios that need control over migration state import the
`migrations` package directly and call `Apply()` against a test DB handle —
no production-risky env var needed. Disaster recovery is a `psql` operation,
not a binary flag: operator stops the binary, patches the DB by hand, inserts
a `schema_migrations` row to record the fixup, restarts. Failed migrations
must be loud, not skippable.

## Phases

### Phase 1.5 — Idempotency audit + fix

**Why first**: every migration needs to be safely re-runnable for baseline mode
to work and for the runner to converge on existing volumes.

**Tasks**:

- Audit every migration `001_init.sql`...`014_audit_degraded_reason.sql`:
  - `CREATE TABLE` → `CREATE TABLE IF NOT EXISTS`
  - `CREATE INDEX` → `CREATE INDEX IF NOT EXISTS`
  - `CREATE EXTENSION` → already idempotent in Postgres; verify
  - `ALTER TABLE ... ADD COLUMN` → `ADD COLUMN IF NOT EXISTS`
  - `ALTER TABLE ... ADD CONSTRAINT` → wrap in
    `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='X')
    THEN ALTER TABLE ... ADD CONSTRAINT X ...; END IF; END $$;`
  - Plain `INSERT INTO` seed data → `INSERT ... ON CONFLICT DO NOTHING`
- For each migration, manually run it twice against a fresh Postgres and
  confirm second run is a no-op (no errors, no row count change for seed data).

**Pre-existing schema bugs uncovered tonight stay fixed in this phase:**

- `011_api_keys.sql:7`: `created_by` already changed `TEXT → UUID` (commit pending).
- `012_audit_webhooks.sql:6`: `audit_id` already changed `TEXT → UUID` (commit pending).

These two changes are part of the Phase 1.5 commit. They're load-bearing for
the runner because Phase 1.5 verifies "every migration applies cleanly to a
fresh Postgres", which gates Phase 4's CI test.

### Phase 1 — Runner core

- Create `backend/internal/repository/migrations/` package with embedded SQL.
- Move all 14 existing `.sql` files into the package (delete from
  `backend/migrations/`).
- Implement `Apply(ctx, db, dialect)` with the algorithm above.
- Add migration `015_schema_migrations_table.sql` that creates the tracking
  table. (The runner needs this table to exist before it can record the
  versions it applied, so the runner has special-case logic to apply 015 first
  if `schema_migrations` doesn't exist yet.)
- Unit tests: `runner_test.go` covers happy path, checksum-drift detection,
  failed-mid-batch transaction rollback, advisory-lock contention, baseline
  mode against a populated DB.

### Phase 2 — Wire into backend startup

- `NewPostgresRepo` and `NewSQLiteRepo` call `Apply()` after `Ping()`.
- Remove the inline `CREATE TABLE`/`ALTER TABLE` blocks from
  `sqlite_repo.go:222-242`. The runner is now authoritative for both dialects.
- `cmd/vulture/main.go` propagates `Apply()` errors into a non-zero exit code
  with a clear human-readable message.

### Phase 3 — Baseline migration table for existing volumes

- On first run against an existing volume: probe schema, populate
  `schema_migrations` with detected versions, then proceed.
- Test: spin up old-version Postgres, populate via `docker-entrypoint-initdb.d`
  through (e.g.) migration 010, then run new backend → it should detect 1..10
  applied, then apply 11..15 cleanly.

### Phase 4 — CI test

- New GitHub Actions workflow `.github/workflows/migrations.yml`:
  - Spin up `pgvector/pgvector:pg17` against ephemeral volume.
  - Run `go test ./internal/repository/migrations/... -tags=integration` which
    pings the DB and runs `Apply()` end-to-end.
  - Assert no errors in container logs.
  - Assert `schema_migrations` row count equals number of files in the
    migrations dir.

This catches the next 011/012-style FK type mismatch the moment it's committed.

### Phase 5 — Remove docker-entrypoint mount

- Delete `./backend/migrations:/docker-entrypoint-initdb.d` from
  `docker-compose.yml` line 12.
- Same for `docker-compose.readonly.yml` if present.
- Backends apply migrations themselves now; the mount is redundant and
  actively harmful (re-applying via two paths can race or apply at different
  versions).

### Phase 6 — Authoring guide

- `docs/guides/migration_authoring.md`:
  - Filename grammar.
  - Idempotency rules (every DDL must use `IF NOT EXISTS` or be guarded).
  - One transaction per file; no `CREATE INDEX CONCURRENTLY` for now.
  - Type-match rule for FKs (this is what tonight's bugs violated).
  - "Verify on fresh Postgres before committing" checklist.
  - How to write a migration that is also a SQLite no-op when needed
    (e.g., guarded `CREATE EXTENSION` for pgvector).

## Tests

| Layer | Test | Asserts |
|---|---|---|
| Unit (Go) | `runner_test.go::TestApply_Empty` | Empty DB + 14 migrations → all 14 applied; `schema_migrations` has 14 rows |
| Unit (Go) | `runner_test.go::TestApply_Idempotent` | Apply twice → second run does nothing; no errors |
| Unit (Go) | `runner_test.go::TestApply_ChecksumDrift` | DB has v3 with checksum X; file v3 has checksum Y → abort with descriptive error |
| Unit (Go) | `runner_test.go::TestApply_PartialFailure` | Migration 7 has bad SQL → migrations 1..6 applied, 7 rolled back, 8+ skipped, error message names file 7 |
| Unit (Go) | `runner_test.go::TestApply_BaselineDetection` | Existing populated DB without `schema_migrations` → runner detects current version, populates table, applies new migrations only |
| Unit (Go) | `runner_test.go::TestApply_AdvisoryLock_Postgres` | Two concurrent `Apply()` calls → one wins; the other waits; both return nil |
| Integration | CI workflow `.github/workflows/migrations.yml` | Fresh Postgres + backend startup → all migrations apply, no errors in logs, `schema_migrations` populated |
| Manual | E2E with real Postgres compose stack | `docker compose down -v && docker compose up -d` works without `/docker-entrypoint-initdb.d` mount |

## Performance

- Each migration is ~10ms-100ms (small schema, no large backfills today).
- Total startup overhead: ~500ms on a fresh DB (14 migrations + advisory lock).
- On subsequent starts: one `SELECT version FROM schema_migrations` ≈ 1ms.

Acceptable. Backend startup is already several seconds (agent registration,
pgvector init, etc.).

## Risks

| Risk | Mitigation |
|---|---|
| Two backends race on first migration apply | Postgres advisory lock; SQLite is single-process |
| Operator edits an applied migration in-place | Checksum drift detection aborts startup with a clear error |
| Migration file accidentally numbered out-of-order (e.g., 012b) | Filename grammar enforced at startup; reject `012b_*.sql` |
| Existing prod Postgres has subtly different schema than what migrations describe | Phase 3 baseline detection handles standard cases. For edge cases, doc says: dump schema, manually pre-populate `schema_migrations`, restart. |
| `Apply()` hangs forever on advisory-lock | 30s timeout; abort startup if lock not acquired (suggests a stuck previous instance) |
| SQLite locking issue between auto-migrator and existing inline DDL during Phase 2 cutover | Phase 2 deletes the inline DDL in the same commit that adds the `Apply()` call; no overlap |

## Planned follow-up: v1.2 baseline squash

Once v1.1 is stable in production for ~2 weeks, squash migrations 001..014
(plus whichever 015+ have shipped by then) into a single `0001_baseline.sql`
that captures the current schema as the new starting point. Mark the squash
itself as "applied" for any existing `schema_migrations` rows that already
recorded the squashed-out versions.

Squashing keeps the migration directory tractable and removes the historical
warts (e.g., the original `001_init.sql` had `CREATE TABLE` without
`IF NOT EXISTS`, then 011/012's FK type bugs, etc.) without losing any live
schema state. The runner needs no changes — it just sees `0001_baseline.sql`
plus any post-squash migrations.

This is a separate feature (likely 0042 or whatever's free at the time) but
explicitly tracked here as load-bearing for the long-term ergonomics of the
auto-migration system.

## Other out-of-scope follow-ups

- Add Prometheus counter for migrations applied per startup. Deferred to v1.1
  polish — useful but not load-bearing.
- A `vulture migrate` CLI command for manual control in CI / disaster
  recovery. Currently no concrete need; auto-apply on startup covers
  everything.

## Open questions

- Should the runner refuse to start if `schema_migrations` shows versions
  greater than the embedded files (i.e., DB is ahead of binary, suggesting an
  accidental rollback to an older binary)? Lean yes — abort with "DB is at
  v17 but binary only knows v16; refusing to start to avoid corruption."
- Should we ship a `--auto-baseline` flag for the first deploy of the runner
  on existing Postgres, or always auto-detect? Lean auto-detect; it's safe
  given Phase 1.5's idempotency audit.
- Should we extract the runner into a separate small repo for reuse? No —
  it's small, project-specific, and the `embed.FS` makes it harder to share
  cleanly. Keep it in-tree.
