# 0040 — Implementation Status

**Branch**: tbd (recommend `feat/0040-auto-migration-runner`)
**Status**: PLANNED
**Owner**: tbd
**Started**: not started
**Target v1.0** (Phases 1.5+1+2+4+5): ~2 days
**Target v1.1** (Phases 3+6 + Prometheus counters): +1 day
**Target v1.2** (baseline squash): tracked as a separate follow-up feature
                                   (~0.5 day, after ~2 weeks of v1.1 stability)

## Phase summary

| Phase | Status | E2E green | v1.x | Notes |
|---|---|---|---|---|
| 1.5 — Idempotency audit + 011/012 type fixes | PLANNED | — | v1.0 | Every migration safely re-runnable |
| 1 — Runner core (`migrations/runner.go`) | PLANNED | — | v1.0 | Embedded SQL + `Apply()` + advisory lock |
| 2 — Wire into backend startup | PLANNED | — | v1.0 | Replaces inline DDL in `sqlite_repo.go`; both repos call `Apply()` |
| 3 — Baseline detection for existing volumes | PLANNED | — | v1.1 | Probe schema, populate `schema_migrations`, then continue |
| 4 — CI test for fresh-init migration replay | PLANNED | — | v1.0 | `.github/workflows/migrations.yml` |
| 5 — Remove `docker-entrypoint-initdb.d` mount | PLANNED | — | v1.0 | Compose change after Phase 2 lands |
| 6 — Authoring guide | PLANNED | — | v1.1 | `docs/guides/migration_authoring.md` |

## Detailed task list

### Phase 1.5 — Idempotency audit + fix

- [ ] 1.5.t1 — Apply pending fix: `011_api_keys.sql` `created_by TEXT → UUID`
- [ ] 1.5.t2 — Apply pending fix: `012_audit_webhooks.sql` `audit_id TEXT → UUID`
- [ ] 1.5.t3 — `001_init.sql`: switch all `CREATE TABLE` to `CREATE TABLE IF NOT EXISTS`; same for indexes
- [ ] 1.5.t4 — `002`-`014`: audit each file; convert `ALTER TABLE ... ADD COLUMN` to `... ADD COLUMN IF NOT EXISTS`; same for indexes/constraints
- [ ] 1.5.t5 — Verification: run each migration twice against a fresh Postgres; assert second run is a no-op
- [ ] 1.5.t6 — Verification: run each migration twice against a fresh SQLite; assert second run is a no-op

### Phase 1 — Runner core

#### 1.1 Package layout
- [ ] 1.1.t1 — Create `backend/internal/repository/migrations/migrations.go` with `//go:embed *.sql`
- [ ] 1.1.t2 — Move all 14 `.sql` files from `backend/migrations/` into the new package dir
- [ ] 1.1.t3 — Add `015_schema_migrations_table.sql` (creates the `schema_migrations` tracking table)
- [ ] 1.1.t4 — Delete the old `backend/migrations/` directory

#### 1.2 Runner implementation
- [ ] 1.2.t1 — Filename parser: `parseFilename("001_init.sql") → (1, "init")`; reject malformed names
- [ ] 1.2.t2 — Checksum: `sha256(fileContent)` → 64-char hex
- [ ] 1.2.t3 — Discover-and-sort: `discover(fs)` returns `[]Migration` sorted by version
- [ ] 1.2.t4 — `Apply(ctx, db, dialect)`:
  - [ ] Acquire advisory lock (Postgres) / no-op (SQLite)
  - [ ] Bootstrap `schema_migrations` table if missing
  - [ ] Read applied versions
  - [ ] Detect checksum drift on already-applied versions
  - [ ] For each pending: BEGIN, exec SQL, INSERT row, COMMIT
  - [ ] Release lock on return (Postgres)
- [ ] 1.2.t5 — Public API frozen: `Apply(ctx, db, dialect) error` and nothing else

#### 1.3 Unit tests (`runner_test.go`)
- [ ] 1.3.t1 — `TestApply_Empty` — fresh DB, 14 migrations, all applied
- [ ] 1.3.t2 — `TestApply_Idempotent` — second `Apply()` is a no-op
- [ ] 1.3.t3 — `TestApply_ChecksumDrift` — drift detection aborts with descriptive error
- [ ] 1.3.t4 — `TestApply_PartialFailure` — bad SQL on N → 1..N-1 applied, N rolled back, N+1 skipped
- [ ] 1.3.t5 — `TestApply_BaselineDetection` — populated DB without `schema_migrations` → baseline + apply pending only
- [ ] 1.3.t6 — `TestApply_AdvisoryLock_Postgres` — two concurrent calls; one wins, one waits, both succeed
- [ ] 1.3.t7 — `TestApply_ParseError_BadFilename` — filename `012b_typo.sql` aborts startup with "invalid filename" error
- [ ] 1.3.t8 — Coverage: `pytest`-equivalent for Go: 100% line coverage on `runner.go`

### Phase 2 — Wire into backend startup

- [ ] 2.1.t1 — `NewPostgresRepo`: call `migrations.Apply(ctx, db, migrations.Postgres)` after `Ping()`
- [ ] 2.1.t2 — `NewSQLiteRepo`: call `migrations.Apply(ctx, db, migrations.SQLite)` after open
- [ ] 2.1.t3 — Delete inline DDL block from `sqlite_repo.go:222-242`
- [ ] 2.1.t4 — `cmd/vulture/main.go`: surface `Apply()` errors with context (file/version named)
- [ ] 2.2.t1 — Smoke test: `go run ./cmd/vulture/ serve` against fresh Postgres → migrations apply, backend starts
- [ ] 2.2.t2 — Smoke test: `go run ./cmd/vulture/ serve` against fresh SQLite → migrations apply, backend starts
- [ ] 2.2.t3 — Smoke test: rerun against same DB → migrations skip, backend starts

### Phase 3 — Baseline detection

- [ ] 3.1.t1 — `detectBaseline(db, embeddedFiles)` — probe live schema, return highest applied version
- [ ] 3.1.t2 — Marker probe: each migration declares (or the runner infers) a 1-or-more "fingerprint" SQL probe (e.g., for 014: `SELECT 1 FROM information_schema.columns WHERE table_name='audits' AND column_name='degraded_reason'`)
- [ ] 3.1.t3 — On baseline detect: insert one `schema_migrations` row per detected version; log "baselined at v%d"
- [ ] 3.2.t1 — Test against simulated existing volumes (populated through 010 / 012 / 014)

### Phase 4 — CI

- [ ] 4.1.t1 — Create `.github/workflows/migrations.yml`
- [ ] 4.1.t2 — Job: spin up `pgvector/pgvector:pg17` service container
- [ ] 4.1.t3 — Job: run `go test ./internal/repository/migrations/... -tags=integration -count=1`
- [ ] 4.1.t4 — Job: assert `schema_migrations` row count == number of `*.sql` files in package
- [ ] 4.1.t5 — Job: grep container logs for `ERROR`; fail if any
- [ ] 4.2.t1 — Add a regression test that intentionally breaks 011's FK type to UUID-vs-TEXT and asserts CI fails

### Phase 5 — Remove compose mount

- [ ] 5.1.t1 — Delete `- ./backend/migrations:/docker-entrypoint-initdb.d` from `docker-compose.yml:12`
- [ ] 5.1.t2 — Same for `docker-compose.readonly.yml` (if present)
- [ ] 5.2.t1 — Manual E2E: `docker compose down -v && docker compose up -d` → backend container's logs show migrations applying via the runner; no errors in postgres container

### Phase 6 — Authoring guide

- [ ] 6.1.t1 — Write `docs/guides/migration_authoring.md`
- [ ] 6.1.t2 — Sections: filename grammar / idempotency rules / FK type-match rule / per-dialect notes / "verify on fresh Postgres" checklist
- [ ] 6.1.t3 — Cross-link from `CLAUDE.md` "Languages & Testing" section

## Cross-cutting

- [ ] CC.1 — TDD discipline: tests in Phase 1.3 written first; Phase 1.2 implementation makes them green
- [ ] CC.2 — No silent failures: every `Apply()` error surfaces a file name + underlying error
- [ ] CC.3 — Backwards-compat verified: existing Postgres volume populated through migration 010 still works (Phase 3)
- [ ] CC.4 — `cyclomatic complexity < 10` for all new functions (CLAUDE.md rule)
- [ ] CC.5 — `go vet ./...` clean for the new package

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-04-27 | Migration files embed via `//go:embed` rather than reading from disk at startup; works in any deployment, no external mount required. | spec |
| 2026-04-27 | One transaction per migration file. Allows partial-failure recovery without complex resume logic. | spec |
| 2026-04-27 | Tracking table named `schema_migrations` with `(version, name, checksum, applied_at)` columns. Standard convention; matches Rails / Flyway semantics that operators already know. | spec |
| 2026-04-27 | Postgres advisory lock with constant `0x564C545F4D49475F` ("VLT_MIG_") for concurrency control. SQLite needs nothing (single-process). | spec |
| 2026-04-27 | Down migrations are explicitly out of scope. Each feature's `<feature>_rollback_plan.md` is the authoritative rollback path. | spec |
| 2026-04-27 | Phase 1.5 idempotency audit precedes Phase 1 because baseline mode needs every migration to be safely re-runnable. | spec |
| 2026-04-27 | Phase 5 (compose mount removal) is part of v1.0, not deferred — leaving the dual-path mount + runner risks racing or version drift. | spec |
| 2026-04-28 | Do not ship `VULTURE_SKIP_MIGRATIONS` (or any equivalent escape hatch). The whole feature exists to eliminate "did someone remember to run migrations?" as a failure mode; a skip flag re-creates that bug pattern (forgotten flag → silent schema drift). CI controls migration state by importing the `migrations` package and calling `Apply()` directly. Disaster recovery is a `psql` operation, not a binary flag. Failed migrations must be loud. | spec |
| 2026-04-28 | Prometheus counters (applied / skipped / failed migrations) deferred to v1.1 polish. Useful but not load-bearing for v1.0. | spec |
| 2026-04-28 | Squash migrations 001..N into a single `0001_baseline.sql` once v1.1 has been stable in production for ~2 weeks. Tracked as a separate follow-up feature; the runner needs no changes to support it. | spec |

## Out of scope (tracked separately)

- Down migrations / `vulture migrate down` command.
- Schema diffing / drift detection between migrations and live schema.
- Online schema change tools (gh-ost, pt-osc) for zero-downtime large alters.
- A standalone `vulture migrate` CLI command (the auto-runner at startup
  covers every current need).
- A skip / bypass env var (explicit decision 2026-04-28: never).

## Planned follow-ups

- v1.2 baseline squash: consolidate `001..N` into `0001_baseline.sql` after
  ~2 weeks of v1.1 stability. Separate feature folder; the runner itself
  needs no changes to support it.
