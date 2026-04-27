package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// advisoryLockKey is the Postgres advisory-lock identifier the runner
// uses to serialize concurrent backend startups against the same DB.
// The value is "VLT_MIG_" interpreted as a big-endian 64-bit integer —
// chosen so it's unlikely to collide with any application-level
// advisory lock anyone else might use against the same DB.
const advisoryLockKey int64 = 0x564C545F4D49475F

// lockAcquireTimeout caps how long Apply waits to acquire the advisory
// lock. If another instance is mid-migration, normal startup is well
// under a minute, so 30s is a generous bound. Hitting it indicates a
// stuck connection holding the lock — fail loud rather than hang
// startup forever.
const lockAcquireTimeout = 30 * time.Second

// Apply runs every pending migration against db in version order. Each
// migration is a separate transaction; a failure in migration N rolls
// back N's changes, leaves 1..N-1 applied, and aborts (returns error).
// Re-running after a successful Apply is a no-op.
//
// Apply is safe to call from concurrent backend processes pointed at
// the same Postgres: callers serialize on a Postgres advisory lock,
// and the lock auto-releases on connection close.
//
// SQLite skips advisory locking (single-process; SQLite's own write
// lock is sufficient).
func Apply(ctx context.Context, db *sql.DB, dialect Dialect) error {
	return applyFromFS(ctx, db, dialect, sqlFS)
}

// applyFromFS is the testable inner loop. Production calls through
// Apply with the embedded sqlFS; tests substitute their own fs.FS.
//
// All DB operations during Apply happen on a single pinned connection
// (db.Conn) so that the Postgres session-level advisory lock taken at
// the top is held by the same session that runs the migrations and
// the corresponding pg_advisory_unlock at the end. Without pinning,
// sql.DB checks out arbitrary pool connections per call — the unlock
// could run on a different session than the lock, leaving the lock
// dangling until the original connection's lifetime expires.
func applyFromFS(ctx context.Context, db *sql.DB, dialect Dialect, f migrationFS) error {
	migs, err := discover(f)
	if err != nil {
		return fmt.Errorf("discover migrations: %w", err)
	}
	if len(migs) == 0 {
		return nil
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Close()

	release, err := lockIfPostgres(ctx, conn, dialect)
	if err != nil {
		return err
	}
	defer release()

	applied, err := readSchemaMigrations(ctx, conn, dialect, migs)
	if err != nil {
		return err
	}

	return applyPending(ctx, conn, dialect, migs, applied)
}

// lockIfPostgres acquires the advisory lock for Postgres deployments
// and returns a release function. SQLite is single-process; no lock
// needed, returns a no-op release.
func lockIfPostgres(ctx context.Context, conn *sql.Conn, dialect Dialect) (func(), error) {
	if dialect != Postgres {
		return func() {}, nil
	}
	return acquireAdvisoryLock(ctx, conn)
}

// readSchemaMigrations bootstraps schema_migrations if missing, loads
// the applied set, and verifies no checksum drift on already-applied
// versions.
func readSchemaMigrations(ctx context.Context, conn *sql.Conn, dialect Dialect, migs []Migration) (map[int]appliedMig, error) {
	if err := ensureMigrationsTable(ctx, conn, dialect); err != nil {
		return nil, fmt.Errorf("ensure schema_migrations table: %w", err)
	}
	applied, err := loadApplied(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("load applied migrations: %w", err)
	}
	if err := checkChecksumDrift(migs, applied); err != nil {
		return nil, err
	}
	return applied, nil
}

// applyPending runs each not-yet-applied migration in version order,
// each in its own transaction, recording results in schema_migrations.
func applyPending(ctx context.Context, conn *sql.Conn, dialect Dialect, migs []Migration, applied map[int]appliedMig) error {
	for _, m := range migs {
		if _, ok := applied[m.Version]; ok {
			continue
		}
		start := time.Now()
		if err := applyOne(ctx, conn, dialect, m); err != nil {
			return fmt.Errorf("migration %03d_%s: %w", m.Version, m.Name, err)
		}
		log.Printf("applied migration %03d_%s in %s", m.Version, m.Name, time.Since(start).Round(time.Millisecond))
	}
	return nil
}

// acquireAdvisoryLock takes the Postgres advisory lock on conn and
// returns a release function. Bounded by lockAcquireTimeout so a stuck
// previous instance doesn't hang startup forever — if the lock can't
// be acquired in time, Apply returns an error and the operator can
// investigate.
//
// IMPORTANT: the lock and unlock must happen on the SAME connection
// (Postgres advisory locks are session-scoped). The runner pins one
// connection for the duration of Apply to satisfy this invariant.
//
// The release function uses context.Background() on purpose: even if
// the calling context is cancelled mid-Apply, the lock must still be
// released or future startups will hit the same timeout.
func acquireAdvisoryLock(ctx context.Context, conn *sql.Conn) (func(), error) {
	lockCtx, cancel := context.WithTimeout(ctx, lockAcquireTimeout)
	defer cancel()
	if _, err := conn.ExecContext(lockCtx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return nil, fmt.Errorf("acquire advisory lock (waited %s): %w", lockAcquireTimeout, err)
	}
	return func() {
		if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockKey); err != nil {
			log.Printf("warning: release advisory lock: %v", err)
		}
	}, nil
}

// ensureMigrationsTable creates schema_migrations if absent. The DDL
// uses IF NOT EXISTS so re-runs are no-ops. The Go runner — not a
// migration file — owns this table because the runner needs the table
// to exist before it can record any migrations, including the very
// first one.
func ensureMigrationsTable(ctx context.Context, conn *sql.Conn, dialect Dialect) error {
	var ddl string
	switch dialect {
	case Postgres:
		ddl = `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       VARCHAR(200) NOT NULL,
			checksum   VARCHAR(64) NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`
	case SQLite:
		ddl = `CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT NOT NULL,
			checksum   TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`
	default:
		return fmt.Errorf("unknown dialect %d", dialect)
	}
	_, err := conn.ExecContext(ctx, ddl)
	return err
}

// appliedMig is the row shape we read back from schema_migrations.
type appliedMig struct {
	Version  int
	Checksum string
}

// loadApplied returns a map of version -> applied state for every row
// already in schema_migrations. Used both for skipping pending work
// and for checksum-drift detection on already-applied versions.
func loadApplied(ctx context.Context, conn *sql.Conn) (map[int]appliedMig, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int]appliedMig)
	for rows.Next() {
		var a appliedMig
		if err := rows.Scan(&a.Version, &a.Checksum); err != nil {
			return nil, err
		}
		out[a.Version] = a
	}
	return out, rows.Err()
}

// checkChecksumDrift verifies that every already-applied migration's
// recorded checksum still matches the embedded file. A mismatch means
// someone edited a migration that has already been applied somewhere —
// that's never safe (different deployments would diverge silently), so
// abort startup with an actionable error.
func checkChecksumDrift(migs []Migration, applied map[int]appliedMig) error {
	for _, m := range migs {
		existing, ok := applied[m.Version]
		if !ok {
			continue
		}
		if existing.Checksum != m.Checksum {
			return fmt.Errorf(
				"checksum drift on migration %03d_%s: file=%s db=%s — "+
					"an applied migration was edited; revert the change or "+
					"manually update schema_migrations after verifying schema state",
				m.Version, m.Name, m.Checksum[:16], existing.Checksum[:16],
			)
		}
	}
	return nil
}

// applyOne runs a single migration and records it in schema_migrations,
// all inside one transaction. Failure rolls back the entire migration
// (and the bookkeeping insert), leaving the DB in the pre-migration
// state — the caller can fix the SQL and re-run.
//
// The transaction runs on the same pinned connection that holds the
// advisory lock, so the lock remains valid throughout.
func applyOne(ctx context.Context, conn *sql.Conn, dialect Dialect, m Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is a no-op after a successful Commit.
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("exec migration: %w", err)
	}

	if err := recordApplied(ctx, tx, dialect, m); err != nil {
		return fmt.Errorf("record applied: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// recordApplied inserts the migration row into schema_migrations
// inside the same tx as the migration itself. Postgres has DEFAULT now()
// on applied_at so we don't pass it; SQLite's tracking table uses TEXT
// without a default, so we provide ISO-8601 explicitly to keep the two
// dialects' column shapes interchangeable.
func recordApplied(ctx context.Context, tx *sql.Tx, dialect Dialect, m Migration) error {
	switch dialect {
	case Postgres:
		_, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
			m.Version, m.Name, m.Checksum)
		return err
	case SQLite:
		_, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
			m.Version, m.Name, m.Checksum, time.Now().UTC().Format(time.RFC3339))
		return err
	default:
		return fmt.Errorf("unknown dialect %d", dialect)
	}
}
