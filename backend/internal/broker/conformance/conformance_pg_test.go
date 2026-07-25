package conformance

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/repository/migrations"
)

// openPostgres returns a migrated, freshly-truncated Postgres store when
// POSTGRES_TEST_DSN is set (the same convention as the migration lane), else
// nil so the suite runs SQLite-only. A set-but-unreachable DSN skips.
func openPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		return nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("open postgres: %v", err)
		return nil
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		t.Skipf("postgres not reachable (%v); skipping pg conformance", err)
		return nil
	}
	if err := migrations.Apply(context.Background(), db, migrations.Postgres); err != nil {
		_ = db.Close()
		t.Fatalf("apply migrations (pg): %v", err)
	}
	// Clean slate so cross-run residue can't skew the budget assertions.
	if _, err := db.ExecContext(context.Background(),
		`TRUNCATE llm_ledger, llm_lease, llm_budget_shard, revoked_jti, kid_denylist, llm_audit_log`); err != nil {
		_ = db.Close()
		t.Fatalf("truncate broker tables (pg): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
