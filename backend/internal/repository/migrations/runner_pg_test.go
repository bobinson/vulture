//go:build integration

// Postgres integration tests for the migration runner. Gated by the
// `integration` build tag because they require a running Postgres
// addressable via the POSTGRES_TEST_DSN environment variable. CI sets
// this; normal `go test` runs skip these tests.
//
// Each test creates a unique schema (per-test) so multiple integration
// test runs don't collide on the same DB.
package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func openPGForTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping integration test")
	}

	// First open: create the per-test schema. Each test gets a unique
	// schema name so concurrent test runs (or sequential runs that
	// share a long-lived container) don't collide.
	bootstrap, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres (bootstrap): %v", err)
	}
	if err := bootstrap.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	schema := fmt.Sprintf("vlt_test_%d", time.Now().UnixNano())
	if _, err := bootstrap.Exec(fmt.Sprintf(`CREATE SCHEMA "%s"`, schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	bootstrap.Close()

	// Second open: bake search_path into the connection options so every
	// pool connection — including the pinned conn applyFromFS opens via
	// db.Conn() — inherits "<test_schema>, public". A previous version
	// of this helper used `db.Exec("SET search_path ...")` which only
	// affects the pool connection that ran it, not later db.Conn() calls.
	// public is included so extensions (uuid-ossp, vector, pg_trgm) that
	// install there remain visible to the test schema.
	testDSN := dsn
	options := fmt.Sprintf("-c search_path=%q,public", schema)
	encOpts := url.QueryEscape(options)
	if strings.Contains(testDSN, "?") {
		testDSN += "&options=" + encOpts
	} else {
		testDSN += "?options=" + encOpts
	}
	db, err := sql.Open("postgres", testDSN)
	if err != nil {
		t.Fatalf("open postgres (with search_path): %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping (with search_path): %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		// Drop the schema via a fresh bootstrap connection — we can't
		// reuse `db` because dropping the schema we're connected to is
		// awkward with libpq's reconnect behavior.
		cleanup, err := sql.Open("postgres", dsn)
		if err != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Exec(fmt.Sprintf(`DROP SCHEMA "%s" CASCADE`, schema))
	})
	return db
}

// TestApply_PG_RealMigrations runs the full embedded set of 14
// migrations against a real Postgres. Asserts no errors, all 14
// recorded in schema_migrations, and a re-run is a no-op.
func TestApply_PG_RealMigrations(t *testing.T) {
	db := openPGForTest(t)

	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// Discover the embedded count to compare against schema_migrations.
	migs, err := discover(sqlFS)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	want := len(migs)

	var got int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != want {
		t.Fatalf("schema_migrations count = %d, want %d (one per embedded file)", got, want)
	}

	// Re-run is a no-op.
	if err := Apply(context.Background(), db, Postgres); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatalf("count after rerun: %v", err)
	}
	if got != want {
		t.Fatalf("schema_migrations count after rerun = %d, want %d (no duplicates)", got, want)
	}
}

// TestApply_PG_AdvisoryLock confirms that concurrent Apply calls
// against the same Postgres serialize via the advisory lock — no
// "table already exists" or duplicate-key errors.
func TestApply_PG_AdvisoryLock(t *testing.T) {
	db := openPGForTest(t)

	f := fixtureFS(map[string]string{
		"001_a.sql": `CREATE TABLE a (id INTEGER)`,
		"002_b.sql": `CREATE TABLE b (id INTEGER)`,
		"003_c.sql": `CREATE TABLE c (id INTEGER)`,
	})

	const concurrency = 6
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- applyFromFS(context.Background(), db, Postgres, f)
		}()
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		if e != nil {
			t.Errorf("concurrent apply: %v", e)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version IN (1, 2, 3)`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Fatalf("schema_migrations rows for v1-3 = %d, want 3 (no dupes, no missing)", n)
	}
}

// TestApply_PG_PartialFailure verifies Postgres rolls back the failing
// migration cleanly (DDL is transactional in Postgres; a syntax error
// in migration N must leave 1..N-1 applied and N fully rolled back).
func TestApply_PG_PartialFailure(t *testing.T) {
	db := openPGForTest(t)

	f := fixtureFS(map[string]string{
		"001_a.sql":   `CREATE TABLE a (id INTEGER)`,
		"002_bad.sql": `THIS IS NOT VALID SQL;`,
		"003_c.sql":   `CREATE TABLE c (id INTEGER)`,
	})

	err := applyFromFS(context.Background(), db, Postgres, f)
	if err == nil {
		t.Fatal("expected error from migration 002, got nil")
	}
	if !strings.Contains(err.Error(), "002_bad") {
		t.Fatalf("error %q should name 002_bad", err)
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations count = %d, want 1 (only 001 applied)", n)
	}

	// Confirm 003's table was never created in *this* schema (other
	// integration tests share the DB and might have their own 'c').
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.tables
		WHERE table_name='c' AND table_schema = current_schema()
	)`).Scan(&exists); err != nil {
		t.Fatalf("query c: %v", err)
	}
	if exists {
		t.Fatal("table c should not exist after 002 failed")
	}
}

// TestApply_PG_RegressFKTypeMismatch reproduces the schema bug class that
// hit production tonight (011/012: TEXT-typed FK columns referencing
// UUID PKs). The runner must surface the failure with a clear,
// migration-named error so CI catches the next instance at commit time
// instead of at deploy time.
func TestApply_PG_RegressFKTypeMismatch(t *testing.T) {
	db := openPGForTest(t)

	f := fixtureFS(map[string]string{
		"001_users.sql":    `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"; CREATE TABLE users (id UUID PRIMARY KEY DEFAULT uuid_generate_v4())`,
		"002_api_keys.sql": `CREATE TABLE api_keys (id TEXT PRIMARY KEY, created_by TEXT NOT NULL REFERENCES users(id))`,
	})

	err := applyFromFS(context.Background(), db, Postgres, f)
	if err == nil {
		t.Fatal("expected FK-type-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "002_api_keys") {
		t.Fatalf("error %q should name 002_api_keys", err)
	}
	if !strings.Contains(err.Error(), "foreign key constraint") {
		t.Fatalf("error %q should mention 'foreign key constraint'", err)
	}
}

// TestApply_PG_LockReleasedOnError confirms that even when Apply fails
// (e.g., a migration errors), the advisory lock is released so a
// retry can acquire it without timing out.
func TestApply_PG_LockReleasedOnError(t *testing.T) {
	db := openPGForTest(t)

	bad := fixtureFS(map[string]string{
		"001_bad.sql": `THIS IS NOT VALID SQL;`,
	})

	if err := applyFromFS(context.Background(), db, Postgres, bad); err == nil {
		t.Fatal("expected error, got nil")
	}

	// If the lock leaked, this second call would hang forever; gate
	// with a timeout to surface the bug as a test failure instead.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	good := fixtureFS(map[string]string{
		"001_a.sql": `CREATE TABLE a (id INTEGER)`,
	})

	done := make(chan error, 1)
	go func() { done <- applyFromFS(ctx, db, Postgres, good) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("retry apply: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retry apply hung — advisory lock leaked")
	}
}
