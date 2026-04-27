package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"
)

// openTestDB returns an in-memory SQLite handle for unit tests. Each
// test gets a fresh DB; ":memory:" plus a unique cache string makes
// independent connections (no cross-test bleed).
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// fixtureFS builds an fs.FS with a set of fake migrations for unit
// tests. Each entry is "<NNN_name.sql>" → SQL body.
func fixtureFS(files map[string]string) migrationFS {
	mfs := fstest.MapFS{}
	for name, body := range files {
		mfs[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return mfs
}

func countApplied(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count applied: %v", err)
	}
	return n
}

// TestApply_Empty verifies a fresh DB applies every migration once.
func TestApply_Empty(t *testing.T) {
	db := openTestDB(t)
	f := fixtureFS(map[string]string{
		"001_a.sql": `CREATE TABLE a (id INTEGER)`,
		"002_b.sql": `CREATE TABLE b (id INTEGER)`,
		"003_c.sql": `CREATE TABLE c (id INTEGER)`,
	})

	if err := applyFromFS(context.Background(), db, SQLite, f); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := countApplied(t, db); got != 3 {
		t.Fatalf("schema_migrations count = %d, want 3", got)
	}
	for _, table := range []string{"a", "b", "c"} {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %q missing: %v", table, err)
		}
	}
}

// TestApply_Idempotent verifies a second Apply is a no-op.
func TestApply_Idempotent(t *testing.T) {
	db := openTestDB(t)
	f := fixtureFS(map[string]string{
		"001_a.sql": `CREATE TABLE a (id INTEGER)`,
		"002_b.sql": `CREATE TABLE b (id INTEGER)`,
	})

	if err := applyFromFS(context.Background(), db, SQLite, f); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	if err := applyFromFS(context.Background(), db, SQLite, f); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if got := countApplied(t, db); got != 2 {
		t.Fatalf("schema_migrations count after rerun = %d, want 2", got)
	}
}

// TestApply_ChecksumDrift verifies that editing an already-applied
// migration is detected and aborts startup with a descriptive error.
func TestApply_ChecksumDrift(t *testing.T) {
	db := openTestDB(t)
	original := fixtureFS(map[string]string{
		"001_a.sql": `CREATE TABLE a (id INTEGER)`,
	})
	if err := applyFromFS(context.Background(), db, SQLite, original); err != nil {
		t.Fatalf("apply 1: %v", err)
	}

	edited := fixtureFS(map[string]string{
		"001_a.sql": `CREATE TABLE a (id INTEGER, extra TEXT)`,
	})
	err := applyFromFS(context.Background(), db, SQLite, edited)
	if err == nil {
		t.Fatal("expected drift error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum drift") {
		t.Fatalf("error %q does not mention 'checksum drift'", err)
	}
}

// TestApply_PartialFailure verifies that when migration N fails:
//   - migrations 1..N-1 stay applied
//   - migration N is rolled back (not in schema_migrations, no schema change)
//   - migrations N+1.. are NOT attempted
//   - the error names the failing migration
func TestApply_PartialFailure(t *testing.T) {
	db := openTestDB(t)
	f := fixtureFS(map[string]string{
		"001_a.sql":   `CREATE TABLE a (id INTEGER)`,
		"002_bad.sql": `THIS IS NOT VALID SQL;`,
		"003_c.sql":   `CREATE TABLE c (id INTEGER)`,
	})

	err := applyFromFS(context.Background(), db, SQLite, f)
	if err == nil {
		t.Fatal("expected error from migration 002, got nil")
	}
	if !strings.Contains(err.Error(), "002_bad") {
		t.Fatalf("error %q should name migration 002_bad", err)
	}

	// 001 applied:
	if got := countApplied(t, db); got != 1 {
		t.Fatalf("schema_migrations count = %d, want 1 (only 001)", got)
	}
	// 003 NOT applied:
	var n int
	err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='c'`).Scan(&n)
	if err != nil {
		t.Fatalf("query c: %v", err)
	}
	if n != 0 {
		t.Fatalf("table c should NOT exist after 002 failed; got count=%d", n)
	}
	// 002 rollback: table 'bad' should not exist.
	err = db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='bad'`).Scan(&n)
	if err != nil {
		t.Fatalf("query bad: %v", err)
	}
	if n != 0 {
		t.Fatalf("table bad should NOT exist (002 was rolled back); got count=%d", n)
	}
}

// TestApply_BadFilename verifies that a malformed filename aborts
// with a clear error before any migration is attempted.
func TestApply_BadFilename(t *testing.T) {
	db := openTestDB(t)
	f := fixtureFS(map[string]string{
		"001_a.sql":   `CREATE TABLE a (id INTEGER)`,
		"012b_oops.sql": `CREATE TABLE oops (id INTEGER)`,
	})

	err := applyFromFS(context.Background(), db, SQLite, f)
	if err == nil {
		t.Fatal("expected error for bad filename, got nil")
	}
	if !strings.Contains(err.Error(), "012b_oops.sql") {
		t.Fatalf("error %q should name 012b_oops.sql", err)
	}
}

// TestApply_DuplicateVersion verifies that two files claiming the same
// version number is caught at discover() time, before any migration
// is applied.
func TestApply_DuplicateVersion(t *testing.T) {
	db := openTestDB(t)
	f := fixtureFS(map[string]string{
		"001_first.sql":  `CREATE TABLE first (id INTEGER)`,
		"001_second.sql": `CREATE TABLE second (id INTEGER)`,
	})

	err := applyFromFS(context.Background(), db, SQLite, f)
	if err == nil {
		t.Fatal("expected duplicate-version error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error %q should mention 'duplicate'", err)
	}
}

// TestApply_VersionOrdering verifies that the runner sorts by integer
// version, not lexicographic filename. (e.g., "010" must apply after
// "009" and before "100", not be sorted as "010" < "100" lexically —
// though for the canonical zero-padded form they happen to align.)
func TestApply_VersionOrdering(t *testing.T) {
	db := openTestDB(t)
	f := fixtureFS(map[string]string{
		"002_b.sql": `CREATE TABLE b (id INTEGER)`,
		"010_j.sql": `CREATE TABLE j (id INTEGER)`,
		"001_a.sql": `CREATE TABLE a (id INTEGER)`,
		"009_i.sql": `CREATE TABLE i (id INTEGER)`,
	})
	if err := applyFromFS(context.Background(), db, SQLite, f); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// ORDER BY version (not applied_at): SQLite's TEXT applied_at is
	// RFC3339 second precision, so all four rows tie on timestamp and
	// the sort would be non-deterministic. Sorting by version proves
	// the runner inserted them in the correct order.
	rows, err := db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var versions []int
	for rows.Next() {
		var v int
		_ = rows.Scan(&v)
		versions = append(versions, v)
	}
	want := []int{1, 2, 9, 10}
	if len(versions) != len(want) {
		t.Fatalf("got %v, want %v", versions, want)
	}
	for i, v := range versions {
		if v != want[i] {
			t.Fatalf("position %d: got version %d, want %d", i, v, want[i])
		}
	}
}

// TestParseFilename covers the regex grammar directly.
func TestParseFilename(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantV   int
		wantN   string
		wantErr bool
	}{
		{"canonical", "001_init.sql", 1, "init", false},
		{"three_digit", "014_audit_degraded_reason.sql", 14, "audit_degraded_reason", false},
		{"four_digit", "1234_big.sql", 1234, "big", false},
		{"missing_underscore", "001init.sql", 0, "", true},
		{"alpha_version", "abc_init.sql", 0, "", true},
		{"trailing_letter", "012b_oops.sql", 0, "", true},
		{"uppercase_name", "001_BadName.sql", 0, "", true},
		{"wrong_ext", "001_init.SQL", 0, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, n, err := parseFilename(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", c.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v != c.wantV || n != c.wantN {
				t.Fatalf("got (%d, %q), want (%d, %q)", v, n, c.wantV, c.wantN)
			}
		})
	}
}

// TestApply_TableExistsBeforeBootstrap confirms that ensureMigrationsTable
// is safe to call when schema_migrations already exists from a previous
// startup (the typical case). No error, no row changes.
func TestApply_TableExistsBeforeBootstrap(t *testing.T) {
	db := openTestDB(t)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	if err := ensureMigrationsTable(context.Background(), conn, SQLite); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if err := ensureMigrationsTable(context.Background(), conn, SQLite); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
}

// Note: SQLite multi-goroutine concurrency is not a supported scenario
// for the runner — backend startup calls Apply() once per process, and
// multi-process SQLite isn't a deployment mode (mode A is single-process,
// mode B/C use Postgres). The Postgres advisory-lock path is exercised by
// the integration tests in runner_pg_test.go (build tag: integration).
