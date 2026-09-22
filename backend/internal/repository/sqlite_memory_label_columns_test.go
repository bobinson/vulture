package repository

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// The release smoke log carried, on a first boot against a fresh SQLite file:
//
//	[validate.l4] lookup failed (skipping): SQL logic error: no such column: user_label (1)
//
// The L4 memory-prior lookup reads audit_memories.user_label, and on a fresh
// install that column did not exist. It is a FIRST-BOOT-ONLY fault, which is
// why no dev machine ever saw it: openRepo runs sqlite_repo's migrate() before
// registerMemoryRoutes calls NewSQLiteMemoryRepo, so on boot one the three
// label ALTERs hit a table that does not exist yet and are swallowed by their
// `_, _ =`; the table is then CREATEd without them. On boot two the table is
// there, the ALTERs land, and the install silently heals. A release smoke boots
// exactly once.
//
// So this test reproduces the real order — audit repo first, memory repo
// second, one boot — rather than calling migrateMemory on its own, because
// calling it alone is the one arrangement in which the bug cannot appear.

func memoryColumns(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(audit_memories)`)
	if err != nil {
		t.Fatalf("read audit_memories schema: %v", err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	return cols
}

// bootOnce wires the two repos in the same order server.go does.
func bootOnce(t *testing.T, path string) *sql.DB {
	t.Helper()
	repo, err := NewSQLiteRepo(path)
	if err != nil {
		t.Fatalf("open audit repo: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if _, err := NewSQLiteMemoryRepo(repo.DB()); err != nil {
		t.Fatalf("open memory repo: %v", err)
	}
	return repo.DB()
}

// TestFreshInstallHasTheL4LabelColumns is the regression for the smoke log.
func TestFreshInstallHasTheL4LabelColumns(t *testing.T) {
	db := bootOnce(t, filepath.Join(t.TempDir(), "vulture.db"))
	cols := memoryColumns(t, db)
	for _, want := range []string{"user_label", "labelled_by", "labelled_at", "fingerprint"} {
		if !cols[want] {
			t.Errorf("fresh install is missing audit_memories.%s.\n"+
				"The L4 memory-prior lookup selects it, so every audit on a brand-new "+
				"install logs `[validate.l4] lookup failed (skipping)` and silently loses "+
				"the prior-label tier until the process is restarted once.", want)
		}
	}
}

// TestUpgradeGainsTheL4LabelColumns covers the other direction: a database
// written by a build that predates the columns must still acquire them. That
// is the case the ALTERs were added for, and it has to keep working wherever
// they end up living.
func TestUpgradeGainsTheL4LabelColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulture.db")

	// Stand up an OLD audit_memories: the shipped CREATE minus every column
	// the label tier needs.
	seed, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if _, err := seed.Exec(`CREATE TABLE audit_memories (
		id TEXT PRIMARY KEY, audit_id TEXT NOT NULL, agent_type TEXT NOT NULL,
		codebase_path TEXT NOT NULL, finding_type TEXT NOT NULL, title TEXT NOT NULL,
		content TEXT NOT NULL, severity TEXT NOT NULL, created_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("seed old schema: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	cols := memoryColumns(t, bootOnce(t, path))
	for _, want := range []string{"user_label", "labelled_by", "labelled_at", "fingerprint"} {
		if !cols[want] {
			t.Errorf("upgrading an existing install did not add audit_memories.%s; "+
				"the L4 lookup would keep failing on a database that already has rows", want)
		}
	}
}
