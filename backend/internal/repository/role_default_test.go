package repository

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// 0036 Phase 3 finding C2 — pin the user-default-role contract.
//
// The Postgres migration (001_init.sql) defaults `users.role` to
// 'member' with a CHECK constraint of {admin, member, viewer}. The
// SQLite inline schema in sqlite_repo.go drifted to DEFAULT 'admin'
// — meaning any future INSERT eliding the role column would silently
// promote new users to admin. Today's registration flow always sets
// role explicitly, so this hasn't bitten in production; the test
// pins the schema invariant so a future code path can't regress it.
func TestSQLiteUserDefaultRoleIsMember(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	repo, err := NewSQLiteRepo(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRepo: %v", err)
	}
	defer repo.Close()

	// INSERT eliding the role column; relies on DEFAULT.
	_, err = repo.db.Exec(
		`INSERT INTO users (id, email, password_hash, name, created_at)
		 VALUES ('u1', 'test@example.com', 'hash', 'test', '2026-05-31')`,
	)
	if err != nil {
		t.Fatalf("insert without role: %v", err)
	}

	var role string
	if err := repo.db.QueryRow(
		`SELECT role FROM users WHERE id = ?`, "u1",
	).Scan(&role); err != nil {
		t.Fatalf("select role: %v", err)
	}
	if role == "admin" {
		t.Errorf("SQLite users.role defaulted to %q — must default to 'member' per C2", role)
	}
	if role != "member" {
		t.Errorf("SQLite users.role default = %q; want 'member'", role)
	}
}

// Companion: the CHECK constraint must reject unknown role values so a
// schema-level guard fails before the application logic has a chance
// to write a corrupt value.
func TestSQLiteUserRoleCheckConstraint(t *testing.T) {
	repo, err := NewSQLiteRepo(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRepo: %v", err)
	}
	defer repo.Close()

	_, err = repo.db.Exec(
		`INSERT INTO users (id, email, password_hash, name, role, created_at)
		 VALUES ('u2', 'bad@example.com', 'hash', 'bad', 'superadmin', '2026-05-31')`,
	)
	if err == nil {
		t.Errorf("INSERT with role='superadmin' succeeded — CHECK constraint missing")
	}
}
