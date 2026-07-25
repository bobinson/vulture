package dialect

import "testing"

func TestRebind_PostgresRenumbers(t *testing.T) {
	got := Postgres.Rebind("INSERT INTO t (a,b,c) VALUES (?,?,?)")
	want := "INSERT INTO t (a,b,c) VALUES ($1,$2,$3)"
	if got != want {
		t.Fatalf("Rebind = %q, want %q", got, want)
	}
}

func TestRebind_SQLitePassthrough(t *testing.T) {
	q := "UPDATE t SET x = x + ? WHERE id = ? AND y <= ?"
	if got := SQLite.Rebind(q); got != q {
		t.Fatalf("SQLite Rebind must be identity, got %q", got)
	}
}

func TestRebind_NoPlaceholders(t *testing.T) {
	q := "SELECT 1"
	if got := Postgres.Rebind(q); got != q {
		t.Fatalf("no-placeholder query changed: %q", got)
	}
}

func TestNeedsWriteLock(t *testing.T) {
	if Postgres.NeedsWriteLock() {
		t.Error("Postgres must not need an in-process write lock")
	}
	if !SQLite.NeedsWriteLock() {
		t.Error("SQLite must need an in-process write lock")
	}
}
