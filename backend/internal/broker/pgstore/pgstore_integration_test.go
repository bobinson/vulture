//go:build integration

package pgstore

import (
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/broker/token"
)

// Integration coverage for the PG-backed denylist + revocation stores against a
// live Postgres with migration 024 applied. Run:
//
//	POSTGRES_TEST_DSN=postgres://test:test@localhost:25439/test?sslmode=disable \
//	  go test -tags=integration ./internal/broker/pgstore/
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("postgres not reachable (%v); skipping", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPG_Denylist_DenyThenDenied(t *testing.T) {
	db := testDB(t)
	d := NewDenylist(db, time.Millisecond) // tiny TTL so the deny is visible at once
	kid := "kid-itest-" + time.Now().Format("150405.000000")

	ok, err := d.IsDenied(kid)
	if err != nil || ok {
		t.Fatalf("fresh kid: IsDenied = %v,%v want false,nil", ok, err)
	}
	if err := d.Deny(kid); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	ok, err = d.IsDenied(kid)
	if err != nil || !ok {
		t.Fatalf("after Deny: IsDenied = %v,%v want true,nil", ok, err)
	}
}

func TestPG_Revocation_RevokeThenRevoked(t *testing.T) {
	db := testDB(t)
	r := NewRevocation(db, time.Millisecond)
	jti := "jti-itest-" + time.Now().Format("150405.000000")

	ok, err := r.IsRevoked(jti)
	if err != nil || ok {
		t.Fatalf("fresh jti: IsRevoked = %v,%v want false,nil", ok, err)
	}
	if err := r.Revoke(jti); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ok, err = r.IsRevoked(jti)
	if err != nil || !ok {
		t.Fatalf("after Revoke: IsRevoked = %v,%v want true,nil", ok, err)
	}
	// Revoke is idempotent (ON CONFLICT DO NOTHING).
	if err := r.Revoke(jti); err != nil {
		t.Fatalf("re-Revoke: %v", err)
	}
}

// A closed DB (unreachable store) fails CLOSED with ErrRevocationUnavailable.
func TestPG_Revocation_StoreDownFailsClosed(t *testing.T) {
	db := testDB(t)
	r := NewRevocation(db, time.Millisecond)
	_ = db.Close() // simulate PG unreachable
	_, err := r.IsRevoked("some-jti")
	if err == nil {
		t.Fatal("want error when store is down (fail closed)")
	}
	if !errors.Is(err, token.ErrRevocationUnavailable) {
		t.Fatalf("err = %v, want ErrRevocationUnavailable", err)
	}
}
