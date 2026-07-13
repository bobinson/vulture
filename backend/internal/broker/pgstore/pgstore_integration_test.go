//go:build integration

package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/vulture/backend/internal/broker/budget"
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

func TestPG_AuditLog_InsertsRow(t *testing.T) {
	db := testDB(t)
	al := NewAuditLog(db)
	run := "run-al-" + time.Now().Format("150405.000000")
	al.Log(context.Background(), budget.LedgerEntry{
		RunID: run, RequestID: "q1", TenantID: "local", Provider: "openai",
		Model: "gpt-4o", InputTokens: 120, OutputTokens: 42, CostUSD: 0.0031,
	}, false)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM llm_audit_log WHERE run_id=$1`, run).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("audit-log rows for %s = %d, want 1", run, n)
	}
}
